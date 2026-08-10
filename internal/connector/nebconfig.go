package connector

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/rjsocha/robinet/internal/enroll"
	"go.yaml.in/yaml/v3"
)

// nebulaOverhead is what nebula adds to every packet: outer IPv4 and UDP
// headers, its own header and the AEAD tag.
const nebulaOverhead = 60

// minimumMTU is IPv6's, and it is not a preference: gvisor refuses to send an
// IPv6 packet at all on a link below 1280, so a smaller stack silently drops
// every one of them while IPv4 keeps working.
const minimumMTU = 1280

// nebulaConfig renders the connector's nebula configuration.
//
// The timers are deliberately tighter than nebula's defaults. A connector has
// no local traffic of its own when idle, so lighthouse updates are the only
// thing keeping the NAT mapping warm and the only thing that notices a
// lighthouse that went away.
func nebulaConfig(bundle *enroll.Bundle, keyPEM []byte) ([]byte, error) {
	if !bundle.Lighthouse.OverlayAddress.IsValid() {
		return nil, fmt.Errorf("the bundle carries no lighthouse address")
	}
	if len(bundle.Lighthouse.Endpoints) == 0 {
		return nil, fmt.Errorf("the bundle carries no lighthouse endpoint")
	}

	lighthouse := bundle.Lighthouse.OverlayAddress.String()

	pki := map[string]any{
		"ca":   bundle.CA,
		"cert": bundle.Certificate,
		"key":  string(keyPEM),
	}
	if len(bundle.Blocked) > 0 {
		// A banned member's certificate is still valid and still signed by the
		// authority this connector trusts, so refusing it by fingerprint is
		// what stops it reaching the network being carried.
		pki["blocklist"] = bundle.Blocked
	}

	cfg := map[string]any{
		"pki": pki,
		"static_host_map": map[string]any{
			lighthouse: bundle.Lighthouse.Endpoints,
		},
		"lighthouse": map[string]any{
			"am_lighthouse": false,
			"interval":      5,
			"hosts":         []string{lighthouse},
		},
		"listen": map[string]any{
			"host": "0.0.0.0",
			"port": 0,
		},
		"punchy": map[string]any{
			"punch":              true,
			"respond":            true,
			"target_all_remotes": true,
		},
		"relay": map[string]any{
			"am_relay":   false,
			"use_relays": bundle.Lighthouse.Relay,
		},
		"handshakes": map[string]any{
			"try_interval": "100ms",
			"retries":      40,
		},
		"timers": map[string]any{
			"connection_alive_interval": 2,
			"pending_deletion_interval": 3,
		},
		"firewall": map[string]any{
			// Without this an inbound rule only matches our own overlay
			// address once the certificate carries unsafe networks, and every
			// forwarded packet is dropped.
			"default_local_cidr_any": true,
			"outbound": []map[string]any{
				{"port": "any", "proto": "any", "host": "any"},
			},
			"inbound": []map[string]any{
				{"port": "any", "proto": "any", "host": "any"},
			},
		},
		"logging": map[string]any{
			"level":  "info",
			"format": "text",
		},
	}

	return yaml.Marshal(cfg)
}

// overlayMTU picks a stack MTU that survives the path the tunnel takes.
//
// That path is the one to the other members, over the default route - not the
// network being carried. The two are different, and mistaking one for the
// other is what produced a stack that could not send IPv6 at all: Railway
// hands out a 1316 byte private link, and 1316 minus nebula's overhead is
// below the 1280 IPv6 requires. The link to the carried network constrains the
// connection this connector opens to a service there, which is a separate
// connection made by the host, with the host's own MTU.
func overlayMTU(hubMTU, override uint32, log *slog.Logger) uint32 {
	if override > 0 {
		return override
	}

	link := tunnelLinkMTU()
	if hubMTU > 0 && hubMTU < link {
		link = hubMTU
	}

	mtu := minimumMTU
	if link > nebulaOverhead+minimumMTU {
		mtu = int(link) - nebulaOverhead
	} else if log != nil {
		// Said out loud: the path cannot carry what IPv6 requires, so large
		// packets will be lost somewhere rather than refused here.
		log.Warn("the path to the other members is narrower than IPv6 allows, using the minimum",
			"path", link, "mtu", minimumMTU)
	}

	return uint32(mtu)
}

// tunnelLinkMTU is the MTU of the interface carrying the default route, which
// is where packets to the other members go.
func tunnelLinkMTU() uint32 {
	name := defaultRouteInterface()
	if name != "" {
		if iface, err := net.InterfaceByName(name); err == nil && iface.MTU > 0 {
			return uint32(iface.MTU)
		}
	}

	// No default route to read: fall back to the widest interface that is up,
	// since the narrowest is almost certainly the network being carried.
	ifaces, err := net.Interfaces()
	if err != nil {
		return 1500
	}

	best := uint32(0)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.MTU <= 0 {
			continue
		}
		if uint32(iface.MTU) > best {
			best = uint32(iface.MTU)
		}
	}

	if best == 0 {
		return 1500
	}
	return best
}

// defaultRouteInterface reads the name of the interface with a default route.
func defaultRouteInterface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(raw), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// destination 00000000 is the default route.
		if fields[1] == "00000000" {
			return fields[0]
		}
	}

	return ""
}

// localLinkMTU is the smallest MTU among the interfaces carrying the prefixes
// we announce, falling back to a conservative default.
//
//nolint:unused // kept for the fallback path below
func localLinkMTU(routes []netip.Prefix) uint32 {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 1500
	}

	best := uint32(0)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.MTU <= 0 {
			continue
		}

		if len(routes) > 0 && !carriesAny(iface, routes) {
			continue
		}

		mtu := uint32(iface.MTU)
		if best == 0 || mtu < best {
			best = mtu
		}
	}

	if best == 0 {
		return 1500
	}
	return best
}

func carriesAny(iface net.Interface, routes []netip.Prefix) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}

		for _, r := range routes {
			if r.Contains(addr.Unmap()) {
				return true
			}
		}
	}

	return false
}
