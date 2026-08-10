package tenant

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/version"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"go.yaml.in/yaml/v3"
)

// runner is one connection's nebula: its own tun, its own certificate, its own
// lighthouse. Several may run at once, one per instance.
type runner struct {
	instance string
	control  *nebula.Control
	cfg      *config.C
	log      *slog.Logger
}

// runners tracks what is up.
type runners struct {
	mu      sync.Mutex
	running map[string]*runner
}

func newRunners() *runners {
	return &runners{running: map[string]*runner{}}
}

func (rs *runners) start(conn *Connection, table *hub.RouteTable, local choices, log *slog.Logger) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if _, ok := rs.running[conn.InstanceID]; ok {
		return nil
	}

	raw, err := renderConfig(conn, table, local)
	if err != nil {
		return err
	}

	var c config.C
	if err := c.LoadString(string(raw)); err != nil {
		return fmt.Errorf("could not load the generated config: %w", err)
	}

	l := log.With("instance", conn.Name, "device", conn.Device)

	control, err := nebula.Main(&c, false, version.Nebula("tenant"), l, overlay.NewDeviceFromConfig)
	if err != nil {
		return fmt.Errorf("could not start nebula: %w", err)
	}
	control.Start()

	rs.running[conn.InstanceID] = &runner{
		instance: conn.InstanceID,
		control:  control,
		cfg:      &c,
		log:      l,
	}

	l.Info("connected", "address", conn.Address, "routes", len(table.Routes))
	return nil
}

// reload pushes a new route table into a running nebula, which is how a
// connector admitted a minute ago becomes reachable without a restart.
func (rs *runners) reload(conn *Connection, table *hub.RouteTable, local choices) error {
	rs.mu.Lock()
	r, ok := rs.running[conn.InstanceID]
	rs.mu.Unlock()

	if !ok {
		return nil
	}

	raw, err := renderConfig(conn, table, local)
	if err != nil {
		return err
	}

	return r.cfg.ReloadConfigString(string(raw))
}

func (rs *runners) stop(instance string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if r, ok := rs.running[instance]; ok {
		r.control.Stop()
		delete(rs.running, instance)
	}
}

func (rs *runners) stopAll() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for id, r := range rs.running {
		r.control.Stop()
		delete(rs.running, id)
	}
}

func (rs *runners) isRunning(instance string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	_, ok := rs.running[instance]
	return ok
}

// renderConfig builds nebula's configuration for one connection.
//
// The routes come from the hub rather than from anything local: a member
// consumes the table, it does not own it.
func renderConfig(conn *Connection, table *hub.RouteTable, local choices) ([]byte, error) {
	if !conn.Ready() {
		return nil, fmt.Errorf("connection to %s has no certificate yet", conn.Name)
	}
	if len(conn.Lighthouse.Endpoints) == 0 {
		return nil, fmt.Errorf("connection to %s has no lighthouse endpoint", conn.Name)
	}

	lighthouse := conn.Lighthouse.OverlayAddress.String()

	var routes []map[string]any
	for _, r := range table.Routes {
		// Our own routes are not ours to install: a connector reaches its own
		// network directly.
		if r.Via == conn.Address.Addr() {
			continue
		}
		// A machine that installs one family only still holds a certificate
		// for both, and still reaches the lighthouse. This decides what goes
		// on the device, nothing else.
		if !wantedFamily(local.families, r.Prefix) {
			continue
		}
		routes = append(routes, map[string]any{
			"route": r.Prefix.String(),
			"via":   r.Via.String(),
		})
	}

	if local.chromiumProbeRoute && conn.Address6.IsValid() && wantedFamily(local.families, chromiumProbe) {
		// The route has to exist for Chromium's probe to succeed, and it has
		// to lead nowhere: nothing is meant to arrive. Via the lighthouse
		// because a via has to be somebody, and a packet that really goes
		// there is dropped at the far end rather than starting a handshake
		// with an address nobody holds.
		//
		// Only where the device has an IPv6 address of its own: without one
		// the kernel has no source to answer with and the probe fails anyway,
		// leaving a hijacked address and nothing gained.
		routes = append(routes, map[string]any{
			"route": chromiumProbe.String(),
			"via":   lighthouse,
		})
	}

	tun := map[string]any{
		"dev":      conn.Device,
		"disabled": false,
	}
	if len(routes) > 0 {
		tun["unsafe_routes"] = routes
	}

	pki := map[string]any{
		"ca":   conn.CA,
		"cert": conn.Certificate,
		"key":  conn.PrivateKey,
	}
	if len(table.Blocked) > 0 {
		// A banned member's certificate is still valid and still signed by an
		// authority we trust. Refusing it is the only thing that stops it
		// reaching us, since it already knows where we are.
		pki["blocklist"] = table.Blocked
	}

	cfg := map[string]any{
		"pki": pki,
		"static_host_map": map[string]any{
			lighthouse: conn.Lighthouse.Endpoints,
		},
		"lighthouse": map[string]any{
			"am_lighthouse": false,
			"interval":      5,
			"hosts":         []string{lighthouse},
		},
		"listen": map[string]any{
			"host": "0.0.0.0",
			"port": conn.ListenPort,
		},
		"punchy": map[string]any{
			"punch":              true,
			"respond":            true,
			"target_all_remotes": true,
		},
		"relay": map[string]any{
			"am_relay":   false,
			"use_relays": conn.Lighthouse.Relay,
		},
		"handshakes": map[string]any{
			"try_interval": "100ms",
			"retries":      40,
		},
		"timers": map[string]any{
			"connection_alive_interval": 2,
			"pending_deletion_interval": 3,
		},
		"tun": tun,
		"firewall": map[string]any{
			// Without this an inbound rule only matches our own overlay
			// address once a certificate carries unsafe networks.
			"default_local_cidr_any": true,
			"outbound": []map[string]any{
				{"port": "any", "proto": "any", "host": "any"},
			},
			// What members of this instance may reach here. Ping by default:
			// joining an instance to reach a network is not an offer to be
			// reached back.
			"inbound": inboundRules(local.inbound),
		},
		"logging": map[string]any{
			"level":  "info",
			"format": "text",
		},
	}

	return yaml.Marshal(cfg)
}

// collides reports the connection already carrying a prefix that overlaps one
// of these, if any.
//
// Two paths to the same prefix cannot both live in one route table, and
// quietly picking one would make the loser look broken for no visible reason.
func collides(existing map[string][]netip.Prefix, instance string, wanted []netip.Prefix) (string, netip.Prefix, bool) {
	for other, held := range existing {
		if other == instance {
			continue
		}
		for _, a := range held {
			for _, b := range wanted {
				if a.Overlaps(b) {
					return other, b, true
				}
			}
		}
	}
	return "", netip.Prefix{}, false
}
