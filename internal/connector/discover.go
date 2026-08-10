package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/rjsocha/robinet/internal/enroll"
)

// DiscoverRoutes returns the prefixes this host is directly attached to, less
// the ones the platform it runs on is known to hand out uselessly.
//
// Loopback, link local and unspecified addresses are skipped, as are host
// routes: a /32 or /128 says nothing about a network.
func DiscoverRoutes() []netip.Prefix {
	return platformFilter(attachedPrefixes())
}

// platformFilter drops what the platform hands out uselessly, unless that
// would leave nothing: announcing a range that identifies little still beats
// announcing none at all, and a platform can change under us.
func platformFilter(routes []netip.Prefix) []netip.Prefix {
	p, found := detectPlatform()
	if !found || !p.dropIPv4 || keepPlatformIPv4() {
		return routes
	}

	var kept []netip.Prefix
	for _, r := range routes {
		if !r.Addr().Is4() {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return routes
	}
	return kept
}

// keepPlatformIPv4 is the way out. A platform can change, and a guess about
// one should never be the only behaviour available.
func keepPlatformIPv4() bool {
	switch os.Getenv("ROBINET_KEEP_PLATFORM_IPV4") {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func attachedPrefixes() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	seen := map[netip.Prefix]struct{}{}
	var out []netip.Prefix

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
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
			addr = addr.Unmap()

			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
				continue
			}

			ones, bits := ipnet.Mask.Size()
			if ones == 0 || ones == bits {
				continue
			}

			prefix := netip.PrefixFrom(addr, ones).Masked()
			if _, dup := seen[prefix]; dup {
				continue
			}

			seen[prefix] = struct{}{}
			out = append(out, prefix)
		}
	}

	return out
}

// DiscoverDomains returns the search domains the resolver of this network was
// configured with, which is what makes a bare service name work inside it.
//
// On Railway that is railway.internal, and reusing it is the point: a member of
// the instance types the same name somebody inside the network would.
func DiscoverDomains() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	var out []string

	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		// search takes a list and domain takes one, and both mean the same
		// thing here: what gets completed onto a bare name in this network.
		if fields[0] != "search" && fields[0] != "domain" {
			continue
		}

		for _, candidate := range fields[1:] {
			name, err := enroll.ParseDomain(candidate)
			if err != nil {
				continue
			}
			// A single label is a local search domain, not a zone worth
			// claiming on somebody else's machine.
			if !strings.Contains(name, ".") {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}

	return out
}

// A platform is recognized by an environment variable only it sets, and what
// is worth knowing about a deployment is then read from named variables rather
// than by dumping everything that matched a prefix.
//
// The point is recognition: somebody deciding whether to admit a connector
// wants to read "railway, project netprobe, service robinet" and know whether
// that is theirs. Raw variable names are noise, and ids are noise twice over.
type platform struct {
	name string

	// dropIPv4 says the platform's IPv4 range identifies nothing. Railway
	// gives every project on it the same 10.128.0.0/9 while the IPv6 prefix
	// is unique per environment, so announcing the IPv4 one claims a range
	// that belongs to everybody and collides with every other connector.
	dropIPv4 bool

	// detect is the variable whose presence means this platform. The first
	// match in the list below wins, so containers come last: everything here
	// runs in one.
	detect string

	// fields maps a normalized hint to the variable that carries it. Same
	// vocabulary across providers, so the same three lines are read every time.
	fields map[string]string
}

var platforms = []platform{
	{
		name:     "railway",
		detect:   "RAILWAY_ENVIRONMENT_NAME",
		dropIPv4: true,
		fields: map[string]string{
			"project":     "RAILWAY_PROJECT_NAME",
			"environment": "RAILWAY_ENVIRONMENT_NAME",
			"service":     "RAILWAY_SERVICE_NAME",
			"region":      "RAILWAY_REPLICA_REGION",
		},
	},
	{
		name:   "fly",
		detect: "FLY_APP_NAME",
		fields: map[string]string{
			"service": "FLY_APP_NAME",
			"region":  "FLY_REGION",
		},
	},
	{
		name:   "render",
		detect: "RENDER_SERVICE_NAME",
		fields: map[string]string{
			"service":     "RENDER_SERVICE_NAME",
			"environment": "RENDER_GIT_BRANCH",
		},
	},
	{
		name:   "koyeb",
		detect: "KOYEB_SERVICE_NAME",
		fields: map[string]string{
			"project": "KOYEB_APP_NAME",
			"service": "KOYEB_SERVICE_NAME",
			"region":  "KOYEB_REGION",
		},
	},
	{
		name:   "cloud-run",
		detect: "K_SERVICE",
		fields: map[string]string{
			"service":     "K_SERVICE",
			"environment": "K_REVISION",
		},
	},
	{
		name:   "cloudflare-pages",
		detect: "CF_PAGES_BRANCH",
		fields: map[string]string{
			"project":     "CF_PAGES_URL",
			"environment": "CF_PAGES_BRANCH",
		},
	},
	{
		name:   "kubernetes",
		detect: "KUBERNETES_SERVICE_HOST",
		fields: map[string]string{
			"project": "POD_NAMESPACE",
			"service": "POD_NAME",
		},
	},
}

// DiscoverHints says where this connector runs, in the same words whatever it
// runs on.
func DiscoverHints() map[string]string {
	hints := map[string]string{}

	if host, err := os.Hostname(); err == nil && host != "" {
		hints["hostname"] = host
	}

	if p, found := detectPlatform(); found {
		hints["platform"] = p.name
		for hint, variable := range p.fields {
			if v := os.Getenv(variable); v != "" {
				hints[hint] = v
			}
		}
		return hints
	}

	// Nothing named it, but a container is still worth saying: it means the
	// network being offered is a container network rather than a machine.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		hints["platform"] = "container"
	}

	return hints
}

// detectPlatform returns the first platform claiming this host. Order matters:
// containers come last, because everything here runs in one.
func detectPlatform() (platform, bool) {
	for _, p := range platforms {
		if os.Getenv(p.detect) != "" {
			return p, true
		}
	}
	return platform{}, false
}

func fingerprint(publicKeyPEM string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(publicKeyPEM), " ")))
	return hex.EncodeToString(sum[:])
}
