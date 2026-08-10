package connector

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/netstack"
	"github.com/rjsocha/robinet/internal/userdev"
	"github.com/rjsocha/robinet/internal/version"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"golang.org/x/sync/errgroup"
)

// Config is what the connector is told, by flag or by environment.
type Config struct {
	// HubURL is where the enrollment mailbox lives, including the instance,
	// for example https://hub.example:8443 with Instance set separately.
	HubURL   string
	Instance string

	// SharedToken authenticates the enrollment payload end to end. Optional,
	// and strongly recommended: without it the hub could swap our public key.
	SharedToken string

	// Name is a label for the operator approving us.
	Name string

	// Routes to announce on top of, or instead of, what we detect.
	Routes []netip.Prefix

	// Domains to announce on top of, or instead of, what we detect.
	Domains []string

	// DisableAutodiscover stops route and domain detection, leaving only what
	// was given.
	DisableAutodiscover bool

	// StateDir holds the identity and the granted certificate. It must survive
	// restarts, otherwise this connector comes back as a stranger every time.
	StateDir string

	// MTU overrides the computed stack MTU.
	MTU uint32

	// Insecure skips verification of the hub's TLS certificate, which is the
	// normal case for a self signed hub.
	Insecure bool

	// DNS forwards queries sent to our overlay address to the resolver this
	// container uses.
	DNS bool

	Logger *slog.Logger
}

// Run enrolls if needed and then stays connected until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	if cfg.HubURL == "" || cfg.Instance == "" {
		return fmt.Errorf("the hub url and the instance are required")
	}

	state, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}

	// First, and before anything can fail: on a platform the only way to know
	// which build is running is what it says on the way up, and a redeploy
	// that silently kept the old image looks exactly like a fix that did not
	// work.
	log.Info("robinet connector starting",
		"version", version.String(),
		"fingerprint", state.Fingerprint(),
		"state", cfg.StateDir,
	)
	warnIfEphemeral(cfg.StateDir, log)

	given, givenDomains := cfg.Routes, cfg.Domains

	routes := given
	domains := givenDomains
	var found []netip.Prefix
	var foundDomains []string

	if !cfg.DisableAutodiscover {
		found = DiscoverRoutes()
		foundDomains = DiscoverDomains()
		routes = append(routes, found...)
		domains = append(domains, foundDomains...)
	}
	routes = dedupe(routes)
	domains = dedupeStrings(domains)

	// What this connector decided about the network it sits in, before it says
	// any of it to anybody. Nothing here is a secret - the owner sees the same
	// thing when deciding - and it is the only place the reasoning is visible:
	// what was configured, what was detected, and what the two came to.
	describeNetwork(log, cfg, given, found, givenDomains, foundDomains)

	if state.Bundle == nil {
		req := enroll.Request{
			PublicKey: string(state.PublicKeyPEM),
			Name:      cfg.Name,
			Domains:   domains,
			Routes:    routes,
			Hints:     DiscoverHints(),
		}

		// Said before it is sent, so a log shows what was asked for even when
		// nobody ever approves it. The shared token is not here and never is:
		// it authenticates the request without travelling in it.
		log.Info("asking to be admitted",
			"hub", cfg.HubURL,
			"instance", cfg.Instance,
			"name", cfg.Name,
			"routes", prefixList(routes),
			"domains", strings.Join(domains, ","),
			"authenticated", cfg.SharedToken != "",
		)
		for _, k := range sortedKeys(req.Hints) {
			log.Info("telling the owner", "hint", k, "value", req.Hints[k])
		}

		client := newHubClient(cfg.HubURL, cfg.SharedToken, cfg.Insecure, log)
		bundle, err := client.waitForApproval(ctx, cfg.Instance, req, state)
		if err != nil {
			return err
		}
		if err := state.SaveBundle(bundle); err != nil {
			return err
		}

		log.Info("enrollment approved",
			"instance", bundle.Instance,
			"address", bundle.OverlayAddress,
			"lighthouse", bundle.Lighthouse.OverlayAddress,
		)
	}

	compareRoutes(routes, state.Bundle, log)

	return connect(ctx, cfg, state, routes, log)
}

// connect starts nebula on a user space device and attaches the stack.
func connect(ctx context.Context, cfg Config, state *State, routes []netip.Prefix, log *slog.Logger) error {
	bundle := state.Bundle

	raw, err := nebulaConfig(bundle, state.PrivateKeyPEM)
	if err != nil {
		return err
	}

	var c config.C
	if err := c.LoadString(string(raw)); err != nil {
		return fmt.Errorf("could not load the generated config: %w", err)
	}

	var device *userdev.Device
	factory := func(_ *config.C, _ *slog.Logger, networks []netip.Prefix, _ int) (overlay.Device, error) {
		device = userdev.New(networks, nil)
		return device, nil
	}

	control, err := nebula.Main(&c, false, version.Nebula("connector"), log, factory)
	if err != nil {
		return fmt.Errorf("could not start nebula: %w", err)
	}

	mtu := overlayMTU(bundle.MTU, cfg.MTU, log)

	stack, err := netstack.New(control, device, netstack.Options{
		Gateway: true,
		DNS:     cfg.DNS,
		MTU:     mtu,
		Logger:  log,
	})
	if err != nil {
		return err
	}

	log.Info("connector running",
		"instance", bundle.Instance,
		"address", bundle.OverlayAddress,
		"mtu", mtu,
		"routes", routes,
		"dns", cfg.DNS,
		"dnsUpstreams", stack.DNSUpstreams(),
	)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(stack.Wait)
	eg.Go(func() error {
		watchBlocklist(ctx, cfg, state, &c, log)
		return nil
	})
	eg.Go(func() error {
		<-ctx.Done()
		return stack.Close()
	})

	return eg.Wait()
}

// compareRoutes says something loud when the network moved under us.
//
// The certificate is signed once and never refreshed, so a connector whose
// subnet changed keeps a tunnel that quietly carries nothing: both firewalls
// drop the traffic and nothing in the logs explains why.
func compareRoutes(detected []netip.Prefix, bundle *enroll.Bundle, log *slog.Logger) {
	if len(detected) == 0 || bundle == nil {
		return
	}

	c, _, err := cert.UnmarshalCertificateFromPEM([]byte(bundle.Certificate))
	if err != nil {
		return
	}

	granted := map[netip.Prefix]struct{}{}
	for _, p := range c.UnsafeNetworks() {
		granted[p.Masked()] = struct{}{}
	}

	var missing []netip.Prefix
	for _, p := range detected {
		if _, ok := granted[p.Masked()]; !ok {
			missing = append(missing, p)
		}
	}

	if len(missing) > 0 {
		log.Warn("this host is attached to networks the certificate does not carry, traffic for them will be dropped, purge the state directory and enroll again",
			"detected", missing,
			"granted", c.UnsafeNetworks(),
		)
	}
}

func warnIfEphemeral(dir string, log *slog.Logger) {
	if strings.HasPrefix(dir, "/tmp/") {
		log.Warn("the state directory looks temporary, this connector will come back as a new identity after a restart",
			"state", dir,
		)
	}
}

func dedupe(prefixes []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]struct{}{}
	out := make([]netip.Prefix, 0, len(prefixes))

	for _, p := range prefixes {
		p = p.Masked()
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	slices.SortFunc(out, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})

	return out
}

// dedupeStrings keeps the first of each, since order is what an operator wrote.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))

	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}

// blocklistInterval is how often a connector asks whether anybody has been
// banned. Slow, because a ban is rare and this is the only reason to talk to
// the hub at all once a connector is running.
const blocklistInterval = 5 * time.Minute

// watchBlocklist keeps a running connector's refusals up to date.
//
// A connector reads no route table: everything it needs arrived in its bundle
// when it was approved. That leaves one thing it cannot learn - that a member
// it already trusts has been banned - and it is the thing that matters most
// here, because this is the node carrying the network somebody was banned from
// reaching.
func watchBlocklist(ctx context.Context, cfg Config, state *State, c *config.C, log *slog.Logger) {
	if state.RequestID == "" {
		return
	}

	client := newHubClient(cfg.HubURL, cfg.SharedToken, cfg.Insecure, log)
	ticker := time.NewTicker(blocklistInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		res, err := client.result(ctx, cfg.Instance, state.RequestID)
		if err != nil || res.Bundle == nil {
			log.Debug("could not read the blocklist", "error", err)
			continue
		}

		if slices.Equal(res.Bundle.Blocked, state.Bundle.Blocked) {
			continue
		}

		updated := *state.Bundle
		updated.Blocked = res.Bundle.Blocked

		raw, err := nebulaConfig(&updated, state.PrivateKeyPEM)
		if err != nil {
			log.Warn("could not render the new configuration", "error", err)
			continue
		}
		if err := c.ReloadConfigString(string(raw)); err != nil {
			log.Warn("could not apply the new blocklist", "error", err)
			continue
		}

		if err := state.SaveBundle(&updated); err != nil {
			log.Warn("the blocklist was applied but not saved", "error", err)
		}
		state.Bundle = &updated

		log.Info("blocklist updated", "blocked", len(updated.Blocked))
	}
}

// describeNetwork says what this connector made of where it is running.
//
// Two questions get asked of a connector carrying the wrong thing: what did it
// find, and what was it told. Answering both here means neither has to be
// guessed at from outside, where there is no interface to look at.
func describeNetwork(log *slog.Logger, cfg Config, given, found []netip.Prefix, givenDomains, foundDomains []string) {
	if platform, ok := detectPlatform(); ok {
		log.Info("recognized where this is running",
			"platform", platform.name,
			"dropsPlatformIPv4", platform.dropIPv4 && !keepPlatformIPv4(),
		)
	}

	if len(given) > 0 {
		log.Info("told to carry", "routes", prefixList(given))
	}
	if len(givenDomains) > 0 {
		log.Info("told to resolve", "domains", strings.Join(givenDomains, ","))
	}

	if cfg.DisableAutodiscover {
		log.Info("detecting nothing, by configuration")
		return
	}

	// Every prefix on every interface, before the platform filter, so a
	// dropped one is visible as dropped rather than as absent.
	log.Info("attached to", "prefixes", prefixList(attachedPrefixes()))
	log.Info("detected", "routes", prefixList(found), "domains", strings.Join(foundDomains, ","))
}

// prefixList renders prefixes for a log line.
func prefixList(routes []netip.Prefix) string {
	parts := make([]string, 0, len(routes))
	for _, r := range routes {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, ",")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
