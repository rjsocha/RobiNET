package hub

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/rjsocha/robinet/internal/version"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"go.yaml.in/yaml/v3"
)

// lighthouse is one instance's nebula process, running in this process.
//
// It routes nothing - a relay forwards encrypted packets between members
// without handing them to an interface - but it does hold a device, because it
// answers DNS on its own overlay address and nothing reaches that address
// without one. So the hub needs CAP_NET_ADMIN and /dev/net/tun.
type lighthouse struct {
	control *nebula.Control
	log     *slog.Logger

	// cfg is what nebula was started from, kept so the blocklist can be
	// changed by reloading it rather than by taking the instance down.
	cfg *config.C
}

// lighthouseDevice names an instance's tun.
//
// From the port rather than the name: a port is unique on this hub by
// construction and is already a number, and an instance's name is chosen by
// whoever created it and has to fit in IFNAMSIZ.
func lighthouseDevice(inst *Instance) string {
	return fmt.Sprintf("robinet-lh%d", inst.Port)
}

// lighthouseConfig renders the nebula configuration for an instance.
func lighthouseConfig(inst *Instance, bind string, dns, noTun bool) ([]byte, error) {
	if inst.CACert == "" || inst.LighthouseCert == "" {
		return nil, fmt.Errorf("instance %s has no certificate yet", inst.ID)
	}

	pki := map[string]any{
		"ca":   inst.CACert,
		"cert": inst.LighthouseCert,
		"key":  inst.LighthouseKey,
	}
	if blocked := blockedIn(inst); len(blocked) > 0 {
		// The lighthouse refuses them too, so a banned member cannot even ask
		// where anybody is.
		pki["blocklist"] = blocked
	}

	cfg := map[string]any{
		"pki":             pki,
		"static_host_map": map[string]any{},
		"lighthouse": map[string]any{
			"am_lighthouse": true,

			// Every member handshakes the lighthouse, and nebula records the
			// remote certificate's name against its overlay address as it
			// does. So the lighthouse already holds the one complete list of
			// who is where, and answering for it costs a listener.
			//
			// The names are the certificate names:
			// <member>.<kind>.<instance>.instance, which is what
			// MemberCertName builds and what a member can be reached by
			// without this machine's resolver being told anything.
			//
			// Off when the hub says so, and off without a device whatever the
			// hub says: nothing addressed to the lighthouse arrives without
			// one, so a listener would answer nobody.
			"serve_dns": dns && !noTun,
			"dns": map[string]any{
				// The overlay address, not the host's. Reachable only from
				// inside the instance, which is the whole of who should be
				// asking, and it needs the tun below to exist at all.
				"host": inst.LighthouseAddress.String(),
				"port": 53,
			},
		},
		"listen": map[string]any{
			"host": bind,
			"port": int(inst.Port),
		},
		"punchy": map[string]any{
			"punch":              true,
			"respond":            true,
			"target_all_remotes": true,
		},
		"relay": map[string]any{
			"am_relay":   inst.Relay,
			"use_relays": false,
		},
		// A lighthouse routes nothing, but it does answer: DNS above is served
		// on its overlay address, and a packet only arrives there through a
		// device. A disabled tun answers ICMP echo and discards the rest.
		//
		// One device per instance, named after its port, because the hub runs
		// one lighthouse per instance and they cannot share a name.
		"tun": map[string]any{
			"dev":      lighthouseDevice(inst),
			"disabled": noTun,
		},
		"firewall": map[string]any{
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

// startLighthouse brings an instance's nebula up.
func startLighthouse(inst *Instance, bind string, dns, noTun bool, log *slog.Logger) (*lighthouse, error) {
	raw, err := lighthouseConfig(inst, bind, dns, noTun)
	if err != nil {
		return nil, err
	}

	var c config.C
	if err := c.LoadString(string(raw)); err != nil {
		return nil, fmt.Errorf("could not load the generated config: %w", err)
	}

	l := log.With("instance", inst.Name, "port", inst.Port)

	control, err := nebula.Main(&c, false, version.Nebula("hub"), l, overlay.NewDeviceFromConfig)
	if err != nil {
		return nil, fmt.Errorf("could not start nebula: %w", err)
	}

	control.Start()

	return &lighthouse{control: control, log: l, cfg: &c}, nil
}

func (l *lighthouse) stop() {
	if l == nil || l.control == nil {
		return
	}
	l.control.Stop()
}

// lighthouses tracks the running instances.
type lighthouses struct {
	// dns and noTun are the hub's, not one instance's: every lighthouse here
	// answers or none does, and a machine either can create a device or
	// cannot.
	dns   bool
	noTun bool

	mu      sync.Mutex
	running map[string]*lighthouse
}

func newLighthouses(dns, noTun bool) *lighthouses {
	return &lighthouses{dns: dns, noTun: noTun, running: map[string]*lighthouse{}}
}

func (ls *lighthouses) start(inst *Instance, bind string, log *slog.Logger) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if _, ok := ls.running[inst.ID]; ok {
		return nil
	}

	lh, err := startLighthouse(inst, bind, ls.dns, ls.noTun, log)
	if err != nil {
		return err
	}

	ls.running[inst.ID] = lh
	return nil
}

// reload hands a running lighthouse a new configuration.
//
// A ban changes one thing, pki.blocklist, and nebula reloads that in place. It
// used to be done by stopping the instance and starting it again, which was
// free while a lighthouse had no device and stopped being free the moment it
// got one: the kernel had not released the tun by the time the new nebula
// asked for it, so the start failed with "device or resource busy" and the
// instance was left with no lighthouse at all, after the ban had already been
// recorded.
func (ls *lighthouses) reload(inst *Instance, bind string, log *slog.Logger) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	lh, ok := ls.running[inst.ID]
	if !ok || lh.cfg == nil {
		return nil
	}

	raw, err := lighthouseConfig(inst, bind, ls.dns, ls.noTun)
	if err != nil {
		return err
	}

	return lh.cfg.ReloadConfigString(string(raw))
}

func (ls *lighthouses) stop(id string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if lh, ok := ls.running[id]; ok {
		lh.stop()
		delete(ls.running, id)
	}
}

func (ls *lighthouses) stopAll() {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	for id, lh := range ls.running {
		lh.stop()
		delete(ls.running, id)
	}
}

func (ls *lighthouses) isRunning(id string) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	_, ok := ls.running[id]
	return ok
}

// RedactedKey stands in for a private key that was left out.
const RedactedKey = "<redacted, --show-keys>"

// LighthouseConfig renders what nebula is given for one instance.
//
// The same bytes the running lighthouse was loaded from, since the
// configuration is a function of the instance and the hub's own settings and
// nothing else. A ban is the one thing that changes it while the hub runs, and
// it changes the state this reads from too, so the two do not drift.
//
// The signing key is left out unless asked for. Everything else - the
// authority, the certificate, the addresses, the ports - is public by nature
// or already visible to every member.
func LighthouseConfig(inst *Instance, cfg Config, showKeys bool) ([]byte, error) {
	raw, err := lighthouseConfig(inst, cfg.NebulaBind, cfg.DNS, cfg.NoLighthouseTun)
	if err != nil {
		return nil, err
	}
	if showKeys {
		return raw, nil
	}

	return RedactKey(raw)
}

// RedactKey takes the signing key out of a rendered nebula configuration.
//
// Here rather than beside each caller because a tenant's configuration carries
// the same field and hiding it has to mean the same thing in both: one word to
// grep for, one place to change if the shape ever moves.
func RedactKey(raw []byte) ([]byte, error) {
	// Redacted on the rendered tree rather than while rendering, so what is
	// printed has the shape of the real thing down to the last key.
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	if pki, ok := tree["pki"].(map[string]any); ok {
		if _, held := pki["key"]; held {
			pki["key"] = RedactedKey
		}
	}

	return yaml.Marshal(tree)
}
