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
// It has no tun device: a lighthouse only answers where to find whom, and a
// relay forwards encrypted packets between members without ever handing them to
// an interface. So the hub needs no NET_ADMIN and no /dev/net/tun.
type lighthouse struct {
	control *nebula.Control
	log     *slog.Logger
}

// lighthouseConfig renders the nebula configuration for an instance.
func lighthouseConfig(inst *Instance, bind string) ([]byte, error) {
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
			"serve_dns":     false,
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
		// No tun. A lighthouse routes nothing itself.
		"tun": map[string]any{
			"disabled": true,
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
func startLighthouse(inst *Instance, bind string, log *slog.Logger) (*lighthouse, error) {
	raw, err := lighthouseConfig(inst, bind)
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

	return &lighthouse{control: control, log: l}, nil
}

func (l *lighthouse) stop() {
	if l == nil || l.control == nil {
		return
	}
	l.control.Stop()
}

// lighthouses tracks the running instances.
type lighthouses struct {
	mu      sync.Mutex
	running map[string]*lighthouse
}

func newLighthouses() *lighthouses {
	return &lighthouses{running: map[string]*lighthouse{}}
}

func (ls *lighthouses) start(inst *Instance, bind string, log *slog.Logger) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if _, ok := ls.running[inst.ID]; ok {
		return nil
	}

	lh, err := startLighthouse(inst, bind, log)
	if err != nil {
		return err
	}

	ls.running[inst.ID] = lh
	return nil
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
