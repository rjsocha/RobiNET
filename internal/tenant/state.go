// Package tenant is the daemon on an operator's own machine. It registers with
// a hub, owns the instances it creates, joins the ones it is admitted to, and
// runs nebula for each of them.
package tenant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
)

// Owned is an instance this machine created, and the authority that goes with
// it. The signing key lives here and nowhere else.
type Owned struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`

	CACert string `json:"ca_cert"`
	CAKey  string `json:"ca_key"`

	SharedToken string `json:"shared_token,omitempty"`
}

// Connection is a membership: a certificate for one instance and everything
// needed to run nebula against it.
//
// A separate keypair per instance, so nothing about this machine correlates
// across the instances it belongs to.
type Connection struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`

	// Role is owner or tenant, as the hub sees it.
	Role string `json:"role"`

	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`

	Certificate string       `json:"certificate,omitempty"`
	CA          string       `json:"ca,omitempty"`
	Address     netip.Prefix `json:"address,omitempty"`
	Address6    netip.Prefix `json:"address6,omitempty"`

	Lighthouse enroll.Lighthouse `json:"lighthouse,omitempty"`
	MTU        uint32            `json:"mtu,omitempty"`

	// Device is the tun this connection runs on. Fixed once, so a restart does
	// not shuffle interface names.
	Device string `json:"device"`

	// ListenPort is the udp port nebula binds. Zero means an ephemeral one,
	// which is right behind NAT.
	ListenPort int `json:"listen_port,omitempty"`

	RequestedAt time.Time `json:"requested_at,omitempty"`
	JoinedAt    time.Time `json:"joined_at,omitempty"`
}

// Ready reports whether this connection has everything it needs to run.
func (c *Connection) Ready() bool {
	return c.Certificate != "" && c.CA != "" && c.Lighthouse.OverlayAddress.IsValid()
}

// State is everything this machine keeps.
type State struct {
	path string
	mu   sync.RWMutex

	data data
}

type data struct {
	// HubURL and Identity are what this machine is on the hub. One hub per
	// machine: more than one would mean more than one answer to "who am I
	// here", for no gain worth the confusion.
	HubURL   string `json:"hub_url"`
	Identity string `json:"identity"`
	Binder   string `json:"binder,omitempty"`
	Name     string `json:"name,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	Pin      string `json:"pin,omitempty"`

	// Families says which address families this machine installs routes for.
	// Empty means both, which is what a machine that never said otherwise
	// gets.
	//
	// It is local and told to nobody. A certificate carries both families
	// whatever this says, because what a machine can use is a property of that
	// machine today and a certificate signed once outlives it.
	Families string `json:"families,omitempty"`

	// Inbound is what members of an instance may reach on this machine.
	// Empty means ping, which is what a machine that never said otherwise
	// gets.
	//
	// Local, and told to nobody. Joining an instance to reach a network is not
	// an offer to be reached back, and nothing about it belongs to the
	// instance: the machine that carries the consequence makes the decision.
	Inbound string `json:"inbound,omitempty"`

	// Aliases are extra names for a name space, chosen here and told to
	// nobody: <alias> answers exactly as <canonical> does. Keyed by the alias,
	// because that is what has to be unique.
	Aliases map[string]string `json:"aliases,omitempty"`

	// Owner is the person this daemon belongs to. Recorded at registration so
	// root never has to guess it from the environment.
	Owner    string `json:"owner,omitempty"`
	OwnerUID int    `json:"owner_uid,omitempty"`
	OwnerGID int    `json:"owner_gid,omitempty"`

	Owned       map[string]*Owned      `json:"owned,omitempty"`
	Connections map[string]*Connection `json:"connections,omitempty"`
}

// OpenState reads the state file, creating an empty one if missing.
func OpenState(path string) (*State, error) {
	s := &State{path: path}
	s.data.Owned = map[string]*Owned{}
	s.data.Connections = map[string]*Connection{}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("could not read the state file: %w", err)
	}

	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("could not parse the state file: %w", err)
	}
	if s.data.Owned == nil {
		s.data.Owned = map[string]*Owned{}
	}
	if s.data.Connections == nil {
		s.data.Connections = map[string]*Connection{}
	}

	return s, nil
}

// Registered reports whether this machine knows a hub.
func (s *State) Registered() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.HubURL != "" && s.data.Identity != ""
}

// Read runs fn against the state under a read lock.
func (s *State) Read(fn func(*data)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.data)
}

// Write runs fn against the state and persists the result.
func (s *State) Write(fn func(*data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fn(&s.data); err != nil {
		return err
	}

	return s.save()
}

func (s *State) save() error {
	raw, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}

	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp := s.path + ".tmp"
	// Authority keys live in here, so nothing wider than the owner.
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, s.path)
}

// Connections returns a snapshot.
func (s *State) Connections() []*Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Connection, 0, len(s.data.Connections))
	for _, c := range s.data.Connections {
		copied := *c
		out = append(out, &copied)
	}
	return out
}

// Connection returns one by instance id.
func (s *State) Connection(id string) (*Connection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, ok := s.data.Connections[id]
	if !ok {
		return nil, false
	}
	copied := *c
	return &copied, true
}

// Owned returns the authority for an instance this machine created.
func (s *State) Owned(id string) (*Owned, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	o, ok := s.data.Owned[id]
	if !ok {
		return nil, false
	}
	copied := *o
	return &copied, true
}

// nextDevice picks a free tun name. The caller holds the write lock.
func (d *data) nextDevice() string {
	taken := map[string]bool{}
	for _, c := range d.Connections {
		taken[c.Device] = true
	}

	for i := 0; i < 256; i++ {
		name := fmt.Sprintf("robinet%d", i)
		if !taken[name] {
			return name
		}
	}
	return "robinet255"
}

// Address families a machine may install routes for.
const (
	FamiliesBoth = "both"
	FamiliesIPv4 = "ipv4"
	FamiliesIPv6 = "ipv6"
)

// ValidFamilies reports whether a setting is one of the three.
func ValidFamilies(f string) bool {
	switch f {
	case FamiliesBoth, FamiliesIPv4, FamiliesIPv6:
		return true
	}
	return false
}

// Families is what this machine installs, never empty.
func (s *State) Families() string {
	out := FamiliesBoth
	s.Read(func(d *data) {
		if ValidFamilies(d.Families) {
			out = d.Families
		}
	})
	return out
}

// SetFamilies records the choice.
func (s *State) SetFamilies(f string) error {
	if !ValidFamilies(f) {
		return fmt.Errorf("%q is not one of both, ipv4, ipv6", f)
	}
	return s.Write(func(d *data) error {
		d.Families = f
		return nil
	})
}

// wanted reports whether a prefix is of a family this machine installs.
func wantedFamily(families string, p netip.Prefix) bool {
	switch families {
	case FamiliesIPv4:
		return p.Addr().Is4()
	case FamiliesIPv6:
		return !p.Addr().Is4()
	default:
		return true
	}
}

// What members of an instance may reach on this machine.
const (
	// InboundPing answers echo requests and nothing else. Ping is what people
	// reach for to see whether a tunnel is alive, and it gives nothing away.
	InboundPing = "ping"

	// InboundOpen is every port, which is what a machine offering a service to
	// the instance needs and what nobody should get by default.
	InboundOpen = "open"

	// InboundNone answers nothing at all.
	InboundNone = "none"
)

// ValidInbound reports whether a setting is one this understands.
func ValidInbound(v string) bool {
	switch v {
	case InboundPing, InboundOpen, InboundNone:
		return true
	}
	return false
}

// Inbound is what this machine allows, never empty.
func (s *State) Inbound() string {
	out := InboundPing
	s.Read(func(d *data) {
		if ValidInbound(d.Inbound) {
			out = d.Inbound
		}
	})
	return out
}

// SetInbound records the choice.
func (s *State) SetInbound(v string) error {
	if !ValidInbound(v) {
		return fmt.Errorf("%q is not one of ping, open, none", v)
	}
	return s.Write(func(d *data) error {
		d.Inbound = v
		return nil
	})
}

// inboundRules renders the nebula firewall for a choice.
//
// A connector is not affected by any of this: being reached is what it is for,
// and this is the tenant's own configuration.
func inboundRules(inbound string) []map[string]any {
	switch inbound {
	case InboundOpen:
		return []map[string]any{
			{"port": "any", "proto": "any", "host": "any"},
		}
	case InboundNone:
		// Nebula takes an empty list as "allow nothing", which is different
		// from the key being absent.
		return []map[string]any{}
	default:
		return []map[string]any{
			{"port": "any", "proto": "icmp", "host": "any"},
		}
	}
}

// Aliases returns the extra names this machine answers under.
func (s *State) Aliases() map[string]string {
	out := map[string]string{}
	s.Read(func(d *data) {
		for alias, canonical := range d.Aliases {
			out[alias] = canonical
		}
	})
	return out
}

// SetAlias records one, or removes it when canonical is empty.
func (s *State) SetAlias(alias, canonical string) error {
	return s.Write(func(d *data) error {
		if canonical == "" {
			delete(d.Aliases, alias)
			return nil
		}
		if d.Aliases == nil {
			d.Aliases = map[string]string{}
		}
		d.Aliases[alias] = canonical
		return nil
	})
}
