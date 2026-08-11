// Package hub is the daemon on the public address. It runs a nebula lighthouse
// per instance, allocates addresses and ports, carries enrollment requests, and
// keeps the route table every member reads.
//
// It holds no certificate authority key and makes no decisions.
package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
)

// ErrNotFound is returned for an unknown instance, request or identity.
var ErrNotFound = errors.New("not found")

// Kinds of member and of pending request.
const (
	KindConnector = "connector"
	KindTenant    = "tenant"
	KindOwner     = "owner"
)

// Registration is a machine this hub knows.
//
// Registering proves only that the machine belongs to somebody the hub knows.
// It grants nothing: which instance it may enter is the owner's decision.
type Registration struct {
	Identity string `json:"identity"`

	// Binder is who vouched for it, taken from the ssh key that signed.
	Binder string `json:"binder"`

	// Name is what the machine calls itself, for the log and the listing.
	Name string `json:"name,omitempty"`

	// Key is the ssh key that signed, in authorized_keys form.
	Key string `json:"key,omitempty"`

	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at,omitempty"`
}

// Member is somebody admitted to an instance.
type Member struct {
	// Kind is connector, tenant or owner.
	Kind string `json:"kind"`

	Name string `json:"name,omitempty"`

	// Fingerprint of the nebula public key: the thing a certificate was issued
	// for, and what ban is keyed on.
	Fingerprint string `json:"fingerprint"`

	// Identity is the wrak identity, for members that have one. A connector
	// has none: it is admitted by its key alone.
	Identity string `json:"identity,omitempty"`

	// Binder is who the member belongs to, when it came in through a
	// registration.
	Binder string `json:"binder,omitempty"`

	Address netip.Prefix `json:"address"`

	// Address6 is the same member's IPv6 address, when the hub has a pool for
	// one. A certificate needs it to carry an IPv6 route.
	Address6 netip.Prefix `json:"address6,omitempty"`

	// Routes are the prefixes a connector carries. Empty for anyone else.
	Routes []netip.Prefix `json:"routes,omitempty"`

	// Domain is the zone it can resolve. Carried beside the routes rather than
	// in the certificate, so admitting a connector makes its names work for
	// everybody without anything being reissued.
	Domain string `json:"domain,omitempty"`

	CertFingerprint string `json:"cert_fingerprint,omitempty"`

	// Events are the decisions taken about this member, in the order they were
	// taken. The current state is the last one, so a ban after an unban after a
	// ban needs nothing reconciled: there is no second place recording whether
	// this member is blocked, only the end of this list.
	Events []MemberEvent `json:"events,omitempty"`

	JoinedAt time.Time `json:"joined_at"`
}

// Kinds of decision recorded against a member.
const (
	EventBan   = "ban"
	EventUnban = "unban"
)

// MemberEvent is one decision about a member, with the reason it was taken.
//
// The note is the only place the reason survives. A fingerprint six months old
// says nothing about why somebody was shut out, and the moment of the decision
// is the only moment anybody knows.
type MemberEvent struct {
	Kind string    `json:"kind"`
	Note string    `json:"note,omitempty"`
	At   time.Time `json:"at"`
}

// Banned reports whether the last decision taken about this member was a ban.
func (m *Member) Banned() bool {
	if len(m.Events) == 0 {
		return false
	}
	return m.Events[len(m.Events)-1].Kind == EventBan
}

// Burned is a credential that will never be admitted to this instance again.
//
// It outlives the member it belonged to, which is the whole point: removing a
// member frees its name and its address, and without this the certificate it
// still holds would come off every blocklist at the same moment.
type Burned struct {
	// Fingerprint of the nebula public key. An enrollment carrying it is
	// refused by the hub without troubling the owner.
	Fingerprint string `json:"fingerprint"`

	// CertFingerprint is what goes onto every member's blocklist. Empty for a
	// member that was removed before it was ever issued a certificate.
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
}

// Instance is one mesh: its own authority, its own overlay prefix, its own
// lighthouse on its own port.
type Instance struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Owner is the identity that created this instance and holds its
	// certificate authority. Only it may decide who joins.
	Owner  string `json:"owner"`
	Binder string `json:"binder"`

	Overlay  netip.Prefix `json:"overlay"`
	Overlay6 netip.Prefix `json:"overlay6,omitempty"`
	Port     uint16       `json:"port"`

	// Lighthouse material. The hub generates the keypair and never sees the
	// authority key, so the certificate has to come back from the owner.
	LighthouseAddress  netip.Addr `json:"lighthouse_address"`
	LighthouseAddress6 netip.Addr `json:"lighthouse_address6,omitempty"`

	// TenantAddress belongs to the owner's own node. Reserved here so the hub
	// stays the single place that knows what is taken.
	TenantAddress  netip.Addr `json:"tenant_address"`
	TenantAddress6 netip.Addr `json:"tenant_address6,omitempty"`

	LighthousePublicKey string `json:"lighthouse_public_key"`
	LighthouseKey       string `json:"lighthouse_key"`
	LighthouseCert      string `json:"lighthouse_cert,omitempty"`
	CACert              string `json:"ca_cert,omitempty"`

	Relay bool `json:"relay"`

	// SharedToken, when set, is required on connector enrollments and
	// authenticates them end to end.
	SharedToken string `json:"shared_token,omitempty"`

	// Allocations is the sticky map from a nebula key fingerprint to its
	// address, and Allocations6 is the same for the other family. Two maps
	// rather than one, because the two pools are independent: a member may
	// hold an address in one and none in the other.
	Allocations  map[string]netip.Addr `json:"allocations,omitempty"`
	Allocations6 map[string]netip.Addr `json:"allocations6,omitempty"`

	// Requests are the enrollments waiting for a decision, keyed by id.
	Requests map[string]*Record `json:"requests,omitempty"`

	// Members are everyone admitted, keyed by nebula key fingerprint.
	Members map[string]*Member `json:"members,omitempty"`

	// Burned are the credentials of removed members. Nothing takes anything off
	// this list.
	Burned []Burned `json:"burned,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Record is a stored request plus what the owner decided.
type Record struct {
	enroll.Record

	// Kind says whether this asks to carry routes or to consume them.
	Kind string `json:"kind"`

	// Identity and Binder are set for a tenant, which arrives through a
	// registration rather than anonymously.
	Identity string `json:"identity,omitempty"`
	Binder   string `json:"binder,omitempty"`

	// Bundle is filled in once the owner approves.
	Bundle *enroll.Bundle `json:"bundle,omitempty"`

	// Reason explains a rejection.
	Reason string `json:"reason,omitempty"`
}

// RouteTable is what every member reads to know where to send traffic.
//
// It lives here rather than in any one member's configuration, so admitting a
// connector changes what everybody sees without reissuing a certificate.
type RouteTable struct {
	Instance   string            `json:"instance"`
	Overlay    netip.Prefix      `json:"overlay"`
	Lighthouse enroll.Lighthouse `json:"lighthouse"`
	Routes     []Route           `json:"routes"`

	// Resolvers say which member to ask about which names.
	Resolvers []Resolver `json:"resolvers,omitempty"`

	// Blocked are the fingerprints of certificates that must be refused, which
	// is the only part of a ban that cannot be done by leaving something out.
	// Taking a member's routes away stops anybody being told where it is; this
	// stops anybody talking to it who already knows.
	Blocked []string `json:"blocked,omitempty"`

	MTU uint32 `json:"mtu,omitempty"`
}

// Resolver is one domain and the member that answers for it.
//
// A member answers on its own overlay address, using the resolver of the
// network it sits in, so this is the whole of what anybody needs: a name to
// match and an address to ask.
type Resolver struct {
	Domain string `json:"domain"`

	// Via and Via6 are the member's addresses. Both, because a resolver is
	// asked by this machine's own stack rather than through the tunnel's
	// routing, so a machine that installs one family has to be given an
	// address of that family.
	Via  netip.Addr `json:"via"`
	Via6 netip.Addr `json:"via6,omitempty"`

	Connector string `json:"connector,omitempty"`
}

// Route is one prefix and the member that carries it.
type Route struct {
	Prefix    netip.Prefix `json:"prefix"`
	Via       netip.Addr   `json:"via"`
	Connector string       `json:"connector,omitempty"`
}

// MemberOf reports whether an identity belongs to an instance, and how.
func (inst *Instance) MemberOf(identity string) (*Member, bool) {
	if identity == "" {
		return nil, false
	}

	for _, m := range inst.Members {
		if m.Identity == identity && !m.Banned() {
			return m, true
		}
	}

	if identity == inst.Owner {
		// The owner belongs by construction, from the moment the instance
		// exists and before its own node has enrolled.
		return &Member{Kind: KindOwner, Identity: identity}, true
	}

	return nil, false
}

// Store keeps hub state. It is a JSON file rewritten atomically: at the scale
// this tool targets, a handful of instances and members, a database would be
// ceremony without benefit. The interface is narrow enough to swap later.
type Store struct {
	path string

	mu    sync.RWMutex
	state state
}

type state struct {
	Instances  map[string]*Instance     `json:"instances"`
	Identities map[string]*Registration `json:"identities"`
}

// OpenStore reads the state file, creating an empty one if it is missing.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	s.state.Instances = map[string]*Instance{}
	s.state.Identities = map[string]*Registration{}

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("could not read the state file: %w", err)
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("could not parse the state file: %w", err)
	}
	if s.state.Instances == nil {
		s.state.Instances = map[string]*Instance{}
	}
	if s.state.Identities == nil {
		s.state.Identities = map[string]*Registration{}
	}

	// An empty map is omitted when the state is written, so it comes back as
	// nil rather than as an empty map. Writing to one of those panics, which
	// is how a hub that had been restarted refused the first enrollment after
	// an instance was created.
	for _, inst := range s.state.Instances {
		inst.ensureMaps()
	}

	return s, nil
}

// ensureMaps makes an instance safe to write to.
func (inst *Instance) ensureMaps() {
	if inst.Allocations == nil {
		inst.Allocations = map[string]netip.Addr{}
	}
	if inst.Requests == nil {
		inst.Requests = map[string]*Record{}
	}
	if inst.Members == nil {
		inst.Members = map[string]*Member{}
	}
}

// save writes the state out. The caller holds the lock.
func (s *Store) save() error {
	data, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}

	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, s.path)
}

// Register records a machine, or refreshes what is known about it.
func (s *Store) Register(r *Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.state.Identities[r.Identity]; ok {
		existing.Binder = r.Binder
		existing.Name = r.Name
		existing.Key = r.Key
		existing.LastSeenAt = time.Now().UTC()
	} else {
		r.RegisteredAt = time.Now().UTC()
		s.state.Identities[r.Identity] = r
	}

	return s.save()
}

// Identity returns what is known about a registered machine.
func (s *Store) Identity(identity string) (*Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.state.Identities[identity]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// Update runs fn against an instance and persists the result.
func (s *Store) Update(id string, fn func(*Instance) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inst, ok := s.state.Instances[id]
	if !ok {
		return ErrNotFound
	}

	// Belt as well as braces: every write path goes through here.
	inst.ensureMaps()

	if err := fn(inst); err != nil {
		return err
	}

	return s.save()
}

// Add stores a new instance.
func (s *Store) Add(inst *Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.Instances[inst.ID]; ok {
		return fmt.Errorf("instance %s already exists", inst.ID)
	}

	// Names are unique on a hub, which is what lets one be written into a
	// connector's endpoint and one day into a domain. Checked here rather than
	// before calling, so two creates at once cannot both pass.
	for _, other := range s.state.Instances {
		if other.Name == inst.Name {
			return fmt.Errorf("%s already has an instance called %s", other.Binder, inst.Name)
		}
	}

	s.state.Instances[inst.ID] = inst
	return s.save()
}

// Remove drops an instance and everything the hub knew about it.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.Instances[id]; !ok {
		return ErrNotFound
	}

	delete(s.state.Instances, id)
	return s.save()
}

// Get returns an instance for reading. Callers must not mutate it outside
// Update.
func (s *Store) Get(id string) (*Instance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inst, ok := s.state.Instances[id]
	if !ok {
		return nil, ErrNotFound
	}
	return inst, nil
}

// ErrAmbiguous says a name matches more than one instance.
var ErrAmbiguous = errors.New("more than one instance has that name")

// Resolve finds an instance by id or by name.
//
// A name is what somebody writes into a connector's environment, and it is not
// unique on a hub: two people may each call one railway. So an id always wins,
// a name resolves when only one instance has it, and anything else is refused
// rather than guessed at. A connector that reached the wrong instance would be
// asking a stranger for a certificate.
func (s *Store) Resolve(ref string) (*Instance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if inst, ok := s.state.Instances[ref]; ok {
		return inst, nil
	}

	// Names are stored folded, and a name is not case sensitive anywhere it
	// will be used.
	name := strings.ToLower(strings.TrimSpace(ref))

	var found *Instance
	for _, inst := range s.state.Instances {
		if inst.Name != name {
			continue
		}
		if found != nil {
			return nil, ErrAmbiguous
		}
		found = inst
	}

	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}

// Registrations returns every machine this hub knows.
func (s *Store) Registrations() []*Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Registration, 0, len(s.state.Identities))
	for _, r := range s.state.Identities {
		out = append(out, r)
	}
	return out
}

// List returns every instance.
func (s *Store) List() []*Instance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Instance, 0, len(s.state.Instances))
	for _, inst := range s.state.Instances {
		out = append(out, inst)
	}
	return out
}

// UsedOverlays reports which overlay prefixes are taken.
func (s *Store) UsedOverlays() map[netip.Prefix]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	used := make(map[netip.Prefix]struct{}, len(s.state.Instances))
	for _, inst := range s.state.Instances {
		used[inst.Overlay] = struct{}{}
	}
	return used
}

// UsedOverlays6 reports which IPv6 overlay prefixes are taken.
func (s *Store) UsedOverlays6() map[netip.Prefix]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	used := make(map[netip.Prefix]struct{}, len(s.state.Instances))
	for _, inst := range s.state.Instances {
		if inst.Overlay6.IsValid() {
			used[inst.Overlay6] = struct{}{}
		}
	}
	return used
}

// UsedPorts reports which UDP ports are taken.
func (s *Store) UsedPorts() map[uint16]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	used := make(map[uint16]struct{}, len(s.state.Instances))
	for _, inst := range s.state.Instances {
		used[inst.Port] = struct{}{}
	}
	return used
}
