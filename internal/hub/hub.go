package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/wrak"
)

// Config is what the hub daemon is told at startup.
type Config struct {
	// APIAddr is where the enrollment API listens, for example ":8443".
	APIAddr string

	// NebulaBind is the address nebula listens on for every instance.
	NebulaBind string

	// PublicEndpoint is the host connectors should dial, without a port. The
	// port is per instance.
	PublicEndpoint string

	// PortRange is the range of UDP ports instances are allocated from.
	PortMin, PortMax uint16

	// Overlays are the address spaces instances are carved out of, in the
	// order they are used: when one has no room left, the next is tried.
	// Tenants do not choose their own prefix, because two of them would
	// eventually choose the same one.
	//
	// Overlays6 is the same for IPv6. A hub with none hands out IPv4 only, and
	// no member of any of its instances can carry an IPv6 route.
	Overlays  []Pool
	Overlays6 []Pool

	// Token is what a bootstrap signature proves knowledge of. It is known to
	// every operator who may create an instance and is never transmitted.
	Token string

	// Binders authorizes instance creation: who may take address space here.
	Binders Binders

	// StatePath is the JSON state file.
	StatePath string

	// MTU of the hub's own link, passed to connectors so they can pick the
	// lower of the two.
	MTU uint32

	// Relay enables relaying on every instance's lighthouse.
	Relay bool

	Logger *slog.Logger
}

// Hub is the running daemon.
type Hub struct {
	cfg   Config
	store *Store
	lhs   *lighthouses
	log   *slog.Logger

	limiterOnce sync.Once
	rl          *rateLimiter

	nonceOnce  sync.Once
	nonceStore *wrak.MemoryNonces
}

// New opens the state and starts a lighthouse for every instance that already
// has a certificate.
func New(cfg Config) (*Hub, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PortMin == 0 || cfg.PortMax == 0 || cfg.PortMin > cfg.PortMax {
		return nil, fmt.Errorf("invalid port range %d-%d", cfg.PortMin, cfg.PortMax)
	}
	if len(cfg.Overlays) == 0 {
		return nil, fmt.Errorf("an overlay pool is required")
	}
	store, err := OpenStore(cfg.StatePath)
	if err != nil {
		return nil, err
	}

	h := &Hub{cfg: cfg, store: store, lhs: newLighthouses(), log: cfg.Logger}

	for _, inst := range store.List() {
		if inst.LighthouseCert == "" {
			continue
		}
		if err := h.lhs.start(inst, cfg.NebulaBind, h.log); err != nil {
			h.log.Error("could not start a lighthouse", "instance", inst.Name, "error", err)
		}
	}

	return h, nil
}

// Close stops every lighthouse.
func (h *Hub) Close() { h.lhs.stopAll() }

// CreateInstance allocates a port, reserves the lighthouse address and
// generates its keypair. The certificate has to come back from the tenant,
// because only the tenant can sign.
func (h *Hub) CreateInstance(binder, owner, name, sharedToken string) (*Instance, error) {
	overlay, err := allocateOverlay(h.cfg.Overlays, h.store.UsedOverlays())
	if err != nil {
		return nil, err
	}

	port, err := h.freePort()
	if err != nil {
		return nil, err
	}

	lighthouseAddr, err := reserveLighthouse(overlay)
	if err != nil {
		return nil, err
	}

	tenantAddr, err := lowestFree(overlay, map[netip.Addr]struct{}{lighthouseAddr: {}})
	if err != nil {
		return nil, err
	}

	// The IPv6 side is a pool of its own, walked the same way and exhausted
	// separately.
	var overlay6 netip.Prefix
	var lighthouseAddr6, tenantAddr6 netip.Addr
	if len(h.cfg.Overlays6) > 0 {
		overlay6, err = allocateOverlay(h.cfg.Overlays6, h.store.UsedOverlays6())
		if err != nil {
			return nil, err
		}
		if lighthouseAddr6, err = reserveLighthouse(overlay6); err != nil {
			return nil, err
		}
		tenantAddr6, err = lowestFree(overlay6, map[netip.Addr]struct{}{lighthouseAddr6: {}})
		if err != nil {
			return nil, err
		}
	}

	pubPEM, keyPEM, err := ca.GenerateHostKey()
	if err != nil {
		return nil, err
	}

	inst := &Instance{
		ID:                  newID(),
		Name:                name,
		Binder:              binder,
		Owner:               owner,
		Overlay:             overlay,
		Overlay6:            overlay6,
		Port:                port,
		LighthouseAddress:   lighthouseAddr,
		LighthouseAddress6:  lighthouseAddr6,
		TenantAddress:       tenantAddr,
		TenantAddress6:      tenantAddr6,
		LighthousePublicKey: string(pubPEM),
		LighthouseKey:       string(keyPEM),
		Relay:               h.cfg.Relay,
		SharedToken:         sharedToken,
		Allocations:         map[string]netip.Addr{},
		Allocations6:        map[string]netip.Addr{},
		Requests:            map[string]*Record{},
		Members:             map[string]*Member{},
		CreatedAt:           time.Now().UTC(),
	}

	// The owner belongs to its own instance from the moment it exists, at the
	// address reserved for it. Without this it shows up in a listing as a
	// member with no address, which is exactly as useful as it sounds.
	inst.Members[owner] = &Member{
		Kind:     KindOwner,
		Name:     name,
		Identity: owner,
		Binder:   binder,
		Address:  netip.PrefixFrom(tenantAddr, overlay.Bits()),
		Address6: prefixOf(tenantAddr6, overlay6),
		JoinedAt: time.Now().UTC(),
	}

	if err := h.store.Add(inst); err != nil {
		return nil, err
	}

	h.log.Info("instance created",
		"instance", inst.Name,
		"overlay", inst.Overlay,
		"overlay6", inst.Overlay6,
		"port", inst.Port,
		"lighthouse", inst.LighthouseAddress,
		"tenant", inst.TenantAddress,
	)

	return inst, nil
}

// ActivateInstance stores the lighthouse certificate signed by the tenant and
// brings nebula up.
func (h *Hub) ActivateInstance(id, caCert, lighthouseCert string) error {
	err := h.store.Update(id, func(inst *Instance) error {
		if strings.TrimSpace(caCert) == "" || strings.TrimSpace(lighthouseCert) == "" {
			return fmt.Errorf("both the authority and the lighthouse certificate are required")
		}
		inst.CACert = caCert
		inst.LighthouseCert = lighthouseCert
		return nil
	})
	if err != nil {
		return err
	}

	inst, err := h.store.Get(id)
	if err != nil {
		return err
	}

	h.lhs.stop(id)
	return h.lhs.start(inst, h.cfg.NebulaBind, h.log)
}

// Applicant describes who is asking to be let in.
type Applicant struct {
	// Kind is connector or tenant.
	Kind string

	// Identity and Binder are set for a tenant, which arrives through a
	// registration. A connector has neither.
	Identity string
	Binder   string

	// MAC authenticates a connector's payload under the shared token.
	MAC string

	SourceAddr string
}

// Enroll stores a request and allocates its address. The instance may be named
// by its id or by its name.
func (h *Hub) Enroll(ref string, req enroll.Request, who Applicant) (*Record, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	// A connector's name becomes a certificate's name and the name space it
	// answers under, so it has to be usable as one. A name that is not is
	// dropped rather than refused: a name is a convenience, and turning
	// somebody away over one would be refusing a machine because of how its
	// operator spells. It is kept as a hint, so the owner sees what was meant
	// and can approve it under a name of their own.
	//
	// A tenant's is left alone: it arrives as the machine name from its
	// registration, which is user@host and was never going to be a label.
	if who.Kind == KindConnector && req.Name != "" {
		name, err := ParseMemberName(req.Name)
		if err != nil {
			if req.Hints == nil {
				req.Hints = map[string]string{}
			}
			req.Hints["asked to be called"] = req.Name
			req.Name = ""
		} else {
			req.Name = name
		}
	}

	if who.Kind == KindTenant && who.Identity != "" {
		// An owner already belongs to its own instance. Letting it enroll
		// would give it a second address and a decision to make about itself,
		// and there is no question there to answer.
		if inst, err := h.store.Resolve(ref); err == nil && inst.Owner == who.Identity {
			return nil, fmt.Errorf("this machine owns %s and is already in it", inst.Name)
		}
	}

	if who.Kind == KindTenant && len(req.Routes) > 0 {
		// A tenant consumes routes, it does not offer them, and letting one
		// claim a prefix would quietly turn it into a connector.
		return nil, fmt.Errorf("a tenant does not announce routes")
	}

	target, err := h.store.Resolve(ref)
	if err != nil {
		return nil, err
	}
	id := target.ID

	fingerprint := fingerprintOf(req.PublicKey)

	var record *Record
	err = h.store.Update(id, func(inst *Instance) error {
		if who.Kind == KindConnector && inst.SharedToken != "" && !req.VerifyMAC(inst.SharedToken, who.MAC) {
			return fmt.Errorf("bad or missing request authentication")
		}

		// A connector that re-enrolls with the same key keeps its record, so a
		// restart does not fill the panel with duplicates.
		for _, existing := range inst.Requests {
			if existing.Fingerprint == fingerprint {
				existing.Request = req
				existing.SourceAddr = who.SourceAddr
				if existing.Status == enroll.StatusRejected {
					// A restart is how an operator retries after a mistake.
					existing.Status = enroll.StatusPending
					existing.Reason = ""
					existing.DecidedAt = time.Time{}
				}
				record = existing
				return nil
			}
		}

		// Both are tried, and running out of one is not running out of the
		// other: a connector carrying nothing but IPv6 is admitted into an
		// instance whose IPv4 pool is full, and it works, because what it
		// carries never needed the address it could not have.
		addr, err4 := allocate(inst, fingerprint, who.Kind)
		addr6, err6 := allocate6(inst, fingerprint, who.Kind)

		if !addr.IsValid() && !addr6.IsValid() {
			if err4 != nil {
				return err4
			}
			return err6
		}

		record = &Record{
			Record: enroll.Record{
				ID:              newID(),
				Status:          enroll.StatusPending,
				Request:         req,
				Fingerprint:     fingerprint,
				OverlayAddress:  netip.PrefixFrom(addr, inst.Overlay.Bits()),
				OverlayAddress6: prefixOf(addr6, inst.Overlay6),
				SourceAddr:      who.SourceAddr,
				ReceivedAt:      time.Now().UTC(),
			},
			Kind:     who.Kind,
			Identity: who.Identity,
			Binder:   who.Binder,
		}
		inst.Requests[record.ID] = record

		return nil
	})
	if err != nil {
		return nil, err
	}

	return record, nil
}

// Result reports what a connector should do next. The instance is named the
// same way it was for the enrollment, by id or by name.
func (h *Hub) Result(ref, requestID string) (*enroll.Result, error) {
	inst, err := h.store.Resolve(ref)
	if err != nil {
		return nil, err
	}

	record, ok := inst.Requests[requestID]
	if !ok {
		return nil, ErrNotFound
	}

	res := &enroll.Result{Status: record.Status, Reason: record.Reason}
	switch record.Status {
	case enroll.StatusApproved:
		res.Bundle = record.Bundle
	default:
		res.RetryAfter = 30
	}

	return res, nil
}

// Pending returns the requests waiting for a decision.
func (h *Hub) Pending(instanceID string) ([]*Record, error) {
	inst, err := h.store.Get(instanceID)
	if err != nil {
		return nil, err
	}

	out := make([]*Record, 0, len(inst.Requests))
	for _, r := range inst.Requests {
		if r.Status == enroll.StatusPending {
			out = append(out, r)
		}
	}
	return out, nil
}

// Decide records what the tenant decided.
func (h *Hub) Decide(instanceID, requestID string, d enroll.Decision) error {
	return h.store.Update(instanceID, func(inst *Instance) error {
		record, ok := inst.Requests[requestID]
		if !ok {
			return ErrNotFound
		}

		switch d.Status {
		case enroll.StatusApproved:
			if d.Bundle == nil || d.Bundle.Certificate == "" {
				return fmt.Errorf("an approval needs a certificate")
			}
			bundle := *d.Bundle
			bundle.OverlayAddress = record.OverlayAddress
			bundle.OverlayAddress6 = record.OverlayAddress6
			bundle.Lighthouse = enroll.Lighthouse{
				OverlayAddress:  inst.LighthouseAddress,
				OverlayAddress6: inst.LighthouseAddress6,
				Endpoints:       []string{net.JoinHostPort(h.cfg.PublicEndpoint, strconv.Itoa(int(inst.Port)))},
				Relay:           inst.Relay,
			}
			if bundle.MTU == 0 {
				bundle.MTU = h.cfg.MTU
			}
			if bundle.Instance == "" {
				bundle.Instance = inst.Name
			}
			bundle.Blocked = blockedIn(inst)
			record.Bundle = &bundle
			record.Status = enroll.StatusApproved

			if inst.Members == nil {
				inst.Members = map[string]*Member{}
			}
			// The name the certificate was issued to, which is what anybody
			// will see and type, rather than the empty string an applicant
			// may have asked with.
			name := d.Name
			if name == "" {
				name = record.Request.Name
			}

			// One name, one member. A name is the name space this member
			// answers under, so two of them would collide exactly where names
			// were meant to stop things colliding - and a re-enrolment of the
			// same key is not another member, it is this one again.
			for fp, m := range inst.Members {
				if fp != record.Fingerprint && m.Name == name && name != "" {
					// The usual reason is this one: a connector redeployed
					// with a fresh volume is a new key and a new member, and
					// the one it replaces is still here under the name it
					// will never use again.
					return fmt.Errorf("a %s is already called %s: remove it first with robinet member remove %s, or approve this one with --name",
						m.Kind, name, name)
				}
			}

			inst.Members[record.Fingerprint] = &Member{
				Kind:            record.Kind,
				Name:            name,
				Fingerprint:     record.Fingerprint,
				Identity:        record.Identity,
				Binder:          record.Binder,
				Address:         record.OverlayAddress,
				Address6:        record.OverlayAddress6,
				Routes:          d.Routes,
				Domains:         d.Domains,
				CertFingerprint: d.CertFingerprint,
				JoinedAt:        time.Now().UTC(),
			}

		case enroll.StatusRejected:
			record.Status = enroll.StatusRejected
			record.Bundle = nil
			record.Reason = d.Reason

		default:
			return fmt.Errorf("unknown decision %q", d.Status)
		}

		record.DecidedAt = time.Now().UTC()
		return nil
	})
}

// Forget drops a record. The connector may keep trying; the operator stops
// seeing it until it enrolls with a different key.
func (h *Hub) Forget(instanceID, requestID string) error {
	return h.store.Update(instanceID, func(inst *Instance) error {
		if _, ok := inst.Requests[requestID]; !ok {
			return ErrNotFound
		}
		delete(inst.Requests, requestID)
		return nil
	})
}

// freePort picks the lowest unused port in the configured range.
func (h *Hub) freePort() (uint16, error) {
	used := h.store.UsedPorts()

	for p := h.cfg.PortMin; p <= h.cfg.PortMax; p++ {
		if _, taken := used[p]; !taken {
			return p, nil
		}
		if p == h.cfg.PortMax {
			break
		}
	}

	return 0, fmt.Errorf("no free port in %d-%d", h.cfg.PortMin, h.cfg.PortMax)
}

// fingerprintOf identifies a connector by its public key. This is what reject,
// forget and ban are keyed on.
func fingerprintOf(publicKeyPEM string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(publicKeyPEM), " ")))
	return hex.EncodeToString(sum[:])
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RouteTableOf renders what a member needs to reach everything this instance
// carries.
func (h *Hub) RouteTableOf(inst *Instance) RouteTable {
	return RouteTable{
		Instance:  inst.Name,
		Resolvers: resolversOf(inst),
		Blocked:   blockedIn(inst),
		Overlay:   inst.Overlay,
		Lighthouse: enroll.Lighthouse{
			OverlayAddress: inst.LighthouseAddress,
			Endpoints:      []string{net.JoinHostPort(h.cfg.PublicEndpoint, strconv.Itoa(int(inst.Port)))},
			Relay:          inst.Relay,
		},
		Routes: routesOf(inst),
		MTU:    h.cfg.MTU,
	}
}

// Routes returns the table for an instance by id.
func (h *Hub) Routes(id string) (RouteTable, error) {
	inst, err := h.store.Get(id)
	if err != nil {
		return RouteTable{}, err
	}
	return h.RouteTableOf(inst), nil
}

// routesOf collects what the admitted connectors carry. A banned one carries
// nothing, which is how a ban takes traffic away as well as access.
func routesOf(inst *Instance) []Route {
	var out []Route

	for _, m := range inst.Members {
		if m.Kind != KindConnector || m.Banned {
			continue
		}
		for _, prefix := range m.Routes {
			out = append(out, Route{
				Prefix:    prefix,
				Via:       m.Address.Addr(),
				Connector: m.Name,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Prefix.String() < out[j].Prefix.String()
	})

	return out
}

// resolversOf renders which member answers for which names.
func resolversOf(inst *Instance) []Resolver {
	var out []Resolver

	for _, m := range inst.Members {
		if m.Kind != KindConnector || m.Banned {
			continue
		}
		for _, domain := range m.Domains {
			r := Resolver{
				Domain:    domain,
				Via:       m.Address.Addr(),
				Connector: m.Name,
			}
			if m.Address6.IsValid() {
				r.Via6 = m.Address6.Addr()
			}
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })

	return out
}

// Members counts who is inside, which is what a deletion has to be able to
// report before it happens.
func (inst *Instance) MemberCount() int {
	n := 0
	for _, m := range inst.Members {
		if m.Kind != KindOwner && !m.Banned {
			n++
		}
	}
	return n
}

// Delete removes an instance: its lighthouse stops, its addresses and its port
// go back to the pool, and every certificate issued under it becomes useless.
//
// Nothing is revoked, because nothing can be: the authority is the owner's and
// the hub never had it. What ends is the lighthouse, so members cannot find
// each other, and the route table, so nobody knows where to send anything.
func (h *Hub) Delete(instanceID string) error {
	inst, err := h.store.Get(instanceID)
	if err != nil {
		return err
	}

	h.lhs.stop(inst.ID)

	if err := h.store.Remove(inst.ID); err != nil {
		return err
	}

	h.log.Info("instance deleted",
		"instance", inst.Name,
		"overlay", inst.Overlay,
		"port", inst.Port,
		"members", inst.MemberCount(),
	)

	return nil
}

// blockedIn lists the certificates a ban has to make useless.
//
// A certificate cannot be revoked - it was signed once by an authority the hub
// never had, and nothing checks back with anybody. What can be done is telling
// every member to refuse it, which is what nebula's blocklist is for, and the
// route table is already the thing everybody reads.
func blockedIn(inst *Instance) []string {
	var out []string

	for _, m := range inst.Members {
		if m.Banned && m.CertFingerprint != "" {
			out = append(out, m.CertFingerprint)
		}
	}

	sort.Strings(out)

	return out
}

// Ban blocklists a member and takes its routes out of the table.
func (h *Hub) Ban(instanceID, fingerprint string) error {
	err := h.store.Update(instanceID, func(inst *Instance) error {
		for fp, m := range inst.Members {
			if fp == fingerprint || strings.HasPrefix(fp, fingerprint) || m.Name == fingerprint {
				m.Banned = true
				return nil
			}
		}
		return fmt.Errorf("no such member: %s", fingerprint)
	})
	if err != nil {
		return err
	}

	// The lighthouse holds the blocklist in its own configuration, so it has to
	// be rebuilt before it will stop telling a banned member where anybody is.
	inst, err := h.store.Get(instanceID)
	if err != nil {
		return err
	}
	if h.lhs.isRunning(inst.ID) {
		h.lhs.stop(inst.ID)
		if err := h.lhs.start(inst, h.cfg.NebulaBind, h.log); err != nil {
			return fmt.Errorf("banned, but the lighthouse did not come back: %w", err)
		}
	}

	return nil
}

// RemoveMember forgets a member: its record, its address and the request it
// arrived with.
//
// Not the same as a ban. A ban keeps the member precisely so its certificate
// stays on everybody's blocklist, and forgetting one would quietly let it back
// in. This is for a member that is gone - its key deleted with the container
// that held it - and it frees the address for whatever comes next.
func (h *Hub) RemoveMember(instanceID, ref string) (*Member, error) {
	var removed *Member

	err := h.store.Update(instanceID, func(inst *Instance) error {
		for fp, m := range inst.Members {
			if fp != ref && !strings.HasPrefix(fp, ref) && m.Name != ref {
				continue
			}

			if m.Kind == KindOwner {
				return fmt.Errorf("%s owns this instance and cannot be removed from it", m.Name)
			}
			if m.Banned {
				return fmt.Errorf("%s is banned, and forgetting it would take its certificate off every blocklist", m.Name)
			}

			removed = m
			delete(inst.Members, fp)
			delete(inst.Allocations, fp)
			delete(inst.Allocations6, fp)

			// The request it arrived with goes too, or it would sit in the
			// listing as something already decided about a member that is no
			// longer here.
			for id, record := range inst.Requests {
				if record.Fingerprint == fp {
					delete(inst.Requests, id)
				}
			}

			return nil
		}

		return fmt.Errorf("no member %s", ref)
	})
	if err != nil {
		return nil, err
	}

	h.log.Info("member removed", "instance", instanceID, "name", removed.Name, "address", removed.Address)

	return removed, nil
}

// Members returns everyone admitted to an instance.
func (h *Hub) Members(id string) ([]*Member, error) {
	inst, err := h.store.Get(id)
	if err != nil {
		return nil, err
	}

	out := make([]*Member, 0, len(inst.Members))
	for _, m := range inst.Members {
		copied := *m
		out = append(out, &copied)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// prefixOf is the address written as a prefix of the instance's size, or
// nothing at all when there is no address. An instance on a hub with no IPv6
// pool has none, and every field downstream stays invalid rather than zero.
func prefixOf(addr netip.Addr, overlay netip.Prefix) netip.Prefix {
	if !addr.IsValid() || !overlay.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, overlay.Bits())
}
