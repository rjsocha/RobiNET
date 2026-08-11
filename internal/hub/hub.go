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

	// DNS makes each lighthouse answer for its instance's members, by their
	// certificate names, on its own overlay address.
	DNS bool

	// NoLighthouseTun runs the lighthouses without a device, which costs them
	// their DNS as well: nothing addressed to the lighthouse arrives without
	// one.
	//
	// Not a deployment choice. Creating a tun needs CAP_NET_ADMIN, and the
	// tests start a hub in process as whoever ran them; without this they
	// would pass for root only. Nothing reads it from a configuration file.
	NoLighthouseTun bool

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

	h := &Hub{cfg: cfg, store: store, lhs: newLighthouses(cfg.DNS, cfg.NoLighthouseTun), log: cfg.Logger}

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

		// A removed member asking again. Refused here rather than put in front
		// of the owner, because the decision was already taken and the owner
		// approving it by reflex is exactly what removal exists to prevent.
		if inst.burned(fingerprint) {
			return fmt.Errorf("this key was removed from %s and will not be admitted again", inst.Name)
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
		res.Bundle = withBlocklist(record.Bundle, inst)
	default:
		res.RetryAfter = 30
	}

	return res, nil
}

// withBlocklist answers with the refusals as they stand now rather than as
// they stood when the bundle was signed.
//
// This endpoint is the only thing a running connector comes back to, so it is
// the only way a ban reaches the node carrying the network somebody was banned
// from. The bundle it was approved with is left alone: everything else in
// there was decided once, and the blocklist is the one part that is not.
func withBlocklist(bundle *enroll.Bundle, inst *Instance) *enroll.Bundle {
	if bundle == nil {
		return nil
	}

	fresh := *bundle
	fresh.Blocked = blockedIn(inst)
	return &fresh
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
					return fmt.Errorf("a %s is already called %s: retire it first with robinet member ban %s and robinet member remove %s, or approve this one with --name",
						m.Kind, name, name, name)
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
				Domain:          d.Domain,
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
		if m.Kind != KindConnector || m.Banned() {
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
		if m.Kind != KindConnector || m.Banned() {
			continue
		}
		if m.Domain == "" {
			continue
		}

		r := Resolver{
			Domain:    m.Domain,
			Via:       m.Address.Addr(),
			Connector: m.Name,
		}
		if m.Address6.IsValid() {
			r.Via6 = m.Address6.Addr()
		}
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })

	return out
}

// Members counts who is inside, which is what a deletion has to be able to
// report before it happens.
func (inst *Instance) MemberCount() int {
	n := 0
	for _, m := range inst.Members {
		if m.Kind != KindOwner && !m.Banned() {
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
		if m.Banned() && m.CertFingerprint != "" {
			out = append(out, m.CertFingerprint)
		}
	}

	// A removed member has no record left to carry its ban, and its certificate
	// is exactly as valid as it was the moment before.
	for _, b := range inst.Burned {
		if b.CertFingerprint != "" {
			out = append(out, b.CertFingerprint)
		}
	}

	sort.Strings(out)

	return out
}

// burned reports whether a nebula key has been removed from this instance.
func (inst *Instance) burned(fingerprint string) bool {
	for _, b := range inst.Burned {
		if b.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// memberIn resolves a member by name, by fingerprint, or by the first
// characters of one.
func memberIn(inst *Instance, ref string) (string, *Member, error) {
	for fp, m := range inst.Members {
		if fp == ref || strings.HasPrefix(fp, ref) || m.Name == ref {
			return fp, m, nil
		}
	}
	return "", nil, fmt.Errorf("no member %s: %w", ref, ErrNotFound)
}

// Ban blocklists a member and takes its routes out of the table. The member
// stays: it is kept out, not forgotten, and unbanning it lets it back in.
func (h *Hub) Ban(instanceID, ref, note string) error {
	err := h.store.Update(instanceID, func(inst *Instance) error {
		_, m, err := memberIn(inst, ref)
		if err != nil {
			return err
		}
		if m.Banned() {
			return fmt.Errorf("%s is already banned", m.Name)
		}

		m.Events = append(m.Events, MemberEvent{Kind: EventBan, Note: note, At: time.Now().UTC()})
		return nil
	})
	if err != nil {
		return err
	}

	return h.applyBlocklist(instanceID)
}

// Unban lets a banned member back in. Its certificate was never revoked and
// never could be, so nothing has to be reissued for it to work again.
func (h *Hub) Unban(instanceID, ref, note string) error {
	err := h.store.Update(instanceID, func(inst *Instance) error {
		_, m, err := memberIn(inst, ref)
		if err != nil {
			return err
		}
		if !m.Banned() {
			return fmt.Errorf("%s is not banned", m.Name)
		}

		m.Events = append(m.Events, MemberEvent{Kind: EventUnban, Note: note, At: time.Now().UTC()})
		return nil
	})
	if err != nil {
		return err
	}

	return h.applyBlocklist(instanceID)
}

// applyBlocklist tells a running lighthouse what it must now refuse.
//
// The lighthouse holds the blocklist in its own configuration, so the change
// has to reach it before it will stop telling a banned member where anybody
// is. Reloaded rather than restarted: nebula reloads pki in place, which is
// what a SIGHUP does to it and what the connector already does with the same
// list.
//
// The decision is recorded either way. A reload that fails leaves the hub
// knowing about the ban and one lighthouse not yet enforcing it, which the
// next start of the hub settles; the error says so rather than suggesting the
// ban did not happen.
func (h *Hub) applyBlocklist(instanceID string) error {
	inst, err := h.store.Get(instanceID)
	if err != nil {
		return err
	}

	if err := h.lhs.reload(inst, h.cfg.NebulaBind, h.log); err != nil {
		return fmt.Errorf("recorded, but the lighthouse did not take the new blocklist: %w", err)
	}

	return nil
}

// RemoveMember forgets a member: its record, its history, its address and the
// request it arrived with. Its credentials are burned on the way out.
//
// This is the end of the line and it only follows a ban. Removing a member that
// is not banned would free its address while it still holds a valid certificate
// for the old one, and the next member to be admitted would be handed an
// address something is already using. The certificate cannot be revoked, so the
// only way out is to burn it first and then forget the rest.
func (h *Hub) RemoveMember(instanceID, ref string) (*Member, error) {
	var removed *Member

	err := h.store.Update(instanceID, func(inst *Instance) error {
		fp, m, err := memberIn(inst, ref)
		if err != nil {
			return err
		}

		if m.Kind == KindOwner {
			return fmt.Errorf("%s owns this instance and cannot be removed from it", m.Name)
		}
		if !m.Banned() {
			return fmt.Errorf("%s is not banned: ban it first, or its certificate would still be good for the address this frees", m.Name)
		}

		// Both the key and the certificate. The certificate goes onto every
		// blocklist, and the key stops the same machine enrolling again for a
		// fresh one, which is what "removed" is meant to mean.
		inst.Burned = append(inst.Burned, Burned{
			Fingerprint:     fp,
			CertFingerprint: m.CertFingerprint,
		})

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
	})
	if err != nil {
		return nil, err
	}

	// No lighthouse restart: the certificate was on the blocklist as a banned
	// member's and is on it now as a burned one, so the configuration it would
	// be rebuilt from is the same configuration.

	h.log.Info("member removed", "instance", instanceID, "name", removed.Name, "address", removed.Address)

	return removed, nil
}

// SetSharedToken replaces the secret a connector's enrollment is authenticated
// with.
//
// Only enrollments are authenticated with it, and only the ones that have not
// happened yet: an admitted member holds a certificate and never presents the
// token again. So this locks out every connector configuration handed out so
// far without touching anything currently running.
func (h *Hub) SetSharedToken(instanceID, token string) error {
	if token == "" {
		return fmt.Errorf("a shared token is required")
	}

	return h.store.Update(instanceID, func(inst *Instance) error {
		inst.SharedToken = token
		return nil
	})
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
