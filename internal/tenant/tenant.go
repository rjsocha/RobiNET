package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/wrak"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ssh"
)

// JoinOptions describes registering this machine with a hub.
type JoinOptions struct {
	HubURL string

	// Token is the secret both sides already know. It goes into the signed
	// bootstrap message and never on the wire. Who is asking follows from the
	// ssh key that signs.
	Token string

	// Name is what this machine calls itself, shown to whoever decides.
	Name string

	// SSHKeyPath signs with a private key from disk instead of the agent.
	SSHKeyPath string

	// SSHFingerprint picks one key out of the agent, as SHA256:...
	SSHFingerprint string

	// Signer overrides both, for tests and callers that already have one.
	Signer ssh.Signer

	Insecure bool

	// Pin is the hash of the hub's public key, when whoever handed this over
	// knows it. Stronger than Insecure and stronger than a certificate
	// authority: it names one key rather than trusting anybody an authority
	// would vouch for.
	Pin string
}

// Join registers this machine with a hub. Once, per machine.
//
// The ssh key vouches for it exactly here; afterwards the machine has an
// identity of its own and signs with that, so the agent is never needed again.
// Joined is what the command needs to say out loud afterwards.
type Joined struct {
	Hub    string
	Name   string
	Binder string

	// Refreshed is a registration this machine already had, which is what
	// re-running join looks like once a hub has forgotten this machine.
	Refreshed bool
}

func Join(ctx context.Context, state *State, opts JoinOptions, log *slog.Logger) (Joined, error) {
	if opts.Name == "" || opts.Name == DefaultNameMarker && knownName(state) == "" {
		return Joined{}, fmt.Errorf("a name is required, it is what the owner of an instance will see")
	}

	var (
		knownHub  string
		existing  string
		known     string
		refreshed bool
	)
	state.Read(func(d *data) {
		knownHub, existing, known = d.HubURL, d.Identity, d.Name
	})

	hubURL := strings.TrimRight(opts.HubURL, "/")

	// One hub per machine, so a different one means starting over rather than
	// quietly abandoning the instances this machine owns.
	if knownHub != "" && knownHub != hubURL {
		return Joined{}, fmt.Errorf("this machine is registered with %s: robinet setup --cleanup --force to start over", knownHub)
	}

	// Registering again with the same identity is how a machine recovers when
	// the hub has forgotten it, which happens when its state is rebuilt. The
	// alternative would be deleting this machine's authorities to fix a
	// problem on the other side.
	identity, err := wrak.NewIdentity()
	if err != nil {
		return Joined{}, err
	}
	if existing != "" {
		identity, err = wrak.ParseIdentity(existing)
		if err != nil {
			return Joined{}, err
		}
		if opts.Name == DefaultNameMarker && known != "" {
			opts.Name = known
		}
		log.Debug("already registered here, refreshing", "hub", hubURL, "name", opts.Name)
		refreshed = true
	}

	registered, err := register(ctx, opts, identity)
	if err != nil {
		return Joined{}, err
	}

	owner, uid, gid, err := ownerIdentity()
	if err != nil {
		return Joined{}, err
	}

	err = state.Write(func(d *data) error {
		d.HubURL = hubURL
		d.Identity = identity.Private()
		d.Binder = registered.Binder
		d.Name = opts.Name
		d.Insecure = opts.Insecure
		d.Pin = opts.Pin
		d.Owner, d.OwnerUID, d.OwnerGID = owner, uid, gid
		return nil
	})
	if err != nil {
		return Joined{}, err
	}

	// Debug, not info: joining is something a person does once, by hand, and
	// what they need to read is printed as a sentence by the command itself.
	// A structured line saying the same thing first only makes the sentence
	// harder to find.
	log.Debug("registered with the hub",
		"hub", opts.HubURL,
		"binder", registered.Binder,
		"name", opts.Name,
		"signed_by", registered.SignedBy,
	)

	return Joined{
		Hub:       hubURL,
		Name:      opts.Name,
		Binder:    registered.Binder,
		Refreshed: refreshed,
	}, nil
}

// defaultNameMarker lets the command line say "the user did not choose a
// name", so a re-registration keeps the one already known instead of replacing
// it with whatever this host is called today.
// DefaultNameMarker is what the command line passes when no name was given.
const DefaultNameMarker = "\x00default"

// knownName is what this machine called itself last time.
func knownName(state *State) string {
	var name string
	state.Read(func(d *data) { name = d.Name })
	return name
}

// Daemon runs the connections and serves the local control socket.
type Daemon struct {
	// routers answer DNS for the names each instance carries, one per
	// connection, on that connection's own overlay address.
	routers struct {
		mu      sync.Mutex
		running map[string]*router
	}

	state *State
	hub   *hubClient
	log   *slog.Logger
	run   *runners
}

// NewDaemon prepares a daemon from registered state.
func NewDaemon(state *State, log *slog.Logger) (*Daemon, error) {
	if !state.Registered() {
		return nil, fmt.Errorf("this machine is not registered with a hub, run robinet join first")
	}

	var (
		client *hubClient
		err    error
	)
	state.Read(func(d *data) {
		client, err = newHubClient(d.HubURL, d.Identity, d.Insecure, d.Pin)
	})
	if err != nil {
		return nil, err
	}

	d := &Daemon{state: state, hub: client, log: log, run: newRunners()}
	d.routers.running = map[string]*router{}

	return d, nil
}

// Stop shuts every connection down.
func (d *Daemon) Stop() {
	d.routers.mu.Lock()
	for id, r := range d.routers.running {
		r.conn.Close()
		delete(d.routers.running, id)
	}
	d.routers.mu.Unlock()

	d.run.stopAll()
}

// Refresh brings the world in line with the hub: collects certificates that
// have been granted, and reloads routes that have changed.
//
// This is the whole reason the route table lives on the hub. A connector
// admitted a minute ago shows up here without anybody reissuing anything.
func (d *Daemon) Refresh(ctx context.Context) {
	for _, conn := range d.state.Connections() {
		if !conn.Ready() {
			if err := d.collect(ctx, conn); err != nil {
				d.log.Debug("still waiting to be let in", "instance", conn.Name, "error", err)
			}
			continue
		}

		table, err := d.hub.routes(ctx, conn.InstanceID)
		if err != nil {
			d.log.Warn("could not read the route table", "instance", conn.Name, "error", err)
			continue
		}

		// The names an instance carries change when a connector is admitted,
		// so this follows the table rather than the startup.
		if err := d.startRouter(conn, table); err != nil {
			d.log.Warn("could not answer dns", "instance", conn.Name, "error", err)
		}

		if !d.run.isRunning(conn.InstanceID) {
			if err := d.startConnection(conn, table); err != nil {
				d.log.Error("could not connect", "instance", conn.Name, "error", err)
			}
			continue
		}

		if err := d.run.reload(conn, table, d.state.choices()); err != nil {
			d.log.Warn("could not apply the route table", "instance", conn.Name, "error", err)
		}
	}
}

// startConnection refuses to install a route another connection already holds.
func (d *Daemon) startConnection(conn *Connection, table *hub.RouteTable) error {
	held := map[string][]netip.Prefix{}
	for _, other := range d.state.Connections() {
		if other.InstanceID == conn.InstanceID || !d.run.isRunning(other.InstanceID) {
			continue
		}
		otherTable, err := d.hub.routes(context.Background(), other.InstanceID)
		if err != nil {
			continue
		}
		for _, r := range otherTable.Routes {
			held[other.Name] = append(held[other.Name], r.Prefix)
		}
	}

	var wanted []netip.Prefix
	for _, r := range table.Routes {
		wanted = append(wanted, r.Prefix)
	}

	if other, prefix, clash := collides(held, conn.Name, wanted); clash {
		return fmt.Errorf("%s is already carried by the connection to %s, one route table cannot hold both", prefix, other)
	}

	return d.run.start(conn, table, d.state.choices(), d.log)
}

// collect asks whether a pending join has been granted.
func (d *Daemon) collect(ctx context.Context, conn *Connection) error {
	res, err := d.hub.joinResult(ctx, conn.InstanceID)
	if err != nil {
		return err
	}

	switch res.Status {
	case enroll.StatusApproved:
		if res.Bundle == nil {
			return fmt.Errorf("approved without a certificate")
		}
	case enroll.StatusRejected:
		return fmt.Errorf("refused: %s", res.Reason)
	default:
		return fmt.Errorf("still pending")
	}

	bundle := res.Bundle
	err = d.state.Write(func(s *data) error {
		stored, ok := s.Connections[conn.InstanceID]
		if !ok {
			return fmt.Errorf("connection went away")
		}
		stored.Certificate = bundle.Certificate
		stored.CA = bundle.CA
		stored.Address = bundle.OverlayAddress
		stored.Address6 = bundle.OverlayAddress6
		stored.Lighthouse = bundle.Lighthouse
		stored.MTU = bundle.MTU
		stored.JoinedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		return err
	}

	d.log.Info("admitted", "instance", conn.Name, "address", bundle.OverlayAddress)
	return nil
}

// Create makes a new instance owned by this machine, with its own authority.
// Create returns what the hub allocated and the token it was created with,
// which is generated here when nobody supplied one and is otherwise never
// visible again.
func (d *Daemon) Create(ctx context.Context, name, sharedToken string) (*hub.CreateInstanceResponse, string, error) {
	// A shared token is what lets a connector's enrollment be authenticated
	// end to end. Without one the hub could put a public key of its own
	// choosing in front of the owner, so it is generated rather than left to
	// be remembered.
	if sharedToken == "" {
		sharedToken = newSharedToken()
	}

	created, err := d.hub.createInstance(ctx, name, sharedToken)
	if err != nil {
		return nil, "", err
	}

	// What the hub stored, not what was typed: it folds a name to lower case,
	// and two spellings of one name is exactly what that prevents.
	if created.Name != "" {
		name = created.Name
	}

	// The authority is generated for whatever address space the hub handed
	// out, and its key stays here. Both families, because an authority is
	// signed once and constrains everything under it: one that never saw an
	// IPv6 prefix could never sign a member able to carry an IPv6 route, and
	// there is no way back from that short of a new instance.
	overlays := []netip.Prefix{created.Overlay}
	if created.Overlay6.IsValid() {
		overlays = append(overlays, created.Overlay6)
	}

	authority, caPEM, caKeyPEM, err := ca.Generate("robinet-"+name, overlays, 0)
	if err != nil {
		return nil, "", err
	}

	lighthouseCert, err := authority.Sign(ca.Host{
		Name:         hub.LighthouseCertName(name),
		PublicKeyPEM: []byte(created.LighthousePublicKey),
		Networks: addresses(
			netip.PrefixFrom(created.LighthouseAddress, created.Overlay.Bits()),
			prefixOf(created.LighthouseAddress6, created.Overlay6),
		),
	})
	if err != nil {
		return nil, "", fmt.Errorf("could not sign the lighthouse certificate: %w", err)
	}

	if err := d.hub.activate(ctx, created.ID, string(caPEM), string(lighthouseCert)); err != nil {
		return nil, "", fmt.Errorf("could not activate the instance: %w", err)
	}

	// This machine's own place in its own instance.
	pub, key, err := ca.GenerateHostKey()
	if err != nil {
		return nil, "", err
	}

	address := netip.PrefixFrom(created.TenantAddress, created.Overlay.Bits())
	address6 := prefixOf(created.TenantAddress6, created.Overlay6)
	ownCert, err := authority.Sign(ca.Host{
		Name:         hub.MemberCertName(hub.KindTenant, hub.FoldLabel(machineName(d.state)), name),
		PublicKeyPEM: pub,
		Networks:     addresses(address, address6),
	})
	if err != nil {
		return nil, "", err
	}

	err = d.state.Write(func(s *data) error {
		s.Owned[created.ID] = &Owned{
			InstanceID:  created.ID,
			Name:        name,
			CACert:      string(caPEM),
			CAKey:       string(caKeyPEM),
			SharedToken: sharedToken,
		}
		s.Connections[created.ID] = &Connection{
			InstanceID:  created.ID,
			Name:        name,
			Role:        hub.KindOwner,
			PublicKey:   string(pub),
			PrivateKey:  string(key),
			Certificate: string(ownCert),
			CA:          string(caPEM),
			Address:     address,
			Address6:    address6,
			Lighthouse: enroll.Lighthouse{
				OverlayAddress:  created.LighthouseAddress,
				OverlayAddress6: created.LighthouseAddress6,
				Endpoints:       []string{fmt.Sprintf("%s:%d", created.Endpoint, created.Port)},
				Relay:           created.Relay,
			},
			MTU:      created.MTU,
			Device:   s.nextDevice(),
			JoinedAt: time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	d.log.Info("instance created",
		"instance", name,
		"overlay", created.Overlay,
		"address", address,
		"lighthouse", created.LighthouseAddress,
		"enroll_url", fmt.Sprintf("%s/v1/enroll/%s", d.hub.base, created.ID),
	)

	return created, sharedToken, nil
}

// resolveInstance turns whatever was typed into the instance the hub knows,
// by identifier, by name, or by the first characters of an identifier.
func (d *Daemon) resolveInstance(ctx context.Context, wanted string) (*hub.InstanceSummary, error) {
	instances, err := d.hub.instances(ctx)
	if err != nil {
		return nil, err
	}

	folded := strings.ToLower(strings.TrimSpace(wanted))
	for i := range instances {
		inst := &instances[i]
		if inst.ID == wanted || strings.ToLower(inst.Name) == folded || strings.HasPrefix(inst.ID, wanted) {
			return inst, nil
		}
	}

	return nil, fmt.Errorf("no instance %s", wanted)
}

// Show resolves an instance by id or by name and reports what somebody needs
// in order to point a connector at it.
func (d *Daemon) Show(ctx context.Context, wanted string) (map[string]any, error) {
	instances, err := d.hub.instances(ctx)
	if err != nil {
		return nil, err
	}

	folded := strings.ToLower(strings.TrimSpace(wanted))

	for _, inst := range instances {
		if inst.ID != wanted && strings.ToLower(inst.Name) != folded && !strings.HasPrefix(inst.ID, wanted) {
			continue
		}

		owned, isOwner := d.state.Owned(inst.ID)

		info := d.instanceInfo(inst.ID, inst.Name, inst.Overlay.String(), tokenOf(owned))

		if inst.Overlay6.IsValid() {
			info["overlay6"] = inst.Overlay6.String()
		}
		info["name"] = inst.Name
		info["owner"] = inst.Owner
		info["role"] = inst.Role
		info["running"] = inst.Running
		info["owned"] = isOwner

		if !isOwner {
			// The endpoint is the owner's to hand out: it carries their
			// instance and, when they set one, their shared token.
			delete(info, "endpoint")
			delete(info, "url")
		}

		return info, nil
	}

	return nil, fmt.Errorf("no instance %q on this hub", wanted)
}

// ConnectionConfig is the nebula configuration behind one connection.
//
// The bytes the running nebula was loaded from, when there is a running one.
// Because when nebula fails on something it was told, the only other way to
// know what it was told is to reason about the renderer.
//
// A connection can sit in state without running: waiting to be approved, a
// prefix another instance already carries, a hub that was unreachable when it
// was time to start. Those are the moments somebody asks this question, so a
// fresh render stands in rather than a refusal. The first line says which of
// the two arrived, since they answer different questions.
func (d *Daemon) ConnectionConfig(ctx context.Context, ref string, showKeys bool) ([]byte, error) {
	conn, ok := d.connectionFor(ref)
	if !ok {
		return nil, fmt.Errorf("not connected to %s", ref)
	}

	header := "# what nebula is running on, as it was last loaded\n"

	raw, live := d.run.loaded(conn.InstanceID)
	if !live {
		table, err := d.hub.routes(ctx, conn.InstanceID)
		if err != nil {
			return nil, err
		}
		raw, err = renderConfig(conn, table, d.state.choices())
		if err != nil {
			return nil, err
		}
		header = "# nothing is running for this instance: rendered now, from the hub's route table\n"
	}

	if !showKeys {
		var err error
		if raw, err = hub.RedactKey(raw); err != nil {
			return nil, err
		}
	}

	return append([]byte(header), raw...), nil
}

// TokenResult is a replaced shared token and where it has to be pasted.
type TokenResult struct {
	Instance string `json:"instance"`
	Token    string `json:"token"`
	Endpoint string `json:"endpoint"`
}

// SetToken replaces the shared token of an instance this machine owns.
//
// It gates enrollment and nothing else, so every connector already admitted
// keeps working and every connector configuration handed out before this stops
// being usable for a new one.
func (d *Daemon) SetToken(ctx context.Context, ref, token string) (*TokenResult, error) {
	var owned *Owned
	for _, o := range d.owned() {
		if o.InstanceID == ref || strings.EqualFold(o.Name, ref) || strings.HasPrefix(o.InstanceID, ref) {
			owned = o
			break
		}
	}
	if owned == nil {
		return nil, fmt.Errorf("this machine does not own %s", ref)
	}

	if token == "" {
		token = newSharedToken()
	}

	if err := d.hub.setToken(ctx, owned.InstanceID, token); err != nil {
		return nil, err
	}

	// The hub took it, so this machine has to agree: the endpoint it prints for
	// this instance is rendered from here, and one that still carries the old
	// token would be handed out and refused.
	err := d.state.Write(func(s *data) error {
		if stored, ok := s.Owned[owned.InstanceID]; ok {
			stored.SharedToken = token
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	d.log.Info("shared token replaced", "instance", owned.Name)

	hubURL, hubPin := d.hubAddress()

	return &TokenResult{
		Instance: owned.Name,
		Token:    token,
		Endpoint: shorthandEndpoint(hubURL, owned.Name, token, hubPin),
	}, nil
}

func tokenOf(owned *Owned) string {
	if owned == nil {
		return ""
	}
	return owned.SharedToken
}

// List is what this machine can see on the hub.
func (d *Daemon) List(ctx context.Context) ([]hub.InstanceSummary, error) {
	return d.hub.instances(ctx)
}

// connectionFor finds a connection by its identifier or its name.
//
// Locally rather than through the hub: leaving something is the one thing that
// has to work when the hub cannot be reached.
func (d *Daemon) connectionFor(ref string) (*Connection, bool) {
	if conn, ok := d.state.Connection(ref); ok {
		return conn, true
	}

	folded := strings.ToLower(strings.TrimSpace(ref))
	for _, conn := range d.state.Connections() {
		if strings.ToLower(conn.Name) == folded {
			return conn, true
		}
	}

	return nil, false
}

// Connect asks to be let into an instance, or picks up where a previous ask
// left off.
func (d *Daemon) Connect(ctx context.Context, wanted string) error {
	if _, ok := d.connectionFor(wanted); ok {
		// Already asked. Refresh will collect the answer when there is one.
		return nil
	}

	// What the hub calls it, so what is stored here is an identifier and a
	// name rather than whichever of the two was typed.
	target, err := d.resolveInstance(ctx, wanted)
	if err != nil {
		return err
	}
	instanceID, instanceName := target.ID, target.Name

	// An owner is a member of its own instance by construction. Asking to be
	// let in would enroll it as a stranger, give it a second address, and
	// leave it approving itself - so this rejoins with the authority it
	// already holds instead, which is also how it gets back after a detach.
	if owned, isOwner := d.state.Owned(instanceID); isOwner {
		return d.rejoinOwn(ctx, target, owned)
	}

	pub, key, err := ca.GenerateHostKey()
	if err != nil {
		return err
	}

	var name string
	d.state.Read(func(s *data) { name = s.Name })

	err = d.state.Write(func(s *data) error {
		s.Connections[instanceID] = &Connection{
			InstanceID:  instanceID,
			Name:        instanceName,
			Role:        hub.KindTenant,
			PublicKey:   string(pub),
			PrivateKey:  string(key),
			Device:      s.nextDevice(),
			RequestedAt: time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := d.hub.join(ctx, instanceID, name, string(pub)); err != nil {
		return err
	}

	d.log.Info("asked to join", "instance", instanceID, "as", name)
	return nil
}

// DeleteResult says what a deletion cost, for a command that has to be able to
// say it before doing it.
type DeleteResult struct {
	Instance string `json:"instance"`
	ID       string `json:"instance_id"`
	Members  int    `json:"members"`
	Owned    bool   `json:"owned"`
}

// Delete removes an instance this machine owns, on the hub and here.
//
// Nothing is revoked, because nothing can be: certificates were signed by an
// authority the hub never had, and this deletes the authority too. What ends is
// the lighthouse and the route table, so members can no longer find each other
// or know where to send anything. Connectors pointed at it keep asking.
func (d *Daemon) Delete(ctx context.Context, wanted string, force bool) (*DeleteResult, error) {
	target, err := d.resolveInstance(ctx, wanted)
	if err != nil {
		return nil, err
	}

	owned, isOwner := d.state.Owned(target.ID)
	if !isOwner {
		return nil, fmt.Errorf("this machine does not own %s, and only its owner may delete it", target.Name)
	}

	result := &DeleteResult{
		Instance: target.Name,
		ID:       target.ID,
		Members:  target.Members,
		Owned:    true,
	}

	// Members are counted from the hub's own view rather than remembered here,
	// so the number said out loud is the number that exists.
	if result.Members > 1 && !force {
		return result, fmt.Errorf("%s has %d members, which will all lose it: pass --force",
			target.Name, result.Members-1)
	}

	if err := d.hub.deleteInstance(ctx, target.ID); err != nil {
		return result, err
	}

	d.run.stop(target.ID)
	d.stopRouter(target.ID)

	err = d.state.Write(func(s *data) error {
		delete(s.Owned, target.ID)
		delete(s.Connections, target.ID)
		return nil
	})
	if err != nil {
		return result, err
	}

	d.log.Info("instance deleted", "instance", owned.Name, "members", result.Members)
	return result, nil
}

// rejoinOwn rebuilds an owner's own place in an instance, signing for itself.
//
// Nothing is asked of anybody: the authority is here, the address was reserved
// when the instance was created, and the hub already records this machine as
// its owner.
func (d *Daemon) rejoinOwn(ctx context.Context, inst *hub.InstanceSummary, owned *Owned) error {
	authority, err := ca.Load([]byte(owned.CACert), []byte(owned.CAKey))
	if err != nil {
		return err
	}

	// The lighthouse and its endpoints come from the route table, which is the
	// one place that carries them whole.
	table, err := d.hub.routes(ctx, inst.ID)
	if err != nil {
		return err
	}

	pub, key, err := ca.GenerateHostKey()
	if err != nil {
		return err
	}

	var machine string
	d.state.Read(func(s *data) { machine = s.Name })

	cert, err := authority.Sign(ca.Host{
		Name:         hub.MemberCertName(hub.KindTenant, hub.FoldLabel(machine), owned.Name),
		PublicKeyPEM: pub,
		Networks:     addresses(inst.Address, inst.Address6),
	})
	if err != nil {
		return err
	}

	err = d.state.Write(func(s *data) error {
		s.Connections[inst.ID] = &Connection{
			InstanceID:  inst.ID,
			Name:        owned.Name,
			Role:        hub.KindOwner,
			PublicKey:   string(pub),
			PrivateKey:  string(key),
			Certificate: string(cert),
			CA:          owned.CACert,
			Address:     inst.Address,
			Address6:    inst.Address6,
			Lighthouse:  table.Lighthouse,
			MTU:         table.MTU,
			Device:      s.nextDevice(),
			JoinedAt:    time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return err
	}

	d.log.Info("rejoined an instance this machine owns", "instance", owned.Name, "address", inst.Address)

	return nil
}

// Disconnect stops a connection and forgets it, by identifier or by name.
func (d *Daemon) Disconnect(ref string) error {
	conn, ok := d.connectionFor(ref)
	if !ok {
		return fmt.Errorf("not connected to %s", ref)
	}

	d.run.stop(conn.InstanceID)
	d.stopRouter(conn.InstanceID)

	return d.state.Write(func(s *data) error {
		delete(s.Connections, conn.InstanceID)
		return nil
	})
}

// RemoveMember forgets a member of an instance this machine owns.
func (d *Daemon) RemoveMember(ctx context.Context, req BanRequest) (*MemberEntry, error) {
	found, err := d.findMember(ctx, req.Member, req.Instance)
	if err != nil {
		return nil, err
	}

	member, err := d.hub.removeMember(ctx, found.owned.InstanceID, found.member.Fingerprint)
	if err != nil {
		return nil, err
	}

	d.log.Info("member removed", "instance", found.owned.Name, "member", member.Name)

	return &MemberEntry{
		Instance:   found.owned.Name,
		InstanceID: found.owned.InstanceID,
		Member:     member,
	}, nil
}

// ownedMember is one member, and the instance this machine owns it in.
type ownedMember struct {
	owned  *Owned
	member *hub.Member
}

// findMember resolves a member across the instances this machine owns.
//
// A name is unique inside an instance and nowhere else, so two of them can both
// hold a "railway". Instances are walked in map order, which is no order at
// all, so acting on whichever turned up first is not a tie-break: it is a coin
// toss with somebody's network. An ambiguous name is refused and named.
func (d *Daemon) findMember(ctx context.Context, ref, instance string) (*ownedMember, error) {
	if ref == "" {
		return nil, fmt.Errorf("no member named")
	}

	var (
		found  []ownedMember
		unread error
	)

	for _, owned := range d.owned() {
		if instance != "" && !strings.EqualFold(owned.Name, instance) && owned.InstanceID != instance {
			continue
		}

		members, err := d.hub.members(ctx, owned.InstanceID)
		if err != nil {
			// Kept rather than returned: one unreadable instance should not
			// stop a member being found in another, but it must not turn into
			// "no such member" either.
			unread = err
			continue
		}

		for _, m := range members {
			if m.Name == ref || strings.HasPrefix(m.Fingerprint, ref) {
				found = append(found, ownedMember{owned: owned, member: m})
			}
		}
	}

	switch len(found) {
	case 1:
		return &found[0], nil
	case 0:
		if unread != nil {
			return nil, unread
		}
		if instance != "" {
			return nil, fmt.Errorf("no member %s in %s", ref, instance)
		}
		return nil, fmt.Errorf("no member %s in any instance this machine owns", ref)
	}

	where := make([]string, 0, len(found))
	for _, f := range found {
		where = append(where, f.owned.Name)
	}
	sort.Strings(where)

	return nil, fmt.Errorf("%s is a member of %s: say which with --instance",
		ref, strings.Join(where, " and "))
}

// MemberEntry is one admitted member, with the instance it belongs to.
type MemberEntry struct {
	Instance   string      `json:"instance"`
	InstanceID string      `json:"instance_id"`
	Member     *hub.Member `json:"member"`
}

// Members lists who is inside every instance this machine belongs to.
func (d *Daemon) Members(ctx context.Context) ([]MemberEntry, error) {
	var out []MemberEntry

	for _, conn := range d.state.Connections() {
		members, err := d.hub.members(ctx, conn.InstanceID)
		if err != nil {
			continue
		}

		for _, m := range members {
			out = append(out, MemberEntry{
				Instance:   conn.Name,
				InstanceID: conn.InstanceID,
				Member:     m,
			})
		}
	}

	return out, nil
}

// PendingEntry is a request waiting for this machine's decision.
type PendingEntry struct {
	Instance   string       `json:"instance"`
	InstanceID string       `json:"instance_id"`
	Record     *hub.Record  `json:"record"`
	Address    netip.Prefix `json:"address"`

	// WillBeCalled is the name approving it would give it, which is also the
	// name space it would answer under. Said before the decision, because it
	// is part of what is being decided.
	WillBeCalled string `json:"will_be_called,omitempty"`

	// Routes and Dropped are filled in by Approve: what the certificate ended
	// up carrying, and what the authority could not carry. Domain is what it
	// will answer for, which is not in the certificate at all.
	Routes  []netip.Prefix `json:"routes,omitempty"`
	Dropped []netip.Prefix `json:"dropped,omitempty"`
	Domain  string         `json:"domain,omitempty"`
}

// Pending is everything waiting across the instances this machine owns.
func (d *Daemon) Pending(ctx context.Context) ([]PendingEntry, error) {
	var out []PendingEntry

	for _, owned := range d.owned() {
		records, err := d.hub.pending(ctx, owned.InstanceID)
		if err != nil {
			d.log.Warn("could not read pending requests", "instance", owned.Name, "error", err)
			continue
		}

		for _, record := range records {
			name := record.Request.Name
			if name == "" {
				name = defaultName(record)
			}

			out = append(out, PendingEntry{
				Instance:     owned.Name,
				InstanceID:   owned.InstanceID,
				Record:       record,
				Address:      record.OverlayAddress,
				WillBeCalled: name,
			})
		}
	}

	return out, nil
}

// Approve signs a certificate for a pending request.
func (d *Daemon) Approve(ctx context.Context, requestID string, routes []netip.Prefix, noDomain bool, wanted string) (*PendingEntry, error) {
	entry, err := d.findPending(ctx, requestID)
	if err != nil {
		return nil, err
	}

	owned, ok := d.state.Owned(entry.InstanceID)
	if !ok {
		return nil, fmt.Errorf("this machine does not own %s", entry.Instance)
	}

	record := entry.Record
	asked := routes != nil

	// What the connector announced, unless this refuses it. There is nothing
	// to narrow: a connector answers for one zone, the one its own resolver
	// knows, so naming a different one here would only name something nothing
	// over there can answer.
	domain := record.Request.Domain

	if record.Kind == hub.KindTenant {
		// A tenant consumes routes and names, it never offers them.
		routes = nil
		domain = ""
		asked = false
	} else {
		if !asked {
			routes = record.Request.Routes
		}
		if noDomain {
			domain = ""
		}
	}

	routes, dropped := carriable(routes, addresses(record.OverlayAddress, record.OverlayAddress6))
	if asked && len(dropped) > 0 {
		return nil, fmt.Errorf("cannot carry %s: this instance has no address of that family, and nebula refuses an unsafe network without one", prefixList(dropped))
	}

	authority, err := ca.Load([]byte(owned.CACert), []byte(owned.CAKey))
	if err != nil {
		return nil, err
	}

	// A name it will be known by, always: it goes into the certificate and
	// into the name space this member answers under, and "" is neither.
	if wanted == "" {
		wanted = record.Request.Name
	}
	name := wanted
	if name == "" {
		name = defaultName(record)
	}

	// The name it will answer under has to be a name: this one, the
	// instance's, and the suffix, and DNS stops at 253 characters.
	if err := fitsInAName(record.Kind, name, entry.Instance); err != nil {
		return nil, err
	}

	certPEM, err := authority.Sign(ca.Host{
		Name:           hub.MemberCertName(record.Kind, name, entry.Instance),
		PublicKeyPEM:   []byte(record.Request.PublicKey),
		Networks:       addresses(record.OverlayAddress, record.OverlayAddress6),
		UnsafeNetworks: routes,
	})
	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}

	issued, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	fingerprint, err := issued.Fingerprint()
	if err != nil {
		return nil, err
	}

	err = d.hub.decide(ctx, entry.InstanceID, record.ID, enroll.Decision{
		Status:          enroll.StatusApproved,
		Name:            name,
		Routes:          routes,
		Domain:          domain,
		CertFingerprint: fingerprint,
		Bundle: &enroll.Bundle{
			Certificate: string(certPEM),
			CA:          owned.CACert,
			Instance:    owned.Name,
		},
	})
	if err != nil {
		return nil, err
	}

	entry.Routes = routes
	entry.Dropped = dropped
	entry.Domain = domain

	if len(dropped) > 0 {
		d.log.Warn("dropped routes this instance cannot carry",
			"instance", entry.Instance, "routes", dropped)
	}

	d.log.Info("admitted",
		"instance", entry.Instance,
		"kind", record.Kind,
		"name", name,
		"address", record.OverlayAddress,
		"routes", routes,
	)

	return entry, nil
}

// Reject refuses a request. A connector that restarts will ask again.
func (d *Daemon) Reject(ctx context.Context, requestID, reason string) error {
	entry, err := d.findPending(ctx, requestID)
	if err != nil {
		return err
	}

	return d.hub.decide(ctx, entry.InstanceID, entry.Record.ID, enroll.Decision{
		Status: enroll.StatusRejected,
		Reason: reason,
	})
}

// Forget drops a record so it stops appearing.
func (d *Daemon) Forget(ctx context.Context, requestID string) error {
	entry, err := d.findPending(ctx, requestID)
	if err != nil {
		return err
	}

	return d.hub.forget(ctx, entry.InstanceID, entry.Record.ID)
}

// Ban blocklists a member of an instance this machine owns, which takes its
// routes out of the table for everybody at the same time.
func (d *Daemon) Ban(ctx context.Context, req BanRequest) error {
	found, err := d.findMember(ctx, req.Member, req.Instance)
	if err != nil {
		return err
	}

	if err := d.hub.ban(ctx, found.owned.InstanceID, found.member.Fingerprint, req.Note); err != nil {
		return err
	}

	d.log.Info("banned", "instance", found.owned.Name, "member", found.member.Name, "note", req.Note)

	return nil
}

// Unban lets a banned member of an instance this machine owns back in.
func (d *Daemon) Unban(ctx context.Context, req BanRequest) error {
	found, err := d.findMember(ctx, req.Member, req.Instance)
	if err != nil {
		return err
	}

	if err := d.hub.unban(ctx, found.owned.InstanceID, found.member.Fingerprint, req.Note); err != nil {
		return err
	}

	d.log.Info("unbanned", "instance", found.owned.Name, "member", found.member.Name, "note", req.Note)

	return nil
}

// findPending resolves a request by id or by its first characters.
func (d *Daemon) findPending(ctx context.Context, requestID string) (*PendingEntry, error) {
	entries, err := d.Pending(ctx)
	if err != nil {
		return nil, err
	}

	return matchPending(entries, requestID)
}

// matchPending resolves an id or a leading part of one, and refuses when a
// short one could mean more than one request.
//
// Admitting the wrong machine because two identifiers happened to share a few
// characters is not a mistake anybody would catch afterwards.
func matchPending(entries []PendingEntry, requestID string) (*PendingEntry, error) {
	var found []PendingEntry
	for _, entry := range entries {
		if entry.Record.ID == requestID {
			return &entry, nil
		}
		if strings.HasPrefix(entry.Record.ID, requestID) {
			found = append(found, entry)
		}
	}

	switch len(found) {
	case 0:
		return nil, fmt.Errorf("no pending request %s", requestID)
	case 1:
		return &found[0], nil
	default:
		return nil, fmt.Errorf("%s matches %d pending requests, give more of the id", requestID, len(found))
	}
}

func (d *Daemon) owned() []*Owned {
	var out []*Owned
	d.state.Read(func(s *data) {
		for _, o := range s.Owned {
			copied := *o
			out = append(out, &copied)
		}
	})
	return out
}

// newSharedToken is short enough to paste into a platform's environment by
// hand and long enough that guessing it is not a strategy.
func newSharedToken() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		// Failing here would mean an instance with no protection at all, and
		// a name nobody chose is better than that.
		return "t" + time.Now().UTC().Format("20060102150405")
	}
	return hex.EncodeToString(raw)
}

func machineName(state *State) string {
	name := "node"
	state.Read(func(s *data) {
		if s.Name != "" {
			name = s.Name
		}
	})
	return name
}

// carriable splits announced routes into the ones a certificate can hold and
// the ones it cannot.
//
// Nebula refuses an unsafe network whose family the certificate carries no
// address for. A dual stack instance keeps everything; one on a hub with no
// IPv6 pool drops what it cannot sign rather than failing the whole approval,
// because a connector announces both families whether or not anybody wants it.
func carriable(routes []netip.Prefix, addrs []netip.Prefix) (keep, dropped []netip.Prefix) {
	var has4, has6 bool
	for _, a := range addrs {
		if a.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}

	for _, r := range routes {
		if (r.Addr().Is4() && has4) || (!r.Addr().Is4() && has6) {
			keep = append(keep, r)
		} else {
			dropped = append(dropped, r)
		}
	}
	return keep, dropped
}

// addresses drops the ones that are not there, so a caller can hand over both
// families without asking whether the second exists.
func addresses(list ...netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		if p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

// prefixOf writes an address as a prefix of the instance's size, or nothing
// when the instance has no space of that family.
func prefixOf(addr netip.Addr, overlay netip.Prefix) netip.Prefix {
	if !addr.IsValid() || !overlay.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, overlay.Bits())
}

// prefixList renders prefixes for a message.
func prefixList(routes []netip.Prefix) string {
	parts := make([]string, 0, len(routes))
	for _, r := range routes {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, ", ")
}

// defaultName is what a member is called when it asked for nothing.
//
// The hints it sent are used before its key is: an applicant on a platform
// reports the project and environment it runs in, and
// disciplined-caring-production says what eight characters of a fingerprint
// never will. They are the applicant's own words and are not trusted for
// anything - but this is a label somebody reads, and the owner sees it before
// approving and can say otherwise.
func defaultName(record *hub.Record) string {
	hints := record.Request.Hints

	// Environment first and project second, separated the way DNS separates
	// things: joining them with a hyphen would lose where one ends, since a
	// project name may contain hyphens itself.
	if env, ok := asLabel(hints["environment"]); ok {
		if project, ok := asLabel(hints["project"]); ok {
			return env + "." + project
		}
	}

	for _, candidate := range []string{hints["service"], hints["project"], hints["hostname"]} {
		if name, ok := asLabel(candidate); ok {
			return name
		}
	}

	return record.Kind + "-" + record.Fingerprint[:8]
}

// asLabel turns whatever arrived into something that can stand in a domain
// name, or says it cannot.
//
// Separators become hyphens; anything else outside a label's alphabet makes
// the whole thing unusable rather than being dropped. Dropping would turn
// "żółw" into "w" and put a name in front of somebody that nobody chose. Not
// encoded either: punycode would make what was typed differ from what is read
// back in a log, an endpoint and an environment variable, and these names are
// copied by hand.
func asLabel(raw string) (string, bool) {
	var b strings.Builder

	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ' || r == '/':
			b.WriteRune('-')
		default:
			return "", false
		}
	}

	name := strings.Trim(b.String(), "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// A label is 63 bytes, and a name cut at that boundary must not end on the
	// hyphen the cut created.
	if len(name) > hub.MaxNameLength {
		name = strings.Trim(name[:hub.MaxNameLength], "-")
	}

	if name == "" {
		return "", false
	}
	return name, true
}

// fitsInAName refuses a member name that could not be part of the domain it
// will answer under.
func fitsInAName(kind, member, instance string) error {
	// Two names, and the certificate's is the longer of them because it says
	// what kind of member this is. Both have to fit.
	for _, full := range []string{
		member + "." + instance + "." + Suffix,
		hub.MemberCertName(kind, member, instance),
	} {
		if len(full) > 253 {
			return fmt.Errorf("%s would be called %s, which is %d characters and DNS stops at 253: approve it with a shorter --name",
				member, full, len(full))
		}
	}

	return nil
}
