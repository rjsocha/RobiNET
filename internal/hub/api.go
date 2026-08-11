package hub

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/wrak"
)

// maxBodyBytes bounds every request. The enrollment endpoints are the only
// surface reachable without credentials, so there is a hard ceiling.
const maxBodyBytes = 64 << 10

// Handler builds the hub's HTTP API.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Registering a machine. Signed with an ssh key rather than an identity,
	// because the identity is what this call creates.
	mux.HandleFunc("POST /v1/register", h.handleRegister)

	// Everything else from a registered machine is signed with its identity.
	mux.HandleFunc("POST /v1/instances", h.signed(h.handleCreateInstance))
	mux.HandleFunc("GET /v1/instances", h.signed(h.handleListInstances))

	mux.HandleFunc("POST /v1/instances/{id}/lighthouse", h.ownerOnly(h.handleLighthouse))
	mux.HandleFunc("GET /v1/instances/{id}/requests", h.ownerOnly(h.handlePending))
	mux.HandleFunc("POST /v1/instances/{id}/requests/{rid}", h.ownerOnly(h.handleDecision))
	mux.HandleFunc("DELETE /v1/instances/{id}/requests/{rid}", h.ownerOnly(h.handleForget))
	mux.HandleFunc("POST /v1/instances/{id}/ban", h.ownerOnly(h.handleBan))
	mux.HandleFunc("POST /v1/instances/{id}/unban", h.ownerOnly(h.handleUnban))
	mux.HandleFunc("POST /v1/instances/{id}/token", h.ownerOnly(h.handleSetToken))
	mux.HandleFunc("DELETE /v1/instances/{id}", h.ownerOnly(h.handleDeleteInstance))
	mux.HandleFunc("DELETE /v1/instances/{id}/members/{member}", h.ownerOnly(h.handleRemoveMember))

	// Asking to be let into somebody else's instance, and collecting the
	// answer. Signed, so the owner sees a name rather than a stranger.
	mux.HandleFunc("POST /v1/instances/{id}/join", h.signed(h.handleJoin))
	mux.HandleFunc("GET /v1/instances/{id}/join", h.signed(h.handleJoinResult))

	// The route table, which is why the hub keeps one: admitting a connector
	// changes what every member sees without reissuing anything.
	mux.HandleFunc("GET /v1/instances/{id}/routes", h.memberOnly(h.handleRoutes))
	mux.HandleFunc("GET /v1/instances/{id}/members", h.memberOnly(h.handleMembers))

	// Connector facing. No credentials, so everything here is bounded and rate
	// limited, and a shared token authenticates the payload when configured.
	mux.HandleFunc("POST /v1/enroll/{id}", h.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/{id}/{rid}", h.handleResult)

	return http.MaxBytesHandler(mux, maxBodyBytes)
}

// RegisterRequest is a machine asking to be known.
type RegisterRequest struct {
	Name     string `json:"name"`
	Identity string `json:"identity"`

	// Signature is the bootstrap message signed with an ssh key, armored the
	// way ssh-keygen -Y sign writes it.
	Signature string `json:"signature"`
}

// RegisterResponse tells the machine who the hub thinks it is.
type RegisterResponse struct {
	Identity string `json:"identity"`
	Binder   string `json:"binder"`

	// Key is the ssh key that was accepted, so a person can see which of
	// theirs the hub knows.
	Key string `json:"key"`

	// SignedBy is filled in by the client with the key it used.
	SignedBy string `json:"-"`
}

func (h *Hub) handleRegister(w http.ResponseWriter, r *http.Request) {
	source := sourceAddr(r)
	if !h.limiter().allow(source) {
		writeError(w, http.StatusTooManyRequests, "slow_down", "too many attempts")
		return
	}

	var req RegisterRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if _, err := wrak.ParsePublicIdentity(req.Identity); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// The message is rebuilt from what this hub knows, never from what the
	// caller sent: the token is ours, so the caller cannot choose what they
	// signed.
	bootstrap := wrak.Bootstrap{
		API:      r.Host,
		Token:    h.cfg.Token,
		Name:     req.Name,
		Identity: req.Identity,
	}

	key, err := bootstrap.Verify([]byte(req.Signature), h.cfg.Binders.AllKeys())
	if err != nil {
		// A wrong token and an unknown key get the same answer: telling them
		// apart would say which keys this hub knows.
		h.log.Warn("registration rejected", "from", source, "error", err)
		writeError(w, http.StatusUnauthorized, "unauthorized", "registration rejected")
		return
	}

	binder, ok := h.cfg.Binders.Match(key)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "registration rejected")
		return
	}

	registration := &Registration{
		Identity: req.Identity,
		Binder:   binder,
		Name:     req.Name,
		Key:      wrak.AuthorizedKey(key),
	}
	if err := h.store.Register(registration); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	h.log.Info("machine registered",
		"binder", binder,
		"name", req.Name,
		"key", wrak.AuthorizedKey(key),
		"from", source,
	)

	writeJSON(w, http.StatusCreated, RegisterResponse{
		Identity: req.Identity,
		Binder:   binder,
		Key:      wrak.AuthorizedKey(key),
	})
}

// CreateInstanceRequest asks for a new instance.
type CreateInstanceRequest struct {
	Name string `json:"name"`

	// SharedToken, when set, is required on every connector enrollment for
	// this instance and authenticates it end to end.
	SharedToken string `json:"shared_token,omitempty"`
}

// CreateInstanceResponse is what an owner needs to sign the lighthouse and
// come back.
type CreateInstanceResponse struct {
	ID string `json:"id"`

	// Name as the hub stored it, which is not always what was asked for: a
	// name is folded to lower case, because that is what it will mean in DNS.
	Name string `json:"name"`

	Binder string `json:"binder"`

	Overlay             netip.Prefix `json:"overlay"`
	Overlay6            netip.Prefix `json:"overlay6,omitempty"`
	Port                uint16       `json:"port"`
	LighthouseAddress   netip.Addr   `json:"lighthouse_address"`
	LighthouseAddress6  netip.Addr   `json:"lighthouse_address6,omitempty"`
	TenantAddress       netip.Addr   `json:"tenant_address"`
	TenantAddress6      netip.Addr   `json:"tenant_address6,omitempty"`
	LighthousePublicKey string       `json:"lighthouse_public_key"`
	Endpoint            string       `json:"endpoint"`
	MTU                 uint32       `json:"mtu,omitempty"`
	Relay               bool         `json:"relay"`
}

func (h *Hub) handleCreateInstance(w http.ResponseWriter, r *http.Request, who *Registration) {
	var req CreateInstanceRequest
	if !decode(w, r, &req) {
		return
	}
	name, err := ParseName(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	inst, err := h.CreateInstance(who.Binder, who.Identity, name, req.SharedToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, CreateInstanceResponse{
		ID:                  inst.ID,
		Name:                inst.Name,
		Binder:              inst.Binder,
		Overlay:             inst.Overlay,
		Overlay6:            inst.Overlay6,
		Port:                inst.Port,
		LighthouseAddress:   inst.LighthouseAddress,
		LighthouseAddress6:  inst.LighthouseAddress6,
		TenantAddress:       inst.TenantAddress,
		TenantAddress6:      inst.TenantAddress6,
		LighthousePublicKey: inst.LighthousePublicKey,
		Endpoint:            h.cfg.PublicEndpoint,
		MTU:                 h.cfg.MTU,
		Relay:               inst.Relay,
	})
}

// InstanceSummary is one line of what a machine can see.
type InstanceSummary struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Binder   string       `json:"binder"`
	Overlay  netip.Prefix `json:"overlay"`
	Overlay6 netip.Prefix `json:"overlay6,omitempty"`

	// Role is owner, tenant or connector from the caller's point of view, and
	// empty when the caller does not belong to it.
	Role string `json:"role"`

	// Owner names who to ask for access: the binder that created it, and the
	// machine that did.
	Owner        string `json:"owner"`
	OwnerMachine string `json:"owner_machine,omitempty"`

	// Yours says the caller's own key created this instance, whatever machine
	// they are sitting at. A person has one key and several machines, and
	// without this the caller is told to ask themselves for permission.
	Yours bool `json:"yours,omitempty"`

	Address    netip.Prefix `json:"address,omitempty"`
	Address6   netip.Prefix `json:"address6,omitempty"`
	Routes     []Route      `json:"routes,omitempty"`
	Members    int          `json:"members"`
	Pending    int          `json:"pending,omitempty"`
	Lighthouse netip.Addr   `json:"lighthouse"`
	Running    bool         `json:"running"`
}

func (h *Hub) handleListInstances(w http.ResponseWriter, r *http.Request, who *Registration) {
	out := []InstanceSummary{}

	for _, inst := range h.store.List() {
		// Every instance is listed, because somebody has to be able to find
		// the one they need and see whose it is. What an outsider gets is a
		// name and an owner to ask; membership, addresses and routes are only
		// filled in for those who belong.
		summary := InstanceSummary{
			ID:         inst.ID,
			Name:       inst.Name,
			Binder:     inst.Binder,
			Owner:      inst.Binder,
			Overlay:    inst.Overlay,
			Overlay6:   inst.Overlay6,
			Lighthouse: inst.LighthouseAddress,
			Running:    h.lhs.isRunning(inst.ID),
		}

		if owner, err := h.store.Identity(inst.Owner); err == nil {
			summary.OwnerMachine = owner.Name
		}

		summary.Yours = inst.Binder != "" && inst.Binder == who.Binder

		if member, belongs := inst.MemberOf(who.Identity); belongs {
			summary.Role = member.Kind
			summary.Address = member.Address
			summary.Address6 = member.Address6
			summary.Members = len(inst.Members)
			summary.Routes = routesOf(inst)

			if inst.Owner == who.Identity {
				summary.Role = KindOwner
				for _, rec := range inst.Requests {
					if rec.Status == enroll.StatusPending {
						summary.Pending++
					}
				}
			}
		}

		out = append(out, summary)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	writeJSON(w, http.StatusOK, out)
}

func (h *Hub) handleRemoveMember(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	member, err := h.RemoveMember(inst.ID, r.PathValue("member"))
	if err != nil {
		writeMemberError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, member)
}

func (h *Hub) handleDeleteInstance(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	if err := h.Delete(inst.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// LighthouseRequest carries the certificates only the owner can produce.
type LighthouseRequest struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
}

func (h *Hub) handleLighthouse(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	var req LighthouseRequest
	if !decode(w, r, &req) {
		return
	}

	if err := h.ActivateInstance(inst.ID, req.CA, req.Certificate); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"running": h.lhs.isRunning(inst.ID)})
}

func (h *Hub) handlePending(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	pending, err := h.Pending(inst.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, pending)
}

func (h *Hub) handleDecision(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	var d enroll.Decision
	if !decode(w, r, &d) {
		return
	}

	if err := h.Decide(inst.ID, r.PathValue("rid"), d); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, "bad_request", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Hub) handleForget(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	if err := h.Forget(inst.ID, r.PathValue("rid")); err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// BanRequest names a member to blocklist, or to let back in, and says why.
type BanRequest struct {
	Member string `json:"member"`

	// Note is the reason, kept with the decision. Nothing else will remember it.
	Note string `json:"note,omitempty"`
}

func (h *Hub) handleBan(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	var req BanRequest
	if !decode(w, r, &req) {
		return
	}

	if err := h.Ban(inst.ID, req.Member, req.Note); err != nil {
		writeMemberError(w, err)
		return
	}

	h.log.Info("member banned", "instance", inst.Name, "member", req.Member, "note", req.Note)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Hub) handleUnban(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	var req BanRequest
	if !decode(w, r, &req) {
		return
	}

	if err := h.Unban(inst.ID, req.Member, req.Note); err != nil {
		writeMemberError(w, err)
		return
	}

	h.log.Info("member unbanned", "instance", inst.Name, "member", req.Member, "note", req.Note)
	w.WriteHeader(http.StatusNoContent)
}

// writeMemberError separates "this instance does not have that member" from
// "it does, and this is refused".
//
// The caller walks every instance it owns looking for the member, so it has to
// be able to tell the two apart. Reporting a refusal as a miss made it walk
// past the answer and say the member did not exist anywhere.
func writeMemberError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, "bad_request", err.Error())
}

// TokenRequest replaces the secret new connector enrollments are authenticated
// with.
type TokenRequest struct {
	SharedToken string `json:"shared_token"`
}

func (h *Hub) handleSetToken(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Registration) {
	var req TokenRequest
	if !decode(w, r, &req) {
		return
	}

	if err := h.SetSharedToken(inst.ID, req.SharedToken); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// The token itself is never logged: it is the whole of what authenticates
	// an enrollment, and a log is read by more people than an instance is.
	h.log.Info("shared token replaced", "instance", inst.Name)
	w.WriteHeader(http.StatusNoContent)
}

// JoinRequest asks to be let into an instance as a consumer of its routes.
type JoinRequest struct {
	Name string `json:"name"`

	// PublicKey is the nebula public key this machine will use inside that
	// instance. A separate one per instance, so nothing correlates across them.
	PublicKey string `json:"public_key"`
}

func (h *Hub) handleJoin(w http.ResponseWriter, r *http.Request, who *Registration) {
	id := r.PathValue("id")

	var req JoinRequest
	if !decode(w, r, &req) {
		return
	}

	name := req.Name
	if name == "" {
		name = who.Name
	}

	record, err := h.Enroll(id, enroll.Request{
		PublicKey: req.PublicKey,
		Name:      name,
	}, Applicant{
		Kind:       KindTenant,
		Identity:   who.Identity,
		Binder:     who.Binder,
		SourceAddr: sourceAddr(r),
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such instance")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	h.log.Info("join requested",
		"instance", id,
		"binder", who.Binder,
		"name", name,
		"request", record.ID,
	)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":          record.ID,
		"status":      record.Status,
		"retry_after": 5,
	})
}

func (h *Hub) handleJoinResult(w http.ResponseWriter, r *http.Request, who *Registration) {
	inst, err := h.store.Resolve(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such instance")
		return
	}

	for _, record := range inst.Requests {
		if record.Identity != who.Identity {
			continue
		}

		res := enroll.Result{Status: record.Status, Reason: record.Reason}
		if record.Status == enroll.StatusApproved {
			res.Bundle = withBlocklist(record.Bundle, inst)
		} else {
			res.RetryAfter = 15
		}

		writeJSON(w, http.StatusOK, res)
		return
	}

	writeError(w, http.StatusNotFound, "not_found", "no request from this machine")
}

func (h *Hub) handleMembers(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Member) {
	members, err := h.Members(inst.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, members)
}

func (h *Hub) handleRoutes(w http.ResponseWriter, r *http.Request, inst *Instance, _ *Member) {
	writeJSON(w, http.StatusOK, h.RouteTableOf(inst))
}

func (h *Hub) handleEnroll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	source := sourceAddr(r)

	if !h.limiter().allow(source) {
		writeError(w, http.StatusTooManyRequests, "slow_down", "too many enrollment attempts")
		return
	}

	var req enroll.Request
	if !decode(w, r, &req) {
		return
	}

	record, err := h.Enroll(id, req, Applicant{
		Kind:       KindConnector,
		MAC:        r.Header.Get(enroll.MACHeader),
		SourceAddr: source,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such instance")
			return
		}
		if errors.Is(err, ErrAmbiguous) {
			// Guessing which one was meant would be handing a connector to
			// whichever owner happened to sort first.
			writeError(w, http.StatusConflict, "ambiguous", "more than one instance has that name, use its id")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	h.log.Info("enrollment received",
		"instance", id,
		"request", record.ID,
		"fingerprint", record.Fingerprint[:16],
		"routes", req.Routes,
		"from", source,
	)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":          record.ID,
		"status":      record.Status,
		"retry_after": 5,
	})
}

func (h *Hub) handleResult(w http.ResponseWriter, r *http.Request) {
	res, err := h.Result(r.PathValue("id"), r.PathValue("rid"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such request")
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// signed requires a request signed by a registered machine.
func (h *Hub) signed(next func(http.ResponseWriter, *http.Request, *Registration)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}

		identity, err := wrak.VerifyRequest(r, body, h.nonces())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		who, err := h.store.Identity(identity)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "this machine is not registered here")
			return
		}

		next(w, r, who)
	}
}

// ownerOnly requires the caller to own the instance, which is the only role
// that decides anything: it is the one holding the authority.
func (h *Hub) ownerOnly(next func(http.ResponseWriter, *http.Request, *Instance, *Registration)) http.HandlerFunc {
	return h.signed(func(w http.ResponseWriter, r *http.Request, who *Registration) {
		inst, err := h.store.Resolve(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "no such instance")
			return
		}

		if !wrak.ConstantTimeEqual(who.Identity, inst.Owner) {
			writeError(w, http.StatusForbidden, "forbidden", "only the owner of that instance may do that")
			return
		}

		next(w, r, inst, who)
	})
}

// memberOnly requires the caller to belong to the instance in any role.
func (h *Hub) memberOnly(next func(http.ResponseWriter, *http.Request, *Instance, *Member)) http.HandlerFunc {
	return h.signed(func(w http.ResponseWriter, r *http.Request, who *Registration) {
		inst, err := h.store.Resolve(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "no such instance")
			return
		}

		member, ok := inst.MemberOf(who.Identity)
		if !ok {
			writeError(w, http.StatusForbidden, "forbidden", "this machine does not belong to that instance")
			return
		}

		next(w, r, inst, member)
	})
}

// readBody reads a request body and puts it back, since the signature covers
// it and the handler still wants to decode it.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, enroll.Error{Code: code, Message: message})
}

func sourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiter is a small fixed window counter per source address. The
// unauthenticated endpoints do not get to be free.
type rateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	buckets map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{window: window, limit: limit, buckets: map[string]*bucket{}}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok || now.After(b.reset) {
		rl.buckets[key] = &bucket{count: 1, reset: now.Add(rl.window)}
		return true
	}

	b.count++
	return b.count <= rl.limit
}

// nonces is the replay guard for signed requests.
func (h *Hub) nonces() wrak.NonceStore {
	h.nonceOnce.Do(func() {
		h.nonceStore = wrak.NewMemoryNonces()
	})
	return h.nonceStore
}

func (h *Hub) limiter() *rateLimiter {
	h.limiterOnce.Do(func() {
		h.rl = newRateLimiter(30, time.Minute)
	})
	return h.rl
}
