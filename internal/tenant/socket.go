package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/version"
	"golang.org/x/sys/unix"
)

// The control socket is the whole local API. Authorization is the socket's own
// permissions: it belongs to the person who registered this machine, and the
// kernel reports the caller's credentials, so there is no token to steal and
// nothing bound to a network address.

// ConnectRequest asks to join an instance.
type ConnectRequest struct {
	Instance string `json:"instance"`
}

// ApproveRequest admits a pending applicant.
type ApproveRequest struct {
	ID string `json:"id"`

	// Name overrides what the applicant asked to be called, which is also what
	// it will be known by in DNS.
	Name string `json:"name,omitempty"`

	// Routes and Domains narrow what is accepted from a connector. Empty means
	// everything it announced.
	Routes  []netip.Prefix `json:"routes,omitempty"`
	Domains []string       `json:"domains,omitempty"`
}

// DecisionRequest carries a rejection or a forget.
type DecisionRequest struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// Status is what the command line shows.
type Status struct {
	Hub      string `json:"hub"`
	Identity string `json:"identity"`
	Binder   string `json:"binder"`
	Name     string `json:"name"`

	// Families is which address families this machine installs routes for,
	// and Inbound is what members of an instance may reach here.
	Families string `json:"families,omitempty"`
	Inbound  string `json:"inbound,omitempty"`

	// Version is the build the daemon is running, which is not the build that
	// asked: upgrading replaces the binary and leaves the service on the old
	// one until it is restarted.
	Version string `json:"version"`

	Connections []ConnectionStatus `json:"connections"`
	Pending     []PendingEntry     `json:"pending,omitempty"`
}

// ConnectionStatus is one membership as it stands right now.
type ConnectionStatus struct {
	Instance   string       `json:"instance"`
	InstanceID string       `json:"instance_id"`
	Role       string       `json:"role"`
	Address    netip.Prefix `json:"address,omitempty"`
	Address6   netip.Prefix `json:"address6,omitempty"`
	Device     string       `json:"device"`
	Running    bool         `json:"running"`
	Waiting    bool         `json:"waiting"`
	Routes     []hub.Route  `json:"routes,omitempty"`

	// Endpoint is what a connector for this instance is configured with. Only
	// set for instances this machine owns, since only its owner hands it out.
	Endpoint string `json:"endpoint,omitempty"`
}

// Serve runs the control socket until ctx is done.
func (d *Daemon) Serve(ctx context.Context, path string) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	// A stale socket from a previous run would block the bind.
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("could not listen on %s: %w", path, err)
	}

	if err := d.applySocketPermissions(path); err != nil {
		ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", d.handleStatus)
	mux.HandleFunc("GET /list", d.handleList)
	mux.HandleFunc("GET /members", d.handleMembers)
	mux.HandleFunc("GET /reach", d.handleReach)
	mux.HandleFunc("POST /show", d.handleShow)
	mux.HandleFunc("GET /pending", d.handlePending)
	mux.HandleFunc("POST /create", d.handleCreate)
	mux.HandleFunc("POST /connect", d.handleConnect)
	mux.HandleFunc("POST /disconnect", d.handleDisconnect)
	mux.HandleFunc("POST /approve", d.handleApprove)
	mux.HandleFunc("POST /reject", d.handleReject)
	mux.HandleFunc("POST /forget", d.handleForget)
	mux.HandleFunc("POST /ban", d.handleBan)
	mux.HandleFunc("POST /member/remove", d.handleRemoveMember)
	mux.HandleFunc("POST /restart", d.handleRestart)
	mux.HandleFunc("POST /families", d.handleFamilies)
	mux.HandleFunc("POST /dns", d.handleDNSPlan)
	mux.HandleFunc("POST /alias", d.handleAlias)
	mux.HandleFunc("POST /inbound", d.handleInbound)
	mux.HandleFunc("POST /delete", d.handleDelete)

	srv := &http.Server{
		Handler: d.logPeer(mux),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uc, ok := c.(*net.UnixConn)
			if !ok {
				return ctx
			}
			cred, err := peerCredentials(uc)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, peerKey{}, cred)
		},
	}

	go func() {
		<-ctx.Done()
		srv.Close()
		_ = os.Remove(path)
	}()

	if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// logPeer records who asked. The socket permissions are the gate; this is the
// audit trail, and it is free because the kernel already knows.
// VersionHeader carries the daemon's build on every reply.
//
// The command line and the daemon are the same binary, and an upgrade replaces
// it while leaving the service running the one it started with. So the build
// is the whole contract: two halves of one program that were built together
// agree by construction, and two that were not agree only by luck.
//
// A number to bump instead would need somebody to notice that bumping it was
// due, which is exactly what nobody does while changing what an endpoint
// means.
const VersionHeader = "Robinet-Version"

func (d *Daemon) logPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid, err := peerUID(r); err == nil {
			d.log.Debug("control request", "uid", uid, "path", r.URL.Path)
		}
		w.Header().Set(VersionHeader, version.String())
		next.ServeHTTP(w, r)
	})
}

// handleRestart stops the daemon so its supervisor starts it again on the
// binary that is on disk now.
//
// It signals itself rather than exiting, so the shutdown is the same one a
// systemctl stop takes: connections come down in order and the socket is
// removed. The reply goes out first, because the caller is about to lose the
// connection it is reading.
// DeleteRequest removes an instance this machine owns.
type DeleteRequest struct {
	Instance string `json:"instance"`
	Force    bool   `json:"force"`
}

func (d *Daemon) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req DeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	result, err := d.Delete(r.Context(), req.Instance, req.Force)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// InboundRequest changes what members may reach here.
type InboundRequest struct {
	Inbound string `json:"inbound"`
}

func (d *Daemon) handleInbound(w http.ResponseWriter, r *http.Request) {
	var req InboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.state.SetInbound(req.Inbound); err != nil {
		writeError(w, err)
		return
	}

	// Every connection is rebuilt against the new rule, so closing a machine
	// off takes effect now rather than at the next restart.
	d.Refresh(r.Context())

	writeJSON(w, http.StatusOK, map[string]any{"inbound": d.state.Inbound()})
}

func (d *Daemon) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	var req BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	entry, err := d.RemoveMember(r.Context(), req.Member)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

// AliasRequest gives a name space another name on this machine.
type AliasRequest struct {
	Alias     string `json:"alias"`
	Canonical string `json:"canonical,omitempty"`
}

func (d *Daemon) handleAlias(w http.ResponseWriter, r *http.Request) {
	var req AliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.SetAlias(r.Context(), req.Alias, req.Canonical); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, d.state.Aliases())
}

func (d *Daemon) handleReach(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.Reachable(r.Context()))
}

// DNSRequest installs or removes the resolver configuration.
type DNSRequest struct {
	Mode   string `json:"mode"`
	Remove bool   `json:"remove"`
}

// handleDNSPlan reports what should be configured. Configuring it is the
// caller's, because it needs root and this daemon does not have it.
func (d *Daemon) handleDNSPlan(w http.ResponseWriter, r *http.Request) {
	var req DNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if _, err := lookupMode(req.Mode); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, d.DNSPlan(r.Context(), req.Remove))
}

// FamiliesRequest changes what this machine installs.
type FamiliesRequest struct {
	Families string `json:"families"`
}

func (d *Daemon) handleFamilies(w http.ResponseWriter, r *http.Request) {
	var req FamiliesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.state.SetFamilies(req.Families); err != nil {
		writeError(w, err)
		return
	}

	// Every connection is rebuilt against the new setting, so the change is
	// visible in the route table rather than at the next restart.
	d.Refresh(r.Context())

	writeJSON(w, http.StatusOK, map[string]any{"families": d.state.Families()})
}

func (d *Daemon) handleRestart(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": version.String()})

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	d.log.Info("restarting on request")
	d.restart.Store(true)
	go func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
}

// RestartWanted reports whether the daemon came down because somebody asked it
// to, rather than because it was stopped.
//
// It decides the exit status, and the exit status decides whether systemd
// starts it again: a unit written before this existed says Restart=on-failure,
// where a clean exit means staying down. Exiting non-zero is what makes
// robinet restart work on a unit that has not been rewritten yet.
func (d *Daemon) RestartWanted() bool { return d.restart.Load() }

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := Status{
		Version:  version.String(),
		Families: d.state.Families(),
		Inbound:  d.state.Inbound(),
	}
	d.state.Read(func(s *data) {
		status.Hub = s.HubURL
		status.Binder = s.Binder
		status.Name = s.Name
	})

	for _, conn := range d.state.Connections() {
		entry := ConnectionStatus{
			Instance:   conn.Name,
			InstanceID: conn.InstanceID,
			Role:       conn.Role,
			Address:    conn.Address,
			Address6:   conn.Address6,
			Device:     conn.Device,
			Running:    d.run.isRunning(conn.InstanceID),
			Waiting:    !conn.Ready(),
		}

		if table, err := d.hub.routes(r.Context(), conn.InstanceID); err == nil {
			entry.Routes = table.Routes
		}

		if owned, ok := d.state.Owned(conn.InstanceID); ok {
			var hubURL string
			d.state.Read(func(s *data) { hubURL = s.HubURL })
			// By name: it resolves everywhere an identifier does, it is
			// unique on the hub, and it is the thing somebody has to type
			// into a platform's environment without a way to check it.
			entry.Endpoint = shorthandEndpoint(hubURL, instanceRef(conn), owned.SharedToken)
		}

		status.Connections = append(status.Connections, entry)
	}

	if pending, err := d.Pending(r.Context()); err == nil {
		status.Pending = pending
	}

	writeJSON(w, http.StatusOK, status)
}

func (d *Daemon) handleList(w http.ResponseWriter, r *http.Request) {
	instances, err := d.List(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, instances)
}

// CreateRequest asks for a new instance owned by this machine.
type CreateRequest struct {
	Name        string `json:"name"`
	SharedToken string `json:"shared_token,omitempty"`
}

func (d *Daemon) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	created, sharedToken, err := d.Create(r.Context(), req.Name, req.SharedToken)
	if err != nil {
		writeError(w, err)
		return
	}

	// The enrollment url is what a connector is configured with, and this is
	// the only moment somebody has to copy it somewhere, so hand it over whole
	// rather than in pieces to be assembled.
	var hubURL string
	d.state.Read(func(s *data) { hubURL = s.HubURL })

	out := map[string]any{
		"id":           created.ID,
		"name":         created.Name,
		"overlay":      created.Overlay,
		"endpoint":     shorthandEndpoint(hubURL, created.Name, sharedToken),
		"enroll_url":   fmt.Sprintf("%s/v1/enroll/%s", hubURL, created.ID),
		"shared_token": sharedToken,
	}
	// Absent rather than empty when the hub has no IPv6 pool, so the answer to
	// "did I get one" is visible instead of having to be inferred.
	if created.Overlay6.IsValid() {
		out["overlay6"] = created.Overlay6
	}

	writeJSON(w, http.StatusOK, out)
}

// instanceInfo is what somebody needs in order to point a connector at an
// instance: one string, in the short form a platform's environment takes.
func (d *Daemon) instanceInfo(id, ref, overlay, sharedToken string) map[string]any {
	var hubURL string
	d.state.Read(func(s *data) { hubURL = s.HubURL })

	if ref == "" {
		ref = id
	}

	// The endpoint carries the name and the url carries the identifier: one is
	// typed by a person into a platform's environment, the other is followed
	// by a program.
	endpoint := shorthandEndpoint(hubURL, ref, sharedToken)

	return map[string]any{
		"id":       id,
		"overlay":  overlay,
		"endpoint": endpoint,
		"url":      fmt.Sprintf("%s/v1/enroll/%s", hubURL, id),
	}
}

// instanceRef is what to write into an endpoint: the name when there is one,
// since both resolve and only one can be read back.
func instanceRef(conn *Connection) string {
	if conn.Name != "" {
		return conn.Name
	}
	return conn.InstanceID
}

// shorthandEndpoint renders host/instance[/token], dropping the port when it
// is the default one a connector already assumes.
func shorthandEndpoint(hubURL, id, token string) string {
	host := hubURL
	if u, err := url.Parse(hubURL); err == nil && u.Host != "" {
		host = u.Host
	}
	host = strings.TrimSuffix(host, ":8443")

	out := host + "/" + id
	if token != "" {
		out += "/" + token
	}
	return out
}

func (d *Daemon) handleShow(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	info, err := d.Show(r.Context(), req.Instance)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, info)
}

func (d *Daemon) handleMembers(w http.ResponseWriter, r *http.Request) {
	members, err := d.Members(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

func (d *Daemon) handlePending(w http.ResponseWriter, r *http.Request) {
	pending, err := d.Pending(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pending)
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.Connect(r.Context(), req.Instance); err != nil {
		writeError(w, err)
		return
	}

	// Collect immediately in case the owner approved before we asked, which
	// happens when a connection is being re-established.
	d.Refresh(r.Context())

	writeJSON(w, http.StatusOK, map[string]any{"instance": req.Instance})
}

func (d *Daemon) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.Disconnect(req.Instance); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req ApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	entry, err := d.Approve(r.Context(), req.ID, req.Routes, req.Domains, req.Name)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

func (d *Daemon) handleReject(w http.ResponseWriter, r *http.Request) {
	var req DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.Reject(r.Context(), req.ID, req.Reason); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleForget(w http.ResponseWriter, r *http.Request) {
	var req DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.Forget(r.Context(), req.ID); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// BanRequest names a member to blocklist.
type BanRequest struct {
	Member string `json:"member"`
}

func (d *Daemon) handleBan(w http.ResponseWriter, r *http.Request) {
	var req BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	if err := d.Ban(r.Context(), req.Member); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

// applySocketPermissions hands the socket to the person who registered this
// machine, so they drive the daemon without sudo and nobody else can.
func (d *Daemon) applySocketPermissions(path string) error {
	var uid, gid int
	d.state.Read(func(s *data) { uid, gid = s.OwnerUID, s.OwnerGID })

	if uid > 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("could not give %s to uid %d: %w", path, uid, err)
		}
	}

	return os.Chmod(path, 0o600)
}

// peerKey carries the caller's kernel reported credentials.
type peerKey struct{}

func peerUID(r *http.Request) (uint32, error) {
	cred, ok := r.Context().Value(peerKey{}).(*unix.Ucred)
	if !ok || cred == nil {
		return 0, fmt.Errorf("no peer credentials")
	}
	return cred.Uid, nil
}

// ownerIdentity is who is running this, or who called sudo.
func ownerIdentity() (name string, uid, gid int, _ error) {
	name, err := ownerName()
	if err != nil {
		return "", 0, 0, err
	}

	uid, gid, err = ownerIDs()
	if err != nil {
		return "", 0, 0, err
	}

	return name, uid, gid, nil
}

func peerCredentials(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		cred    *unix.Ucred
		credErr error
	)
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	return cred, credErr
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
