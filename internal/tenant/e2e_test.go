package tenant

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestSharedInstance walks the whole story: an owner creates an instance, a
// connector is admitted and starts carrying a network, and a second person is
// then let in to reach that same network without deploying anything of their
// own.
func TestSharedInstance(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	robertKey := testKey(t)
	jacekKey := testKey(t)

	h, err := hub.New(hub.Config{
		NebulaBind:     "127.0.0.1",
		PublicEndpoint: "127.0.0.1",
		PortMin:        21100,
		PortMax:        21110,
		Overlays: []hub.Pool{
			{Prefix: netip.MustParsePrefix("198.19.200.0/22"), Size: 24},
		},
		Overlays6: []hub.Pool{
			{Prefix: netip.MustParsePrefix("fd7a:1c2d:3e4f::/48"), Size: 112},
		},
		Token: "hub-token",
		Binders: hub.Binders{
			"robert": {Keys: []ssh.PublicKey{robertKey.PublicKey()}},
			"jacek":  {Keys: []ssh.PublicKey{jacekKey.PublicKey()}},
		},
		NoLighthouseTun: true,
		StatePath:       filepath.Join(dir, "hub.json"),
		MTU:             1500,
		Logger:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Robert registers his machine and creates an instance.
	robert := daemonFor(t, ctx, dir, "robert", srv.URL, robertKey, log)

	created, _, err := robert.Create(ctx, "railway-prod", "shared")
	if err != nil {
		t.Fatal(err)
	}

	// The authority never reached the hub.
	hubState, err := os.ReadFile(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(hubState, []byte("NEBULA ED25519 PRIVATE KEY")) {
		t.Fatal("the hub state file contains a signing key")
	}

	// A connector shows up and is admitted.
	connectorKey, _, err := ca.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	req := enroll.Request{
		PublicKey: string(connectorKey),
		Name:      "railway",
		Routes: []netip.Prefix{
			netip.MustParsePrefix("10.128.0.0/9"),
			netip.MustParsePrefix("fd12:a3a7:1986:1::/64"),
		},
	}
	requestID := postEnroll(t, srv.URL, created.ID, req, req.MAC("shared"))

	entry, err := robert.Approve(ctx, requestID, nil, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Record.Kind != hub.KindConnector {
		t.Fatalf("the connector was recorded as %q", entry.Record.Kind)
	}

	// The route table now carries what the connector offered.
	table, err := robert.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Both families were signed, which only works because the instance holds
	// an address of each: nebula refuses an unsafe network otherwise.
	if len(table.Routes) != 2 {
		t.Fatalf("route table is %v", table.Routes)
	}
	if !entry.Address.Addr().Is4() || !entry.Record.OverlayAddress6.Addr().Is6() {
		t.Fatalf("the connector got %s and %s", entry.Address, entry.Record.OverlayAddress6)
	}
	for _, r := range table.Routes {
		if r.Prefix.Addr().Is4() && r.Prefix.String() != "10.128.0.0/9" {
			t.Fatalf("route table is %v", table.Routes)
		}
	}
	if table.Routes[0].Via != entry.Address.Addr() {
		t.Fatalf("route points at %s, want the connector at %s", table.Routes[0].Via, entry.Address.Addr())
	}

	// Jacek registers his own machine and asks to be let in.
	jacek := daemonFor(t, ctx, dir, "jacek", srv.URL, jacekKey, log)

	if _, err := jacek.hub.routes(ctx, created.ID); err == nil {
		t.Fatal("a stranger read the route table")
	}

	if err := jacek.Connect(ctx, created.ID); err != nil {
		t.Fatal(err)
	}

	pending, err := robert.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Record.Kind != hub.KindTenant {
		t.Fatalf("robert sees %d pending, want one tenant", len(pending))
	}
	if pending[0].Record.Binder != "jacek" {
		t.Fatalf("the request says binder %q, want jacek attested by the hub", pending[0].Record.Binder)
	}

	if _, err := robert.Approve(ctx, pending[0].Record.ID, nil, false, ""); err != nil {
		t.Fatal(err)
	}

	// Jacek collects his certificate and reads the same table.
	conn, _ := jacek.state.Connection(created.ID)
	if err := jacek.collect(ctx, conn); err != nil {
		t.Fatal(err)
	}

	conn, _ = jacek.state.Connection(created.ID)
	if !conn.Ready() {
		t.Fatal("jacek has no certificate after being admitted")
	}

	issued, _, err := cert.UnmarshalCertificateFromPEM([]byte(conn.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.UnsafeNetworks()) != 0 {
		t.Fatalf("a tenant was given routes to carry: %v", issued.UnsafeNetworks())
	}

	pool, err := cert.NewCAPoolFromPEM([]byte(conn.CA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), issued); err != nil {
		t.Fatalf("jacek's certificate does not verify under the owner's authority: %s", err)
	}

	jacekTable, err := jacek.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jacekTable.Routes) != 2 {
		t.Fatalf("jacek sees %d routes, want both of the connector's", len(jacekTable.Routes))
	}

	// An owner cannot ask to be let into its own instance: it is already in
	// it, and enrolling would leave it deciding about itself.
	if err := robert.Connect(ctx, created.ID); err != nil {
		t.Fatalf("rejoining an owned instance failed: %v", err)
	}
	if conn, ok := robert.state.Connection(created.ID); !ok || conn.Role != hub.KindOwner {
		t.Fatal("rejoining produced something other than the owner's own connection")
	}

	waiting, err := robert.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range waiting {
		if p.Record.Kind == hub.KindTenant {
			t.Fatal("the owner ended up waiting for its own approval")
		}
	}

	// Deleting is the owner's alone: jacek is a member and may not.
	if _, err := jacek.Delete(ctx, created.ID, true); err == nil {
		t.Fatal("a member deleted somebody else's instance")
	}

	// And it refuses while others are inside, unless told twice.
	if _, err := robert.Delete(ctx, created.ID, false); err == nil {
		t.Fatal("an instance with members was deleted without --force")
	}

	// Removing a member that is not banned is refused: its certificate stays
	// good for the address that would be freed, and the next member admitted
	// would be handed an address something is already using.
	if _, err := robert.RemoveMember(ctx, BanRequest{Member: "railway"}); err == nil {
		t.Fatal("a member that was not banned was removed, freeing an address its certificate still covers")
	}

	// Banning the connector takes the route away from everybody at once,
	// without reissuing anything.
	if err := robert.Ban(ctx, BanRequest{Member: "railway", Note: "suspected"}); err != nil {
		t.Fatal(err)
	}

	jacekTable, err = jacek.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jacekTable.Routes) != 0 {
		t.Fatalf("a banned connector still carries %v", jacekTable.Routes)
	}
	if len(jacekTable.Blocked) != 1 {
		t.Fatalf("a ban put %d certificates on the blocklist, want one", len(jacekTable.Blocked))
	}
	blockedByBan := jacekTable.Blocked[0]

	// And unbanning puts it back, without anything being reissued.
	if err := robert.Unban(ctx, BanRequest{Member: "railway", Note: "cleared"}); err != nil {
		t.Fatal(err)
	}
	jacekTable, err = jacek.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jacekTable.Routes) != 2 || len(jacekTable.Blocked) != 0 {
		t.Fatalf("after unbanning, %d routes and %d blocked", len(jacekTable.Routes), len(jacekTable.Blocked))
	}

	// Banned again and then removed: the record goes, and the certificate stays
	// refused by everybody. Losing the blocklist entry along with the record is
	// what removing a banned member used to be refused for.
	if err := robert.Ban(ctx, BanRequest{Member: "railway", Note: "no answer"}); err != nil {
		t.Fatal(err)
	}
	removed, err := robert.RemoveMember(ctx, BanRequest{Member: "railway"})
	if err != nil {
		t.Fatal(err)
	}

	jacekTable, err = jacek.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jacekTable.Blocked) != 1 || jacekTable.Blocked[0] != blockedByBan {
		t.Fatalf("removing a banned member left %v on the blocklist, want %s", jacekTable.Blocked, blockedByBan)
	}

	members, err := robert.Members(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.Member.Fingerprint == removed.Member.Fingerprint {
			t.Fatal("a removed member is still listed")
		}
	}

	// Its key is burned too, so the same machine asking again is refused by the
	// hub rather than put in front of the owner a second time.
	if code := enrollStatus(t, srv.URL, created.ID, req, req.MAC("shared")); code < 300 {
		t.Fatalf("a removed member enrolled again and got %d", code)
	}

	// The owner deletes it, and it is gone for everybody.
	if _, err := robert.Delete(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := jacek.hub.routes(ctx, created.ID); err == nil {
		t.Fatal("the route table of a deleted instance is still readable")
	}
	if _, ok := robert.state.Owned(created.ID); ok {
		t.Fatal("the authority survived the deletion")
	}
}

// TestAmbiguousMemberName covers what a name is and is not. It is unique inside
// one instance, and instances are walked in map order, so a name held in two of
// them would otherwise pick one of them at random.
func TestAmbiguousMemberName(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	robertKey := testKey(t)

	h, err := hub.New(hub.Config{
		NebulaBind:     "127.0.0.1",
		PublicEndpoint: "127.0.0.1",
		PortMin:        21200,
		PortMax:        21210,
		Overlays: []hub.Pool{
			{Prefix: netip.MustParsePrefix("198.19.204.0/22"), Size: 24},
		},
		Token:           "hub-token",
		Binders:         hub.Binders{"robert": {Keys: []ssh.PublicKey{robertKey.PublicKey()}}},
		NoLighthouseTun: true,
		StatePath:       filepath.Join(dir, "hub.json"),
		MTU:             1500,
		Logger:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	robert := daemonFor(t, ctx, dir, "robert", srv.URL, robertKey, log)

	// Two instances of his own, each with a connector called "railway": one
	// name, two members, and nothing about the name says which.
	for _, name := range []string{"first", "second"} {
		created, _, err := robert.Create(ctx, name, "shared")
		if err != nil {
			t.Fatal(err)
		}

		key, _, err := ca.GenerateHostKey()
		if err != nil {
			t.Fatal(err)
		}
		req := enroll.Request{
			PublicKey: string(key),
			Name:      "railway",
			Routes:    []netip.Prefix{netip.MustParsePrefix("10.128.0.0/9")},
		}
		requestID := postEnroll(t, srv.URL, created.ID, req, req.MAC("shared"))
		if _, err := robert.Approve(ctx, requestID, nil, false, ""); err != nil {
			t.Fatal(err)
		}
	}

	err = robert.Ban(ctx, BanRequest{Member: "railway", Note: "which one"})
	if err == nil {
		t.Fatal("a name held by two instances was banned in whichever came first")
	}
	if !strings.Contains(err.Error(), "--instance") {
		t.Fatalf("the refusal does not say how to resolve it: %s", err)
	}

	// Named, it is not ambiguous at all.
	if err := robert.Ban(ctx, BanRequest{Member: "railway", Instance: "second"}); err != nil {
		t.Fatal(err)
	}

	members, err := robert.Members(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.Member.Kind != hub.KindConnector {
			continue
		}
		if want := m.Instance == "second"; m.Member.Banned() != want {
			t.Fatalf("the connector in %s is banned=%v", m.Instance, m.Member.Banned())
		}
	}
}

// TestSharedTokenRotation covers what replacing a token does and, more to the
// point, what it does not: enrollment is the only thing authenticated with it,
// so an admitted connector is untouched.
func TestSharedTokenRotation(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	robertKey := testKey(t)

	h, err := hub.New(hub.Config{
		NebulaBind:     "127.0.0.1",
		PublicEndpoint: "127.0.0.1",
		PortMin:        21300,
		PortMax:        21310,
		Overlays: []hub.Pool{
			{Prefix: netip.MustParsePrefix("198.19.208.0/22"), Size: 24},
		},
		Token:           "hub-token",
		Binders:         hub.Binders{"robert": {Keys: []ssh.PublicKey{robertKey.PublicKey()}}},
		NoLighthouseTun: true,
		StatePath:       filepath.Join(dir, "hub.json"),
		MTU:             1500,
		Logger:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	robert := daemonFor(t, ctx, dir, "robert", srv.URL, robertKey, log)

	created, _, err := robert.Create(ctx, "railway-prod", "first")
	if err != nil {
		t.Fatal(err)
	}

	admittedKey, _, err := ca.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	admitted := enroll.Request{PublicKey: string(admittedKey), Name: "already-in"}
	requestID := postEnroll(t, srv.URL, created.ID, admitted, admitted.MAC("first"))
	if _, err := robert.Approve(ctx, requestID, nil, false, ""); err != nil {
		t.Fatal(err)
	}

	result, err := robert.SetToken(ctx, "railway-prod", "second")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(result.Endpoint, "/second") {
		t.Fatalf("the endpoint to hand out is %s, and does not carry the new token", result.Endpoint)
	}

	// The one already inside is untouched: it holds a certificate and never
	// presents a token again.
	members, err := robert.Members(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range members {
		if m.Member.Name == "already-in" && !m.Member.Banned() {
			found = true
		}
	}
	if !found {
		t.Fatal("replacing the token disturbed a member that was already admitted")
	}

	// A new connector with the endpoint handed out before is turned away.
	nextKey, _, err := ca.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	next := enroll.Request{PublicKey: string(nextKey), Name: "later"}

	if code := enrollStatus(t, srv.URL, created.ID, next, next.MAC("first")); code < 300 {
		t.Fatalf("the old token still enrolled and got %d", code)
	}
	if code := enrollStatus(t, srv.URL, created.ID, next, next.MAC("second")); code >= 300 {
		t.Fatalf("the new token was refused with %d", code)
	}
}

// daemonFor registers a machine and returns its daemon.
func daemonFor(t *testing.T, ctx context.Context, dir, name, hubURL string, key ssh.Signer, log *slog.Logger) *Daemon {
	t.Helper()

	state, err := OpenState(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Join(ctx, state, JoinOptions{
		HubURL: hubURL,
		Token:  "hub-token",
		Name:   name,
		Signer: key,
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	d, err := NewDaemon(state, log)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// enrollStatus posts an enrollment and reports the status, for the cases where
// being turned away is the thing under test.
func enrollStatus(t *testing.T, base, instance string, req enroll.Request, mac string) int {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, base+"/v1/enroll/"+instance, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(enroll.MACHeader, mac)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

func postEnroll(t *testing.T, base, instance string, req enroll.Request, mac string) string {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, base+"/v1/enroll/"+instance, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(enroll.MACHeader, mac)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("enrollment refused: %s %s", resp.Status, raw)
	}

	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

// TestBootstrapRejections keeps the two ways in shut.
func TestBootstrapRejections(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	known := testKey(t)
	stranger := testKey(t)

	h, err := hub.New(hub.Config{
		NebulaBind:     "127.0.0.1",
		PublicEndpoint: "127.0.0.1",
		PortMin:        21200,
		PortMax:        21210,
		Overlays: []hub.Pool{
			{Prefix: netip.MustParsePrefix("198.19.210.0/22"), Size: 24},
		},
		Token:           "hub-token",
		Binders:         hub.Binders{"robert": {Keys: []ssh.PublicKey{known.PublicKey()}}},
		NoLighthouseTun: true,
		StatePath:       filepath.Join(dir, "hub.json"),
		Logger:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx := context.Background()

	// A valid signature from a key the hub does not know.
	state, _ := OpenState(filepath.Join(dir, "stranger.json"))
	_, err = Join(ctx, state, JoinOptions{HubURL: srv.URL, Token: "hub-token", Name: "stranger", Signer: stranger}, log)
	if err == nil {
		t.Fatal("an unknown ssh key registered")
	}

	// The right key with the wrong token.
	state, _ = OpenState(filepath.Join(dir, "wrong.json"))
	_, err = Join(ctx, state, JoinOptions{HubURL: srv.URL, Token: "not-the-token", Name: "robert", Signer: known}, log)
	if err == nil {
		t.Fatal("a bootstrap with the wrong token was accepted")
	}
}
