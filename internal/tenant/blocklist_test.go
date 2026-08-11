package tenant

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
)

// A running connector reads no route table, so the enrollment result is the
// only thing it comes back to and the only way a ban can reach it. Answering
// with the blocklist as it stood when the bundle was signed made that poll a
// loop that could never see anything change.
func TestAConnectorAdmittedBeforeABanStillLearnsOfIt(t *testing.T) {
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

	created, _, err := robert.Create(ctx, "railway-prod", "shared")
	if err != nil {
		t.Fatal(err)
	}

	admit := func(name string, route netip.Prefix) string {
		t.Helper()

		key, _, err := ca.GenerateHostKey()
		if err != nil {
			t.Fatal(err)
		}
		req := enroll.Request{PublicKey: string(key), Name: name, Routes: []netip.Prefix{route}}
		id := postEnroll(t, srv.URL, created.ID, req, req.MAC("shared"))
		if _, err := robert.Approve(ctx, id, nil, false, ""); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// Both are in before anybody is banned, which is what makes this the
	// interesting order: the second one's bundle was signed while the
	// blocklist was empty.
	admit("first", netip.MustParsePrefix("10.1.0.0/16"))
	watching := admit("second", netip.MustParsePrefix("10.2.0.0/16"))

	// What the connector polls, which is the unauthenticated result endpoint.
	poll := func() enroll.Result {
		t.Helper()

		resp, err := http.Get(srv.URL + "/v1/enroll/" + created.ID + "/" + watching)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		var res enroll.Result
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatal(err)
		}
		if res.Bundle == nil {
			t.Fatal("an approved request answered without a bundle")
		}
		return res
	}

	if blocked := poll().Bundle.Blocked; len(blocked) != 0 {
		t.Fatalf("nobody is banned yet, but the connector was told to refuse %v", blocked)
	}

	if err := robert.Ban(ctx, BanRequest{Member: "first", Note: "suspected"}); err != nil {
		t.Fatal(err)
	}

	table, err := robert.hub.routes(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Blocked) != 1 {
		t.Fatalf("the tenant sees %d blocked, want one", len(table.Blocked))
	}

	blocked := poll().Bundle.Blocked
	if len(blocked) != 1 || blocked[0] != table.Blocked[0] {
		t.Fatalf("the connector was told to refuse %v, the tenant refuses %v", blocked, table.Blocked)
	}

	// And unbanning arrives the same way, so a connector is not left refusing
	// somebody who was let back in.
	if err := robert.Unban(ctx, BanRequest{Member: "first", Note: "cleared"}); err != nil {
		t.Fatal(err)
	}
	if blocked := poll().Bundle.Blocked; len(blocked) != 0 {
		t.Fatalf("after unbanning, the connector still refuses %v", blocked)
	}
}
