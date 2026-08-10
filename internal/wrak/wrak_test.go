package wrak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
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

func TestSSHSIGRoundTrip(t *testing.T) {
	signer := testSigner(t)
	message := []byte("wrak/v1/bootstrap\napi=hub.example\n")

	armored, err := SignSSHSIG(signer, BootstrapNamespace, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(armored, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Fatalf("not armored the way ssh expects:\n%s", armored)
	}

	key, err := VerifySSHSIG(armored, message, BootstrapNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if !SameKey(key, signer.PublicKey()) {
		t.Fatal("verification returned a different key")
	}

	// A signature made for one purpose must not verify as another.
	if _, err := VerifySSHSIG(armored, message, "some-other-namespace"); err == nil {
		t.Fatal("a signature verified under the wrong namespace")
	}

	// Changing the message must break it.
	if _, err := VerifySSHSIG(armored, append(message, '!'), BootstrapNamespace); err == nil {
		t.Fatal("a signature verified over a changed message")
	}
}

// TestSSHSIGInteropWithOpenSSH is the one that matters: our signatures have to
// be the same thing ssh-keygen produces and accepts, otherwise the protocol is
// only compatible with itself.
func TestSSHSIGInteropWithOpenSSH(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")

	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "wrak-test", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %s", out)
	}

	message := []byte("wrak/v1/bootstrap\napi=hub.example\nregistry_token=secret\n")
	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}

	// OpenSSH signs, we verify.
	if out, err := exec.Command(keygen, "-Y", "sign", "-f", keyPath, "-n", BootstrapNamespace, messagePath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %s", out)
	}

	theirs, err := os.ReadFile(messagePath + ".sig")
	if err != nil {
		t.Fatal(err)
	}

	key, err := VerifySSHSIG(theirs, message, BootstrapNamespace)
	if err != nil {
		t.Fatalf("could not verify a signature made by ssh-keygen: %s", err)
	}

	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !SameKey(key, wantKey) {
		t.Fatal("verification returned a key that is not the one that signed")
	}

	// We sign, OpenSSH verifies.
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}

	ours, err := SignSSHSIG(signer, BootstrapNamespace, message)
	if err != nil {
		t.Fatal(err)
	}

	ourSigPath := filepath.Join(dir, "ours.sig")
	if err := os.WriteFile(ourSigPath, ours, 0o600); err != nil {
		t.Fatal(err)
	}

	allowed := filepath.Join(dir, "allowed_signers")
	entry := "wrak-test@example " + AuthorizedKey(wantKey) + "\n"
	if err := os.WriteFile(allowed, []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed,
		"-I", "wrak-test@example", "-n", BootstrapNamespace, "-s", ourSigPath)
	cmd.Stdin = bytes.NewReader(message)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen refused our signature: %s", out)
	}
}

func TestBootstrapVerification(t *testing.T) {
	signer := testSigner(t)

	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	b := Bootstrap{
		API:      "hub.example:8443",
		Token:    "the-token",
		Name:     "railway-prod",
		Identity: identity.Public(),
	}

	armored, err := b.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	authorized := []ssh.PublicKey{signer.PublicKey()}
	if _, err := b.Verify(armored, authorized); err != nil {
		t.Fatal(err)
	}

	// The token never travels, so a hub that knows a different one rebuilds a
	// different message and the signature stops verifying.
	wrongToken := b
	wrongToken.Token = "not-the-token"
	if _, err := wrongToken.Verify(armored, authorized); err == nil {
		t.Fatal("a bootstrap verified against the wrong token")
	}

	// A valid signature from an unlisted key is still refused.
	other := testSigner(t)
	if _, err := b.Verify(armored, []ssh.PublicKey{other.PublicKey()}); err == nil {
		t.Fatal("an unauthorized key was accepted")
	}
}

func TestSignedRequests(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	nonces := NewMemoryNonces()
	body := []byte(`{"name":"railway-prod"}`)

	sign := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://hub.example/v1/instances?scope=all", bytes.NewReader(body))
		if err := identity.SignRequest(r, body); err != nil {
			t.Fatal(err)
		}
		return r
	}

	got, err := VerifyRequest(sign(), body, nonces)
	if err != nil {
		t.Fatal(err)
	}
	if got != identity.Public() {
		t.Fatalf("got identity %s", got)
	}

	// The same request twice is a replay.
	replay := sign()
	if _, err := VerifyRequest(replay, body, nonces); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(replay, body, nonces); err == nil {
		t.Fatal("a replayed request was accepted")
	}

	// A body that changed in flight must not verify.
	if _, err := VerifyRequest(sign(), append(body, ' '), nonces); err == nil {
		t.Fatal("a request verified over a changed body")
	}

	// Nor may a signature be moved to another path.
	moved := sign()
	moved.URL.Path = "/v1/instances/other"
	if _, err := VerifyRequest(moved, body, nonces); err == nil {
		t.Fatal("a signature verified on a different path")
	}

	// Nor to another host.
	elsewhere := sign()
	elsewhere.Host = "evil.example"
	if _, err := VerifyRequest(elsewhere, body, nonces); err == nil {
		t.Fatal("a signature verified against a different host")
	}

	// An old signature falls outside the window.
	stale := sign()
	stale.Header.Set(HeaderTimestamp, time.Now().Add(-2*Window).UTC().Format(time.RFC3339))
	if _, err := VerifyRequest(stale, body, nonces); err == nil {
		t.Fatal("a stale request was accepted")
	}

	// An unsigned request says so plainly.
	plain := httptest.NewRequest(http.MethodGet, "https://hub.example/v1/instances", nil)
	if _, err := VerifyRequest(plain, nil, nonces); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned request gave %v", err)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := ParseIdentity(identity.Private())
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Public() != identity.Public() {
		t.Fatal("an identity did not survive a round trip")
	}

	if _, err := ParsePublicIdentity(identity.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicIdentity("rsa:whatever"); err == nil {
		t.Fatal("a foreign identity format was accepted")
	}
}
