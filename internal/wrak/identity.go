package wrak

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Identity is a machine's own key, minted at enrollment and used for every
// request afterwards. It is not an ssh key: the ssh key proves who may enroll,
// this proves which machine is calling.
type Identity struct {
	private ed25519.PrivateKey
}

// IdentityPrefix is how a public identity is written on the wire.
const IdentityPrefix = "ed25519:"

// NewIdentity mints a machine identity.
func NewIdentity() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{private: priv}, nil
}

// ParseIdentity reads a private identity back from storage.
func ParseIdentity(encoded string) (*Identity, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("malformed identity key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity key is %d bytes, expected %d", len(raw), ed25519.PrivateKeySize)
	}

	return &Identity{private: ed25519.PrivateKey(raw)}, nil
}

// Private renders the identity for storage. Treat it as a secret.
func (i *Identity) Private() string {
	return base64.RawURLEncoding.EncodeToString(i.private)
}

// Public renders the identity the way it appears on the wire.
func (i *Identity) Public() string {
	return PublicIdentity(i.private.Public().(ed25519.PublicKey))
}

// PublicIdentity formats a public key as ed25519:<base64url>.
func PublicIdentity(pub ed25519.PublicKey) string {
	return IdentityPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// ParsePublicIdentity reads the wire form back.
func ParsePublicIdentity(s string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(s, IdentityPrefix)
	if !ok {
		return nil, fmt.Errorf("identity %q does not start with %s", s, IdentityPrefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("malformed identity: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(raw), nil
}

// Request headers. Four, so a proxy that drops unknown headers breaks loudly
// rather than quietly letting an unsigned request through.
const (
	HeaderIdentity  = "Wrak-Identity"
	HeaderTimestamp = "Wrak-Timestamp"
	HeaderNonce     = "Wrak-Nonce"
	HeaderSignature = "Wrak-Signature"
)

// Window is how far apart the two clocks may be.
const Window = 5 * time.Minute

// canonicalRequest is the exact string both sides sign over.
//
// Everything that decides what the request does is in here: the host it was
// sent to, the method, the path, the query in a fixed order and the body. A
// signature therefore cannot be moved to another endpoint, another host or
// another payload.
func canonicalRequest(host, method, path string, query url.Values, body []byte, timestamp, nonce string) string {
	pairs := make([]string, 0, len(query))
	for key, values := range query {
		for _, value := range values {
			pairs = append(pairs, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}
	sort.Strings(pairs)

	sum := sha256.Sum256(body)

	var b strings.Builder
	b.WriteString("wrak/v1/request\n")
	b.WriteString("host=" + strings.ToLower(host) + "\n")
	b.WriteString("method=" + strings.ToUpper(method) + "\n")
	b.WriteString("path=" + path + "\n")
	b.WriteString("query=" + strings.Join(pairs, "&") + "\n")
	b.WriteString("body_sha256=" + hex.EncodeToString(sum[:]) + "\n")
	b.WriteString("timestamp=" + timestamp + "\n")
	b.WriteString("nonce=" + nonce + "\n")

	return b.String()
}

// SignRequest attaches the four headers to a request. Body is what will be
// sent, so the caller keeps it rather than draining it.
func (i *Identity) SignRequest(r *http.Request, body []byte) error {
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		return err
	}

	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	timestamp := time.Now().UTC().Format(time.RFC3339)

	canonical := canonicalRequest(r.Host, r.Method, r.URL.Path, r.URL.Query(), body, timestamp, nonce)
	signature := ed25519.Sign(i.private, []byte(canonical))

	r.Header.Set(HeaderIdentity, i.Public())
	r.Header.Set(HeaderTimestamp, timestamp)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(signature))

	return nil
}

// VerifyRequest checks the signature of an incoming request and returns the
// identity that made it.
//
// It does not say whether that identity may do anything, only that the request
// really came from it, unaltered, recently, and once.
func VerifyRequest(r *http.Request, body []byte, seen NonceStore) (string, error) {
	identity := r.Header.Get(HeaderIdentity)
	timestamp := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	signature := r.Header.Get(HeaderSignature)

	if identity == "" || timestamp == "" || nonce == "" || signature == "" {
		return "", fmt.Errorf("request is not signed")
	}

	pub, err := ParsePublicIdentity(identity)
	if err != nil {
		return "", err
	}

	when, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return "", fmt.Errorf("malformed timestamp: %w", err)
	}
	if drift := time.Since(when); drift > Window || drift < -Window {
		return "", fmt.Errorf("timestamp is %s away, outside the %s window", drift.Round(time.Second), Window)
	}

	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", fmt.Errorf("malformed signature: %w", err)
	}

	canonical := canonicalRequest(r.Host, r.Method, r.URL.Path, r.URL.Query(), body, timestamp, nonce)
	if !ed25519.Verify(pub, []byte(canonical), raw) {
		return "", fmt.Errorf("signature does not verify")
	}

	// Only now, once the signature is known good, does the nonce get spent.
	// Otherwise anyone could burn nonces for someone else.
	if seen != nil && !seen.Use(identity, nonce, Window) {
		return "", fmt.Errorf("nonce has already been used")
	}

	return identity, nil
}

// ConstantTimeEqual compares two secrets without leaking where they differ.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
