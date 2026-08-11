package pin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAPinMatchesOnlyItsOwnKey(t *testing.T) {
	hub := selfSigned(t)
	other := selfSigned(t)

	cfg, err := TLSConfig(Of(hub))
	if err != nil {
		t.Fatal(err)
	}

	if err := cfg.VerifyPeerCertificate([][]byte{hub.Raw}, nil); err != nil {
		t.Fatalf("the hub was refused by its own pin: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{other.Raw}, nil); err == nil {
		t.Fatal("a different key was accepted")
	}
}

// Written either way, since a pin is copied out of whatever produced it.
func TestThePrefixIsOptional(t *testing.T) {
	hub := selfSigned(t)
	full := Of(hub)
	bare := strings.TrimPrefix(full, Prefix)

	for _, form := range []string{full, bare, "  " + full + "  "} {
		if _, err := Parse(form); err != nil {
			t.Errorf("%q: %v", form, err)
		}
	}

	for _, bad := range []string{"", "sha256/not-base64!", "sha256/YWJj"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The same key written the old way and the new way is the same pin. Machines
// that joined before the notation changed carry the old one, and nothing was
// reissued for them.
func TestBothNotationsNameTheSameKey(t *testing.T) {
	hub := selfSigned(t)

	sum := sha256.Sum256(hub.RawSubjectPublicKeyInfo)
	legacy := "sha256/" + base64.StdEncoding.EncodeToString(sum[:])

	cfg, err := TLSConfig(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{hub.Raw}, nil); err != nil {
		t.Fatalf("a pin in the old notation refused its own key: %v", err)
	}

	// And the prefix says nothing about the alphabet: whichever is written,
	// whatever it is written after, decodes to the same hash.
	for _, form := range []string{
		legacy,
		"sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]),
		"SHA256:" + base64.StdEncoding.EncodeToString(sum[:]),
		base64.RawURLEncoding.EncodeToString(sum[:]),
	} {
		got, err := Parse(form)
		if err != nil {
			t.Fatalf("%q: %v", form, err)
		}
		if !bytes.Equal(got, sum[:]) {
			t.Errorf("%q parsed to a different hash", form)
		}
	}
}

// The whole reason for the current notation: a pin travels inside an endpoint
// that is split on "/", so it must not contain one however it was written
// before.
func TestARewrittenPinFitsInAnEndpoint(t *testing.T) {
	hub := selfSigned(t)
	sum := sha256.Sum256(hub.RawSubjectPublicKeyInfo)

	for _, form := range []string{
		Of(hub),
		"sha256/" + base64.StdEncoding.EncodeToString(sum[:]),
		base64.StdEncoding.EncodeToString(sum[:]),
	} {
		got, err := Rewritten(form)
		if err != nil {
			t.Fatalf("%q: %v", form, err)
		}
		if strings.ContainsAny(got, "/+=") {
			t.Errorf("%q was rewritten as %q, which an endpoint cannot carry", form, got)
		}
		if !Written(got) {
			t.Errorf("%q was rewritten as %q, which is not recognizable as a pin", form, got)
		}

		back, err := Parse(got)
		if err != nil || !bytes.Equal(back, sum[:]) {
			t.Errorf("%q did not survive being rewritten", form)
		}
	}
}

// A pin that cannot be parsed must stop a connection rather than quietly
// becoming no verification at all.
func TestABadPinIsRefusedRatherThanIgnored(t *testing.T) {
	var cfg *tls.Config
	cfg, err := TLSConfig("nonsense")
	if err == nil {
		t.Fatalf("a bad pin produced a config: %+v", cfg)
	}
}
