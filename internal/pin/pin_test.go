package pin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

// A pin that cannot be parsed must stop a connection rather than quietly
// becoming no verification at all.
func TestABadPinIsRefusedRatherThanIgnored(t *testing.T) {
	var cfg *tls.Config
	cfg, err := TLSConfig("nonsense")
	if err == nil {
		t.Fatalf("a bad pin produced a config: %+v", cfg)
	}
}
