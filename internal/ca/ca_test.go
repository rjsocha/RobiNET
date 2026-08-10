package ca

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

func TestSignedCertificateVerifies(t *testing.T) {
	overlay := netip.MustParsePrefix("198.19.200.0/24")

	authority, caPEM, caKeyPEM, err := Generate("robinet-test", []netip.Prefix{overlay}, 0)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, _, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := authority.Sign(Host{
		Name:           "connector",
		PublicKeyPEM:   pubPEM,
		Networks:       []netip.Prefix{netip.MustParsePrefix("198.19.200.10/24")},
		UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("10.128.0.0/9")},
	})
	if err != nil {
		t.Fatal(err)
	}

	pool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}

	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	cached, err := pool.VerifyCertificate(time.Now(), c)
	if err != nil {
		t.Fatalf("the issued certificate does not verify: %s", err)
	}
	if cached.Certificate.Name() != "connector" {
		t.Fatalf("got name %q", cached.Certificate.Name())
	}

	// Reloading the authority from disk must produce the same signer.
	reloaded, err := Load(caPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Sign(Host{
		Name:         "second",
		PublicKeyPEM: pubPEM,
		Networks:     []netip.Prefix{netip.MustParsePrefix("198.19.200.11/24")},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateNeverOutlivesAuthority(t *testing.T) {
	overlay := netip.MustParsePrefix("198.19.200.0/24")

	authority, _, _, err := Generate("robinet-test", []netip.Prefix{overlay}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, _, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := authority.Sign(Host{
		Name:         "connector",
		PublicKeyPEM: pubPEM,
		Networks:     []netip.Prefix{netip.MustParsePrefix("198.19.200.10/24")},
		Duration:     DefaultCertDuration,
	})
	if err != nil {
		t.Fatal(err)
	}

	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	if c.NotAfter().After(authority.Certificate().NotAfter()) {
		t.Fatal("the issued certificate outlives its authority, nebula would reject it once the authority expires")
	}
}

func TestUnsafeNetworkNeedsMatchingFamily(t *testing.T) {
	// Nebula refuses an IPv6 unsafe network unless the certificate also has an
	// IPv6 overlay address. This is why the Railway IPv6 prefix cannot be
	// carried by an IPv4 only instance.
	overlay := netip.MustParsePrefix("198.19.200.0/24")

	authority, _, _, err := Generate("robinet-test", []netip.Prefix{overlay}, 0)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, _, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = authority.Sign(Host{
		Name:           "connector",
		PublicKeyPEM:   pubPEM,
		Networks:       []netip.Prefix{netip.MustParsePrefix("198.19.200.10/24")},
		UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("fd12::/16")},
	})
	if err == nil {
		t.Fatal("expected nebula to refuse an IPv6 unsafe network without an IPv6 address")
	}
}
