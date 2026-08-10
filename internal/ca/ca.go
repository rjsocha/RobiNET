// Package ca is the tenant's certificate authority.
//
// The signing key is created here and never leaves the machine that created it.
// The hub carries certificates but can never produce one.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// DefaultCADuration is how long a generated authority lives. Nebula rejects
// every certificate under an expired authority regardless of the certificate's
// own validity, so this has to outlive everything it signs.
const DefaultCADuration = 20 * 365 * 24 * time.Hour

// DefaultCertDuration is how long an issued certificate lives. robinet signs
// once and never refreshes, so this is deliberately long.
const DefaultCertDuration = 10 * 365 * 24 * time.Hour

// CA signs certificates for one instance.
type CA struct {
	cert cert.Certificate
	key  []byte
}

// Generate creates a new authority. It returns the CA and its PEM encoded
// certificate and signing key. The key is the caller's to protect.
func Generate(name string, networks []netip.Prefix, duration time.Duration) (_ *CA, certPEM, keyPEM []byte, _ error) {
	if duration <= 0 {
		duration = DefaultCADuration
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not generate a signing key: %w", err)
	}

	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		Networks:  networks,
		NotBefore: now,
		NotAfter:  now.Add(duration),
		PublicKey: pub,
		IsCA:      true,
		Curve:     cert.Curve_CURVE25519,
	}

	c, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not self sign the authority: %w", err)
	}

	certPEM, err = c.MarshalPEM()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not encode the authority: %w", err)
	}

	return &CA{cert: c, key: priv}, certPEM, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv), nil
}

// Load reads an authority from its PEM encoded certificate and signing key.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("could not read the authority certificate: %w", err)
	}
	if !c.IsCA() {
		return nil, fmt.Errorf("%s is not a certificate authority", c.Name())
	}

	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("could not read the signing key: %w", err)
	}
	if curve != c.Curve() {
		return nil, fmt.Errorf("the signing key curve does not match the certificate")
	}
	if err := c.VerifyPrivateKey(curve, key); err != nil {
		return nil, fmt.Errorf("the signing key does not belong to this certificate: %w", err)
	}

	return &CA{cert: c, key: key}, nil
}

// Certificate returns the authority's own certificate.
func (ca *CA) Certificate() cert.Certificate { return ca.cert }

// CertificatePEM returns the authority certificate, which every member needs.
func (ca *CA) CertificatePEM() ([]byte, error) { return ca.cert.MarshalPEM() }

// Host describes a certificate to issue.
type Host struct {
	// Name is what shows up in logs on both sides.
	Name string

	// PublicKeyPEM is the member's public key. Only the public half is ever
	// sent to us.
	PublicKeyPEM []byte

	// Networks are the overlay addresses assigned to this member.
	Networks []netip.Prefix

	// UnsafeNetworks are the prefixes this member carries traffic for. Nebula
	// refuses a certificate whose unsafe networks include a family the member
	// has no overlay address for.
	UnsafeNetworks []netip.Prefix

	Groups []string

	// Duration defaults to DefaultCertDuration and is clamped to the authority.
	Duration time.Duration
}

// Sign issues a certificate. The result is PEM encoded and ready to hand back.
func (ca *CA) Sign(h Host) ([]byte, error) {
	pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM(h.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("could not read the public key: %w", err)
	}
	if curve != ca.cert.Curve() {
		return nil, fmt.Errorf("the public key curve does not match the authority")
	}

	duration := h.Duration
	if duration <= 0 {
		duration = DefaultCertDuration
	}

	now := time.Now()
	notAfter := now.Add(duration)
	if notAfter.After(ca.cert.NotAfter()) {
		// A certificate outliving its authority is worthless, nebula checks the
		// authority's expiry separately.
		notAfter = ca.cert.NotAfter()
	}

	tbs := &cert.TBSCertificate{
		Version:        cert.Version2,
		Name:           h.Name,
		Networks:       h.Networks,
		UnsafeNetworks: h.UnsafeNetworks,
		Groups:         h.Groups,
		NotBefore:      now,
		NotAfter:       notAfter,
		PublicKey:      pub,
		Curve:          curve,
	}

	c, err := tbs.Sign(ca.cert, curve, ca.key)
	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}

	return c.MarshalPEM()
}
