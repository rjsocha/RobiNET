// Package pin verifies a TLS peer by the hash of its public key.
//
// A hub usually presents a certificate it signed itself, which no certificate
// authority vouches for, so the only options were trusting it blindly or
// getting a real certificate for it. Pinning is the third: whoever hands out a
// binary or a link puts the hash of the hub's public key in it, and a
// connection to anything else fails.
//
// The public key rather than the certificate, so the hub can renew its
// certificate without every member being handed a new pin.
package pin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// Prefix is what a pin is written with, the same form HPKP and curl use.
const Prefix = "sha256/"

// Of renders the pin for a certificate: base64 of the sha256 of its
// SubjectPublicKeyInfo.
func Of(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Prefix + base64.StdEncoding.EncodeToString(sum[:])
}

// Parse checks a pin is well formed and returns it without its prefix.
func Parse(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("a pin cannot be empty")
	}

	value = strings.TrimPrefix(value, Prefix)

	sum, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("pin %q is not base64: %w", raw, err)
	}
	if len(sum) != sha256.Size {
		return "", fmt.Errorf("pin %q is %d bytes, wanted %d", raw, len(sum), sha256.Size)
	}

	return value, nil
}

// TLSConfig verifies the peer against a pin and nothing else.
//
// Certificate chain verification is turned off deliberately rather than by
// accident: a pin is a stronger statement than a chain, since it names one key
// instead of trusting anybody a certificate authority would vouch for. Dates
// are not checked either, for the same reason - an expiry is a statement by an
// authority that has no say here.
func TLSConfig(raw string) (*tls.Config, error) {
	want, err := Parse(raw)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range rawCerts {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				if strings.TrimPrefix(Of(cert), Prefix) == want {
					return nil
				}
			}
			return fmt.Errorf("the hub's public key does not match the pin this binary carries")
		},
	}, nil
}
