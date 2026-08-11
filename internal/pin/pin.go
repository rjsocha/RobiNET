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
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// Prefix is what a pin is written with. The separator is a colon and the
// encoding below is base64url, because a pin travels inside a connector's
// endpoint, which is split on "/": standard base64 contains that character and
// would take the pin apart.
const Prefix = "SHA256:"

// legacyPrefix is the form pins were first written in, still accepted because
// variants and joined machines carry pins recorded that way.
const legacyPrefix = "sha256/"

// Of renders the pin for a certificate: the sha256 of its
// SubjectPublicKeyInfo, base64url without padding.
func Of(cert *x509.Certificate) string {
	sum := sumOf(cert)
	return Prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Rewritten renders a pin in the current notation, whatever it was written in.
//
// A machine that joined before the notation changed has the old form recorded,
// and that form cannot travel in an endpoint. This is how one becomes the
// other without anybody being handed a new pin.
func Rewritten(raw string) (string, error) {
	sum, err := Parse(raw)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(sum), nil
}

// Written reports whether a string is written as a pin.
//
// A connector's endpoint carries an optional token and an optional pin in the
// same place, so which one a trailing part is cannot be read off its position.
// Only the current notation counts here: the old one contains a "/", which the
// endpoint is split on, so it could never have travelled there.
func Written(raw string) bool {
	value := strings.TrimSpace(raw)
	return len(value) >= len(Prefix) && strings.EqualFold(value[:len(Prefix)], Prefix)
}

// Parse checks a pin is well formed and returns the hash it names.
//
// Either prefix is accepted and neither is required, in either case, and both
// base64 alphabets are read: a pin is copied out of whatever produced it, and
// the same key written two ways is the same key.
func Parse(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("a pin cannot be empty")
	}

	for _, p := range []string{Prefix, legacyPrefix} {
		if len(value) >= len(p) && strings.EqualFold(value[:len(p)], p) {
			value = value[len(p):]
			break
		}
	}

	sum, err := decode(value)
	if err != nil {
		return nil, fmt.Errorf("pin %q is not base64: %w", raw, err)
	}
	if len(sum) != sha256.Size {
		return nil, fmt.Errorf("pin %q is %d bytes, wanted %d", raw, len(sum), sha256.Size)
	}

	return sum, nil
}

// decode reads a hash written in either alphabet, padded or not. The two
// differ in two characters, so trying one and falling back to the other
// settles it without having to guess from the content.
func decode(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")

	if sum, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return sum, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
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
				sum := sumOf(cert)
				if bytes.Equal(sum[:], want) {
					return nil
				}
			}
			return fmt.Errorf("the hub's public key does not match the pin this binary carries")
		},
	}, nil
}

func sumOf(cert *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}
