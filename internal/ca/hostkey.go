package ca

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/slackhq/nebula/cert"
)

// GenerateHostKey creates a member keypair. The connector calls this on first
// start and sends only the public half to the hub.
func GenerateHostKey() (pubPEM, keyPEM []byte, _ error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate a host key: %w", err)
	}

	return cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, key.PublicKey().Bytes()),
		cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, key.Bytes()),
		nil
}
