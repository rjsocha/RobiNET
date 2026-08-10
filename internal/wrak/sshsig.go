// Package wrak implements the WRAK authentication protocol.
//
// Two layers. An ssh key proves, once, that a machine may enroll at all: it
// signs a canonical bootstrap message in OpenSSH's SSHSIG format, which is what
// ssh-keygen -Y sign produces and what an ssh-agent can do without ever
// handing over the key. Afterwards the machine has an ed25519 identity of its
// own and signs every request with it, so the agent is needed exactly once and
// no long lived secret travels on the wire.
//
// This is the same protocol DLG speaks. The wire format is shared; the code is
// not.
package wrak

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// sshsigMagic and sshsigVersion are fixed by OpenSSH's PROTOCOL.sshsig.
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1

	// pemType is what the armored signature is wrapped in.
	pemType = "SSH SIGNATURE"
)

// wrappedSig is the armored signature's payload.
type wrappedSig struct {
	Magic         [6]byte
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

// signedData is what the key actually signs: the message digest, bound to a
// namespace so a signature made for one purpose cannot be replayed as another.
type signedData struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

func (s signedData) marshal() []byte {
	return append([]byte(sshsigMagic), ssh.Marshal(s)...)
}

// hash applies the named algorithm, which OpenSSH restricts to these two.
func hash(algorithm string, message []byte) ([]byte, error) {
	switch algorithm {
	case "sha256":
		sum := sha256.Sum256(message)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(message)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", algorithm)
	}
}

// Signer is anything that can sign for an ssh public key: a key held by an
// agent, or one loaded from a file. This is exactly ssh.Signer.
type Signer = ssh.Signer

// SignSSHSIG produces an armored SSHSIG signature over message.
func SignSSHSIG(signer Signer, namespace string, message []byte) ([]byte, error) {
	const algorithm = "sha512"

	digest, err := hash(algorithm, message)
	if err != nil {
		return nil, err
	}

	blob := signedData{
		Namespace:     namespace,
		HashAlgorithm: algorithm,
		Hash:          string(digest),
	}.marshal()

	sig, err := signer.Sign(rand.Reader, blob)
	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}

	wrapped := wrappedSig{
		Version:       sshsigVersion,
		PublicKey:     string(signer.PublicKey().Marshal()),
		Namespace:     namespace,
		HashAlgorithm: algorithm,
		Signature:     string(ssh.Marshal(sig)),
	}
	copy(wrapped.Magic[:], sshsigMagic)

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: ssh.Marshal(wrapped),
	}), nil
}

// VerifySSHSIG checks an armored signature and returns the key that made it.
//
// The caller decides whether that key is allowed to do anything: this only
// says the signature is genuine and was made for this namespace and message.
func VerifySSHSIG(armored, message []byte, namespace string) (ssh.PublicKey, error) {
	block, _ := pem.Decode(armored)
	if block == nil {
		return nil, fmt.Errorf("not an armored ssh signature")
	}
	if block.Type != pemType {
		return nil, fmt.Errorf("expected %q, got %q", pemType, block.Type)
	}

	var wrapped wrappedSig
	if err := ssh.Unmarshal(block.Bytes, &wrapped); err != nil {
		return nil, fmt.Errorf("malformed ssh signature: %w", err)
	}
	if string(wrapped.Magic[:]) != sshsigMagic {
		return nil, fmt.Errorf("bad signature preamble")
	}
	if wrapped.Version != sshsigVersion {
		return nil, fmt.Errorf("unsupported signature version %d", wrapped.Version)
	}
	if wrapped.Namespace != namespace {
		// A signature made for another purpose must not verify here.
		return nil, fmt.Errorf("signature is for namespace %q, expected %q", wrapped.Namespace, namespace)
	}

	key, err := ssh.ParsePublicKey([]byte(wrapped.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("malformed public key: %w", err)
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal([]byte(wrapped.Signature), &sig); err != nil {
		return nil, fmt.Errorf("malformed signature: %w", err)
	}

	digest, err := hash(wrapped.HashAlgorithm, message)
	if err != nil {
		return nil, err
	}

	blob := signedData{
		Namespace:     wrapped.Namespace,
		HashAlgorithm: wrapped.HashAlgorithm,
		Hash:          string(digest),
	}.marshal()

	if err := key.Verify(blob, &sig); err != nil {
		return nil, fmt.Errorf("signature does not verify: %w", err)
	}

	return key, nil
}

// AuthorizedKey renders a key the way it appears in an authorized_keys file,
// which is how a hub's configuration names who may enroll.
func AuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// SameKey compares two ssh keys by their wire form.
func SameKey(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return base64.StdEncoding.EncodeToString(a.Marshal()) ==
		base64.StdEncoding.EncodeToString(b.Marshal())
}
