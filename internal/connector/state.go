// Package connector runs inside the private network being exposed. It has no
// tun device and no capabilities: everything happens in a user space stack.
package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
)

// State is the connector's identity and whatever it has been granted.
//
// The key is the identity: reject, forget and ban on the tenant side are keyed
// on its fingerprint, so losing this directory means coming back as a stranger.
type State struct {
	dir string

	PublicKeyPEM  []byte
	PrivateKeyPEM []byte

	RequestID string
	Bundle    *enroll.Bundle
}

const (
	fileKey       = "host.key"
	filePublicKey = "host.pub"
	fileRequest   = "request.id"
	fileBundle    = "bundle.json"
)

// LoadState reads the state directory, generating an identity on first run.
func LoadState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("could not create the state directory: %w", err)
	}

	s := &State{dir: dir}

	key, err := os.ReadFile(filepath.Join(dir, fileKey))
	switch {
	case errors.Is(err, os.ErrNotExist):
		pub, priv, err := ca.GenerateHostKey()
		if err != nil {
			return nil, err
		}
		if err := s.write(fileKey, priv, 0o600); err != nil {
			return nil, err
		}
		if err := s.write(filePublicKey, pub, 0o644); err != nil {
			return nil, err
		}
		s.PublicKeyPEM, s.PrivateKeyPEM = pub, priv

	case err != nil:
		return nil, fmt.Errorf("could not read the host key: %w", err)

	default:
		pub, err := os.ReadFile(filepath.Join(dir, filePublicKey))
		if err != nil {
			return nil, fmt.Errorf("could not read the public key: %w", err)
		}
		s.PrivateKeyPEM, s.PublicKeyPEM = key, pub
	}

	if id, err := os.ReadFile(filepath.Join(dir, fileRequest)); err == nil {
		s.RequestID = string(id)
	}

	if raw, err := os.ReadFile(filepath.Join(dir, fileBundle)); err == nil {
		var b enroll.Bundle
		if err := json.Unmarshal(raw, &b); err == nil {
			s.Bundle = &b
		}
	}

	return s, nil
}

// SaveRequestID remembers which enrollment we are waiting on, so a restart
// keeps polling the same one instead of queueing another.
func (s *State) SaveRequestID(id string) error {
	s.RequestID = id
	return s.write(fileRequest, []byte(id), 0o600)
}

// SaveBundle stores what the tenant granted.
func (s *State) SaveBundle(b *enroll.Bundle) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := s.write(fileBundle, raw, 0o600); err != nil {
		return err
	}
	s.Bundle = b
	return nil
}

// Reset drops the grant but keeps the identity, so the connector enrolls again
// with the same key and the operator recognizes it.
func (s *State) Reset() error {
	s.Bundle = nil
	s.RequestID = ""
	_ = os.Remove(filepath.Join(s.dir, fileBundle))
	_ = os.Remove(filepath.Join(s.dir, fileRequest))
	return nil
}

func (s *State) write(name string, data []byte, mode os.FileMode) error {
	path := filepath.Join(s.dir, name)
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Fingerprint identifies this connector to a human.
func (s *State) Fingerprint() string {
	return fingerprint(string(s.PublicKeyPEM))
}
