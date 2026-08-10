// Package variant carries a configuration baked into the binary at link time.
//
// A variant exists so a group of people can be handed a binary that already
// knows which hub to talk to and what its token is, and run one command
// instead of copying a url and a secret out of a message. It changes nothing
// about who may do what: the ssh key still decides, and the owner of an
// instance still approves.
package variant

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
)

// Name is the variant this binary was built as, empty for a plain build.
var Name string

// Encoded is the variant configuration, base64 of the json file. Set with -X
// at link time, because a build flag is the one place a value can be fixed
// without a file having to exist next to the binary.
var Encoded string

// Config is what a variant can preset. Everything here is a default: a flag
// on the command line always wins.
type Config struct {
	// Hub is the base url of the hub this binary is meant for.
	Hub string `json:"hub"`

	// Token is the hub's registry token. It is not a secret in the sense of a
	// key: it proves knowledge, and knowing it grants nothing on its own.
	Token string `json:"token"`

	// Insecure skips verification of the hub's TLS certificate, which is the
	// normal case for a hub with a self signed one. Pin is the better answer:
	// with it, the hub is verified against one public key rather than against
	// nothing.
	Insecure bool   `json:"insecure,omitempty"`
	Pin      string `json:"pin,omitempty"`

	// Note is shown once at registration, for whatever the person handing out
	// this binary wants to say.
	Note string `json:"note,omitempty"`
}

var (
	once   sync.Once
	parsed *Config
)

// Load returns the baked in configuration, if this is a variant build.
func Load() (*Config, bool) {
	once.Do(func() {
		if strings.TrimSpace(Encoded) == "" {
			return
		}

		raw, err := base64.StdEncoding.DecodeString(Encoded)
		if err != nil {
			return
		}

		var cfg Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return
		}
		parsed = &cfg
	})

	return parsed, parsed != nil
}

// String describes the variant for the version output.
func String() string {
	if Name == "" {
		return ""
	}

	cfg, ok := Load()
	if !ok {
		return Name + " (no configuration baked in)"
	}
	return Name + " (" + cfg.Hub + ")"
}
