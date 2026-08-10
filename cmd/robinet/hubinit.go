package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// writeHubConfig lays down a starter configuration.
//
// The token is generated rather than left as a placeholder, because a
// placeholder is a thing people forget to change. The first binder is filled
// in from the ssh-agent when there is one, since the key that will drive this
// hub is almost always the key of whoever is installing it.
func writeHubConfig(path, endpoint string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists, refusing to overwrite it", path)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tokenRaw := make([]byte, 16)
	if _, err := rand.Read(tokenRaw); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenRaw)

	if endpoint == "" {
		endpoint = "CHANGE-ME"
	}

	pool6, err := randomULA()
	if err != nil {
		return err
	}

	content := fmt.Sprintf(hubConfigTemplate, endpoint, pool6, token)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n\n", path)
	if endpoint == "CHANGE-ME" {
		fmt.Printf("  set public.endpoint to the address connectors will dial\n")
	}
	fmt.Printf("  add at least one binder: a name and the ssh keys that may create instances\n")
	fmt.Printf("  the ipv6 pool is a generated ULA: %s\n", pool6)
	fmt.Printf("  the token is generated, hand it to whoever runs robinet join:\n\n    %s\n", token)

	return nil
}

// randomULA generates a unique local prefix as RFC 4193 asks for one: fd
// followed by a random 40 bit global id, carved into a /112 per instance.
//
// The randomness is the whole point. Two hubs with the same prefix cannot be
// bridged later, and the collisions people hit with unique local addressing
// come from picking a memorable value rather than from 40 bits being too few.
func randomULA() (string, error) {
	raw := make([]byte, 5)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return fmt.Sprintf("fd%02x:%02x%02x:%02x%02x::/48/112",
		raw[0], raw[1], raw[2], raw[3], raw[4]), nil
}

const hubConfigTemplate = `# robinet hub configuration.

public:
  # What connectors dial. No port: each instance gets its own.
  endpoint: %s

  # What nebula binds to for every instance.
  bind: 0.0.0.0

api:
  listen: ":8443"

  # http or https. http is for a hub behind something that terminates TLS
  # already, and means clients need no --insecure because whatever is in front
  # presents a certificate of its own.
  entrypoint: https

  tls:
    # Leave both empty for a self signed certificate, which is enough here: a
    # bootstrap proves knowledge of a token that never travels, every later
    # request is signed, and a certificate the hub carries cannot be forged by
    # whoever carries it. Clients then need --insecure.
    cert: ""
    key: ""

state:
  path: /var/lib/robinet/hub.json

# Address spaces instances are carved out of, each written as superprefix plus
# the size handed to one instance. A /16 carved into /24s gives 256 instances of
# 254 addresses each. Which family an entry is for is read off the prefix.
#
# They are used in order: when one is full the next is tried, so a hub that runs
# out of room takes another line rather than a renumbering. Entries may not
# overlap, since two pools covering the same addresses would hand the same
# prefix out twice.
#
# Every member gets an address of each family that is listed here, and a
# certificate carrying both, which is what nebula requires before it will sign
# a route of either.
#
# The IPv6 pool is generated rather than defaulted to a constant. A unique
# local address needs a random global id to be unique, and a value shared by
# every robinet hub would be exactly what makes two networks impossible to join
# later.
overlays:
  - 198.19.0.0/16/24
  - %s

# UDP ports instances are allocated from, one per instance.
ports: 20000-24999

# This host's link mtu, handed to connectors so they can take the lower of that
# and their own, minus nebula's overhead.
mtu: 1500

# Let a lighthouse carry traffic for members that cannot punch through. Without
# it, a member behind symmetric NAT has no way in.
relay: true

security:
  # Known to every operator who may create an instance here. It goes into the
  # signed bootstrap message and is never transmitted, so a captured signature
  # is worthless without it.
  token: %s

# Who may create instances. A binder is a name and the ssh keys that speak for
# it - the same keys you would put in authorized_keys. The matching private key
# never leaves the operator's agent.
#
# Nothing is filled in here on purpose: which keys may take address space on
# this hub is a decision, not something to be guessed from whoever happened to
# run --init.
#
# Binders can also live one file per operator in /etc/site/robinet/binder,
# which is read by default. A directory that is not there yet is a warning,
# not a refusal.
#
# binder:
#   - name: robert
#     key:
#       - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... robert@laptop"
`
