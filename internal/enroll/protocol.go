// Package enroll defines the wire protocol between the three roles.
//
// A connector posts an enrollment request to the hub and polls for the result.
// The hub stores the request and hands it to the tenant, which decides locally
// and posts back a signed certificate. The hub never signs anything and never
// decides anything.
package enroll

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Status of an enrollment request.
type Status string

const (
	// StatusPending means nobody has looked at it yet.
	StatusPending Status = "pending"
	// StatusApproved means a certificate is waiting to be collected.
	StatusApproved Status = "approved"
	// StatusRejected means the tenant refused. A connector that restarts will
	// submit again, which is deliberate.
	StatusRejected Status = "rejected"
)

// MACHeader carries the request authentication code when a shared token is in
// use. Without a token the hub could swap the public key in a pending request
// and have the tenant sign a certificate for someone else.
const MACHeader = "Robinet-Mac"

// Request is what a connector asks for. Everything here is public by nature,
// which is why the hub may carry it.
type Request struct {
	// PublicKey is the connector's nebula public key, PEM encoded. The private
	// half never leaves the connector.
	PublicKey string `json:"public_key"`

	// Name is a label chosen by the operator of the connector. Not trusted,
	// not unique, shown in the panel.
	Name string `json:"name,omitempty"`

	// Routes are the prefixes this connector offers to carry traffic for.
	Routes []netip.Prefix `json:"routes,omitempty"`

	// Domains are the names it can resolve, using the resolver of the network
	// it sits in. A prefix says where to send packets; this says what to call
	// the things there, which is what anybody actually types.
	Domains []string `json:"domains,omitempty"`

	// Hints help a human recognize the request. Environment variables of a
	// known provider, the hostname, whatever the connector could detect. Purely
	// for display, never used for matching.
	Hints map[string]string `json:"hints,omitempty"`
}

// Canonical renders a request as the bytes covered by the MAC. Field order is
// fixed and independent of JSON encoding.
func (r *Request) Canonical() []byte {
	var b strings.Builder

	b.WriteString("robinet/v1/enroll\n")
	b.WriteString("public_key=" + normalizePEM(r.PublicKey) + "\n")
	b.WriteString("name=" + r.Name + "\n")

	routes := make([]string, 0, len(r.Routes))
	for _, p := range r.Routes {
		routes = append(routes, p.String())
	}
	slices.Sort(routes)
	b.WriteString("routes=" + strings.Join(routes, ",") + "\n")

	domains := append([]string(nil), r.Domains...)
	slices.Sort(domains)
	b.WriteString("domains=" + strings.Join(domains, ",") + "\n")

	keys := make([]string, 0, len(r.Hints))
	for k := range r.Hints {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		b.WriteString("hint." + k + "=" + r.Hints[k] + "\n")
	}

	return []byte(b.String())
}

// MAC computes the authentication code for a request under a shared token.
func (r *Request) MAC(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(r.Canonical())
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyMAC reports whether mac matches the request under the shared token.
func (r *Request) VerifyMAC(token, mac string) bool {
	want, err := hex.DecodeString(r.MAC(token))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(mac)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// Validate checks a request is well formed enough to be stored.
func (r *Request) Validate() error {
	if strings.TrimSpace(r.PublicKey) == "" {
		return errors.New("public key is missing")
	}
	if len(r.Routes) > 64 {
		return fmt.Errorf("too many routes: %d", len(r.Routes))
	}
	for _, p := range r.Routes {
		if !p.IsValid() {
			return fmt.Errorf("invalid route: %s", p)
		}
		if p.Addr() != p.Masked().Addr() {
			return fmt.Errorf("route %s has bits set outside the prefix", p)
		}
	}
	if len(r.Domains) > 32 {
		return fmt.Errorf("too many domains: %d", len(r.Domains))
	}
	for i, d := range r.Domains {
		name, err := ParseDomain(d)
		if err != nil {
			return err
		}
		r.Domains[i] = name
	}
	if len(r.Hints) > 64 {
		return fmt.Errorf("too many hints: %d", len(r.Hints))
	}
	return nil
}

// ParseDomain checks a domain and returns it in the form it is stored and
// compared in: lower case, no trailing dot.
//
// A domain announced here ends up in a resolver's configuration on somebody
// else's machine, so it is held to what DNS allows rather than to what happens
// to arrive.
func ParseDomain(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return "", errors.New("a domain cannot be empty")
	}
	if len(name) > 253 {
		return "", fmt.Errorf("domain %q is longer than 253 characters", raw)
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return "", fmt.Errorf("domain %q has an empty label", raw)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("domain %q has a label longer than 63 characters", raw)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain %q has a label starting or ending with a hyphen", raw)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return "", fmt.Errorf("domain %q holds %q, which is not a letter, digit or hyphen", raw, string(r))
			}
		}
	}

	return name, nil
}

// Record is a stored request as the hub and the tenant see it.
type Record struct {
	ID      string  `json:"id"`
	Status  Status  `json:"status"`
	Request Request `json:"request"`

	// Fingerprint of the public key. This is the connector's identity, and what
	// reject, forget and ban are keyed on.
	Fingerprint string `json:"fingerprint"`

	// OverlayAddress is allocated by the hub when the request arrives, so the
	// hub stays authoritative over its own pool without signing anything.
	OverlayAddress netip.Prefix `json:"overlay_address"`

	// OverlayAddress6 is the same allocation in IPv6, present when the hub has
	// a pool for it. A certificate carrying it is what lets this member carry
	// an IPv6 route.
	OverlayAddress6 netip.Prefix `json:"overlay_address6,omitempty"`

	// SourceAddr is where the request came from, a display hint.
	SourceAddr string `json:"source_addr,omitempty"`

	ReceivedAt time.Time `json:"received_at"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
}

// Lighthouse tells a connector where to find the mesh.
type Lighthouse struct {
	OverlayAddress netip.Addr `json:"overlay_address"`

	// OverlayAddress6 is the lighthouse's IPv6 address. Members still reach it
	// by its IPv4 one: a host is found by any address its certificate carries,
	// and using one keeps a single entry in every static host map.
	OverlayAddress6 netip.Addr `json:"overlay_address6,omitempty"`

	Endpoints []string `json:"endpoints"`
	Relay     bool     `json:"relay"`
}

// Bundle is everything a connector needs to start, handed over once approved.
type Bundle struct {
	Certificate     string       `json:"certificate"`
	CA              string       `json:"ca"`
	OverlayAddress  netip.Prefix `json:"overlay_address"`
	OverlayAddress6 netip.Prefix `json:"overlay_address6,omitempty"`
	Lighthouse      Lighthouse   `json:"lighthouse"`

	// MTU of the hub's own link, so the connector can take the lower of that
	// and its own minus nebula's overhead.
	MTU uint32 `json:"mtu,omitempty"`

	// Instance is the name the tenant gave this instance, for the log.
	Instance string `json:"instance,omitempty"`

	// Blocked are the certificate fingerprints to refuse. A connector reads no
	// route table, so this is how a ban reaches it.
	Blocked []string `json:"blocked,omitempty"`
}

// Result is what a connector gets while polling.
type Result struct {
	Status Status `json:"status"`

	// RetryAfter is how long the hub wants the connector to wait, in seconds.
	RetryAfter int `json:"retry_after,omitempty"`

	// Bundle is present when Status is approved.
	Bundle *Bundle `json:"bundle,omitempty"`

	// Reason is optional free text for a rejection.
	Reason string `json:"reason,omitempty"`
}

// Decision is what an owner posts back for a pending request.
type Decision struct {
	Status Status  `json:"status"`
	Bundle *Bundle `json:"bundle,omitempty"`
	Reason string  `json:"reason,omitempty"`

	// Name is what the certificate was issued to, which is not always what was
	// asked for: an applicant that asked for nothing is named after its key.
	// The hub records this rather than the request, because the name ends up
	// in a name space people type.
	Name string `json:"name,omitempty"`

	// Routes and Domains are what was granted, which is not always what was
	// asked for: an owner may narrow either, and a route of a family the
	// certificate cannot hold is dropped. The hub records these rather than
	// the request, so the route table says what is true.
	Routes  []netip.Prefix `json:"routes,omitempty"`
	Domains []string       `json:"domains,omitempty"`

	// CertFingerprint identifies the certificate that was issued, which is
	// what a blocklist takes. The hub records it so a ban can be applied
	// without asking the owner what it signed.
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
}

// Error is the shape of every error response.
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message,omitempty"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// normalizePEM strips whitespace differences so a MAC survives re-encoding.
func normalizePEM(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
