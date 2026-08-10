package hub

import "strings"

// CertSuffix is the domain a certificate's name lives in.
//
// It is deliberately not the domain a resolver answers services under. Two
// parallel trees: .instance is who somebody is, and .robinet is what can be
// reached through them. A name in one is never a name in the other, so nothing
// has to guess which side should answer.
const CertSuffix = "instance"

// LighthouseCertName names the one certificate an instance issues to itself.
//
// No kind label, because there is exactly one and it is not a member: it is the
// instance.
func LighthouseCertName(instance string) string {
	return "hub." + instance + "." + CertSuffix
}

// MemberCertName is <name>.<kind>.<instance>.instance.
//
// The kind sits between the two, so a connector and a machine may carry the
// same name without ever meaning the same certificate.
func MemberCertName(kind, name, instance string) string {
	return name + "." + certKind(kind) + "." + instance + "." + CertSuffix
}

// certKind is the label a kind contributes. An owner is a machine like any
// other tenant - what it may decide is a matter for the hub, not for a name.
func certKind(kind string) string {
	if kind == KindConnector {
		return KindConnector
	}
	return KindTenant
}

// FoldLabel forces whatever a machine happens to be called into a single label.
//
// Unlike a name somebody chose, this one is not up for discussion: a machine
// registered as mara@studio.lan has to appear in a certificate regardless, so
// anything outside a label's alphabet becomes a hyphen rather than a refusal.
//
// A name written in another script therefore does not survive it, and what is
// left of it is what appears. That is the price of never refusing; a machine
// that would rather be called something else can be registered under a name of
// its own.
func FoldLabel(raw string) string {
	var b strings.Builder

	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}

	name := strings.Trim(b.String(), "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	if len(name) > MaxNameLength {
		name = strings.Trim(name[:MaxNameLength], "-")
	}

	if name == "" {
		return "node"
	}

	return name
}
