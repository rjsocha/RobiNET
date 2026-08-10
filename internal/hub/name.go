package hub

import (
	"fmt"
	"strings"
)

// MaxNameLength is a DNS label's, because that is what a name becomes.
const MaxNameLength = 63

// ParseName checks a name and returns it in the form it will be stored in.
//
// Instances and members are named by people and then used as identifiers: they
// go into an endpoint a connector is configured with, into a certificate, and
// into the name a resolver will one day answer for. So a name is a DNS label -
// letters, digits and hyphens - and anything else is refused now rather than
// discovered later by whatever cannot hold it.
//
// Case is not refused but folded away. DNS does not distinguish it, so RAILWAY
// and railway would be one name with two spellings, and two spellings of one
// name is the thing this exists to prevent.
func ParseName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))

	switch {
	case name == "":
		return "", fmt.Errorf("a name is required")
	case len(name) > MaxNameLength:
		return "", fmt.Errorf("name %q is longer than %d characters", raw, MaxNameLength)
	case name[0] == '-' || name[len(name)-1] == '-':
		return "", fmt.Errorf("name %q starts or ends with a hyphen", raw)
	}

	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return "", fmt.Errorf("name %q may hold letters, digits and hyphens, not %q", raw, string(r))
		}
	}

	// A name that reads as an address would be ambiguous everywhere one is
	// accepted, and an identifier is sixteen hex characters.
	if len(name) == 16 && isHex(name) {
		return "", fmt.Errorf("name %q looks like an instance id", raw)
	}

	return name, nil
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// ParseMemberName is ParseName for a member, which may be more than one label.
//
// A connector on a platform is best described by two things - the environment
// and the project it runs in - and joining them with a hyphen loses where one
// ends, since a project name may contain hyphens itself. A dot is what DNS
// uses for exactly that, and a member's name is already part of a domain.
func ParseMemberName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return "", fmt.Errorf("a name is required")
	}
	if len(name) > 253 {
		return "", fmt.Errorf("name %q is longer than 253 characters", raw)
	}

	for _, label := range strings.Split(name, ".") {
		if _, err := ParseName(label); err != nil {
			return "", err
		}
	}

	return name, nil
}
