package connector

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/rjsocha/robinet/internal/enroll"
)

func TestHintsSpeakOnePlatformVocabulary(t *testing.T) {
	t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")
	t.Setenv("RAILWAY_PROJECT_NAME", "netprobe")
	t.Setenv("RAILWAY_SERVICE_NAME", "robinet")

	hints := DiscoverHints()

	for key, want := range map[string]string{
		"platform":    "railway",
		"project":     "netprobe",
		"environment": "production",
		"service":     "robinet",
	} {
		if hints[key] != want {
			t.Errorf("hint %s is %q, wanted %q", key, hints[key], want)
		}
	}
}

// Only one platform may claim a connector, whatever else is set: a deployment
// on a managed platform also runs in a container and often in kubernetes.
func TestOnlyTheFirstPlatformClaimsIt(t *testing.T) {
	t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	if got := DiscoverHints()["platform"]; got != "railway" {
		t.Fatalf("platform is %q, wanted railway", got)
	}
}

// Railway hands every project the same IPv4 range and a distinct IPv6 one, so
// announcing the IPv4 range claims something that belongs to everybody.
func TestRailwayDropsTheRangeEverybodyShares(t *testing.T) {
	t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")

	all := []netip.Prefix{
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("fd12:a3a7:1986:1::/64"),
	}

	kept := platformFilter(all)
	if len(kept) != 1 || kept[0] != all[1] {
		t.Fatalf("announced %v, wanted only the IPv6 prefix", kept)
	}

	// The way out, for when a platform changes and the guess stops holding.
	t.Setenv("ROBINET_KEEP_PLATFORM_IPV4", "1")
	if kept := platformFilter(all); len(kept) != 2 {
		t.Fatalf("the override left %v", kept)
	}
}

// Dropping everything would leave a connector announcing nothing at all, which
// is worse than announcing a range that identifies little.
func TestNothingLeftMeansKeepWhatThereIs(t *testing.T) {
	t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")

	only4 := []netip.Prefix{netip.MustParsePrefix("10.128.0.0/9")}
	if kept := platformFilter(only4); len(kept) != 1 {
		t.Fatalf("announced %v, wanted the IPv4 prefix kept", kept)
	}
}

// A network that appends nothing to a name still carries one, and what is said
// outright beats what was detected.
func TestWhatAConnectorAnnounces(t *testing.T) {
	for _, tc := range []struct {
		name            string
		dns             bool
		given, detected string
		want            string
	}{
		{"compose, nothing detected", true, "", "", enroll.RootDomain},
		{"railway", true, "", "railway.internal", "railway.internal"},
		{"said outright", true, "abc.pl", "", "abc.pl"},
		{"said outright over a platform", true, "abc.pl", "railway.internal", "abc.pl"},
		{"the root, said outright", true, enroll.RootDomain, "railway.internal", enroll.RootDomain},
		{"dns forwarding off", false, "abc.pl", "railway.internal", ""},
		{"dns forwarding off, nothing anywhere", false, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := announcedDomain(tc.dns, tc.given, tc.detected); got != tc.want {
				t.Fatalf("announced %q, want %q", got, tc.want)
			}
		})
	}
}

// The zone comes from what the platform states about this deployment, and is
// read off the end of it. A search list is not consulted at all: docker compose
// takes dns_search from the compose file, so it says what this container
// completes names with rather than what the network answers for.
func TestTheZoneComesFromThePlatform(t *testing.T) {
	t.Run("railway", func(t *testing.T) {
		t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")
		t.Setenv("RAILWAY_PRIVATE_DOMAIN", "nginx.railway.internal")

		if got := DiscoverDomain(); got != "railway.internal" {
			t.Fatalf("detected %q", got)
		}
	})

	t.Run("railway, but the name is not in the zone", func(t *testing.T) {
		t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")
		t.Setenv("RAILWAY_PRIVATE_DOMAIN", "nginx.elsewhere.example")

		if got := DiscoverDomain(); got != "" {
			t.Fatalf("detected %q from a name outside the zone", got)
		}
	})

	t.Run("railway, saying nothing", func(t *testing.T) {
		t.Setenv("RAILWAY_ENVIRONMENT_NAME", "production")
		t.Setenv("RAILWAY_PRIVATE_DOMAIN", "")

		if got := DiscoverDomain(); got != "" {
			t.Fatalf("detected %q", got)
		}
	})

	t.Run("an unknown platform, whatever its resolver was told", func(t *testing.T) {
		if got := DiscoverDomain(); got != "" {
			t.Fatalf("detected %q somewhere unrecognized", got)
		}
	})
}

// A typo in an environment variable is answered here, not by a rejected
// enrollment: the hub checks it too, but learning it from the hub means a
// container asking a server whether its own configuration parses.
func TestABadZoneIsRefusedBeforeAnythingIsSent(t *testing.T) {
	err := Run(context.Background(), Config{
		HubURL:   "https://hub.example:8443",
		Instance: "socha",
		Domain:   "abc.pl, klop.pl",
		StateDir: t.TempDir(),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("two zones in one variable were accepted")
	}
	if !strings.Contains(err.Error(), "ROBINET_DOMAIN") {
		t.Fatalf("the refusal does not name the variable: %s", err)
	}
}
