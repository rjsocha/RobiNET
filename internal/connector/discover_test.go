package connector

import (
	"net/netip"
	"testing"
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
