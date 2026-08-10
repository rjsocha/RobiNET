package tenant

import (
	"net/netip"
	"testing"
)

func TestWhatEachChoiceInstalls(t *testing.T) {
	v4 := netip.MustParsePrefix("10.128.0.0/9")
	v6 := netip.MustParsePrefix("fd12:a3a7:1986:1::/64")

	for _, tc := range []struct {
		families string
		want4    bool
		want6    bool
	}{
		{FamiliesBoth, true, true},
		{FamiliesIPv4, true, false},
		{FamiliesIPv6, false, true},
		{"", true, true}, // a machine that never said anything
	} {
		if got := wantedFamily(tc.families, v4); got != tc.want4 {
			t.Errorf("%q installs ipv4: %v, wanted %v", tc.families, got, tc.want4)
		}
		if got := wantedFamily(tc.families, v6); got != tc.want6 {
			t.Errorf("%q installs ipv6: %v, wanted %v", tc.families, got, tc.want6)
		}
	}
}

func TestOnlyTheThreeChoicesAreAccepted(t *testing.T) {
	if ValidFamilies("ip6") || ValidFamilies("v4") || ValidFamilies("") {
		t.Fatal("a setting nobody handles was accepted")
	}
}
