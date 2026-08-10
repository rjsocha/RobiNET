package tenant

import (
	"net/netip"
	"testing"
)

var railway = []netip.Prefix{
	netip.MustParsePrefix("10.128.0.0/9"),
	netip.MustParsePrefix("fd12:a3a7:1986:1::/64"),
}

// A dual stack instance carries what a connector announces, both families.
func TestCarriableKeepsBothWhenTheCertificateHoldsBoth(t *testing.T) {
	addrs := []netip.Prefix{
		netip.MustParsePrefix("198.19.0.3/24"),
		netip.MustParsePrefix("fd12:3456:789a:4::3/64"),
	}

	keep, dropped := carriable(railway, addrs)
	if len(keep) != 2 || len(dropped) != 0 {
		t.Fatalf("kept %v, dropped %v", keep, dropped)
	}
}

// An instance on a hub with no IPv6 pool cannot sign the IPv6 route, so it is
// dropped rather than failing everything.
func TestCarriableDropsTheFamilyTheCertificateCannotHold(t *testing.T) {
	addrs := []netip.Prefix{netip.MustParsePrefix("198.19.0.3/24")}

	keep, dropped := carriable(railway, addrs)
	if len(keep) != 1 || keep[0] != railway[0] {
		t.Fatalf("kept %v, wanted just the IPv4 route", keep)
	}
	if len(dropped) != 1 || dropped[0] != railway[1] {
		t.Fatalf("dropped %v, wanted just the IPv6 route", dropped)
	}
}
