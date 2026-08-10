package hub

import (
	"errors"
	"net/netip"
	"testing"
)

func dualInstance() *Instance {
	return &Instance{
		Overlay:            netip.MustParsePrefix("198.19.4.0/29"),
		Overlay6:           netip.MustParsePrefix("fd12:3456:789a:4::/112"),
		LighthouseAddress:  netip.MustParseAddr("198.19.4.1"),
		LighthouseAddress6: netip.MustParseAddr("fd12:3456:789a:4::1"),
		TenantAddress:      netip.MustParseAddr("198.19.4.2"),
		TenantAddress6:     netip.MustParseAddr("fd12:3456:789a:4::2"),
	}
}

// The two families are walked the same way and answer separately: a connector
// takes the top of each pool, and nothing about one address decides the other.
func TestPoolsAreIndependent(t *testing.T) {
	inst := dualInstance()

	addr, err := allocate(inst, "aa", KindConnector)
	if err != nil {
		t.Fatal(err)
	}
	addr6, err := allocate6(inst, "aa", KindConnector)
	if err != nil {
		t.Fatal(err)
	}

	if want := netip.MustParseAddr("198.19.4.6"); addr != want {
		t.Errorf("connector got %s, wanted %s", addr, want)
	}
	if want := netip.MustParseAddr("fd12:3456:789a:4::ffff"); addr6 != want {
		t.Errorf("connector got %s, wanted %s", addr6, want)
	}

	tenant, err := allocate(inst, "bb", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	tenant6, err := allocate6(inst, "bb", KindTenant)
	if err != nil {
		t.Fatal(err)
	}

	if want := netip.MustParseAddr("198.19.4.3"); tenant != want {
		t.Errorf("tenant got %s, wanted %s", tenant, want)
	}
	if want := netip.MustParseAddr("fd12:3456:789a:4::3"); tenant6 != want {
		t.Errorf("tenant got %s, wanted %s", tenant6, want)
	}
}

// Sticky in both families: the same key asking twice is the same member, not a
// second one.
func TestAllocationsAreSticky(t *testing.T) {
	inst := dualInstance()

	first, _ := allocate(inst, "aa", KindTenant)
	first6, _ := allocate6(inst, "aa", KindTenant)

	again, _ := allocate(inst, "aa", KindTenant)
	again6, _ := allocate6(inst, "aa", KindTenant)

	if first != again || first6 != again6 {
		t.Fatalf("drifted: %s/%s then %s/%s", first, first6, again, again6)
	}
}

// The point of two pools: a full IPv4 prefix stops handing out IPv4 and
// nothing else. What a Railway connector carries is IPv6, and it never needed
// the address it could not have.
func TestIPv4ExhaustionLeavesIPv6Alone(t *testing.T) {
	inst := dualInstance()

	// /29 holds .0 to .7, and the network, the broadcast, the lighthouse and
	// the owner are spoken for: four addresses to give away.
	for _, fp := range []string{"a", "b", "c", "d"} {
		if _, err := allocate(inst, fp, KindTenant); err != nil {
			t.Fatalf("%s: %v", fp, err)
		}
	}

	if _, err := allocate(inst, "e", KindTenant); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("a fifth IPv4 address was handed out: %v", err)
	}

	addr6, err := allocate6(inst, "e", KindTenant)
	if err != nil {
		t.Fatalf("IPv6 refused because IPv4 ran out: %v", err)
	}
	if !inst.Overlay6.Contains(addr6) {
		t.Fatalf("%s is not in %s", addr6, inst.Overlay6)
	}
}

// An instance with no IPv6 pool hands out none, and says so without an error:
// there is nothing wrong with an instance that is IPv4 only.
func TestNoIPv6PoolHandsOutNothing(t *testing.T) {
	inst := &Instance{Overlay: netip.MustParsePrefix("198.19.4.0/24")}

	addr, err := allocate6(inst, "aa", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	if addr.IsValid() {
		t.Fatalf("an address was produced without a pool: %s", addr)
	}
}
