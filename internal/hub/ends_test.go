package hub

import (
	"net/netip"
	"testing"
)

// An address should say which kind of member holds it without looking anything
// up.
func TestConnectorsComeDownFromTheTop(t *testing.T) {
	inst := &Instance{
		Overlay:           netip.MustParsePrefix("198.19.4.0/24"),
		LighthouseAddress: netip.MustParseAddr("198.19.4.1"),
		TenantAddress:     netip.MustParseAddr("198.19.4.2"),
	}
	inst.ensureMaps()

	first, err := allocate(inst, "aaa", KindConnector)
	if err != nil {
		t.Fatal(err)
	}
	// Not .255, which is the broadcast address of this prefix.
	if first.String() != "198.19.4.254" {
		t.Fatalf("the first connector got %s", first)
	}

	second, err := allocate(inst, "bbb", KindConnector)
	if err != nil {
		t.Fatal(err)
	}
	if second.String() != "198.19.4.253" {
		t.Fatalf("the second connector got %s", second)
	}

	// A tenant still comes up from the bottom, past the two reserved ones.
	tenant, err := allocate(inst, "ccc", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.String() != "198.19.4.3" {
		t.Fatalf("a tenant got %s", tenant)
	}

	// Sticky: the same key always gets the same address, so a connector that
	// re-enrolls does not drift.
	again, err := allocate(inst, "aaa", KindConnector)
	if err != nil || again != first {
		t.Fatalf("the same key got %s, then %s", first, again)
	}
}

func TestTheEndsMeetRatherThanRunOff(t *testing.T) {
	inst := &Instance{Overlay: netip.MustParsePrefix("10.9.0.0/29")}
	inst.ensureMaps()

	// .1 to .6 are usable: six members, whichever end they come from.
	for i := 0; i < 3; i++ {
		if _, err := allocate(inst, string(rune('a'+i)), KindConnector); err != nil {
			t.Fatalf("connector %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := allocate(inst, string(rune('x'+i)), KindTenant); err != nil {
			t.Fatalf("tenant %d: %v", i, err)
		}
	}

	if _, err := allocate(inst, "one-too-many", KindConnector); err == nil {
		t.Fatal("a seventh member fitted in a /29")
	}
}

func TestHighestFreeInIPv6(t *testing.T) {
	prefix := netip.MustParsePrefix("fd42::/112")

	got, err := highestFree(prefix, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "fd42::ffff" {
		t.Fatalf("the top of %s is %s", prefix, got)
	}
}
