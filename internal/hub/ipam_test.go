package hub

import (
	"net/netip"
	"testing"
)

func TestAllocateIsSticky(t *testing.T) {
	inst := &Instance{Overlay: netip.MustParsePrefix("198.19.200.0/24")}

	lighthouse, err := reserveLighthouse(inst.Overlay)
	if err != nil {
		t.Fatal(err)
	}
	if lighthouse.String() != "198.19.200.1" {
		t.Fatalf("lighthouse got %s", lighthouse)
	}
	inst.LighthouseAddress = lighthouse

	first, err := allocate(inst, "fp-a", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "198.19.200.2" {
		t.Fatalf("the first tenant got %s, want the address after the lighthouse", first)
	}

	second, err := allocate(inst, "fp-b", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	if second.String() != "198.19.200.3" {
		t.Fatalf("the second tenant got %s", second)
	}

	again, err := allocate(inst, "fp-a", KindTenant)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("the same fingerprint got %s and then %s", first, again)
	}
}

func TestAllocateSkipsBroadcast(t *testing.T) {
	inst := &Instance{Overlay: netip.MustParsePrefix("10.0.0.0/30")}

	// .1 and .2 are usable, .3 is broadcast
	if _, err := allocate(inst, "a", KindTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := allocate(inst, "b", KindTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := allocate(inst, "c", KindTenant); err == nil {
		t.Fatal("expected the pool to be exhausted before handing out the broadcast address")
	}
}
