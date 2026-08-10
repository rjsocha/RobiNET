package main

import (
	"testing"

	"github.com/rjsocha/robinet/internal/hub"
)

func TestGeneratedPoolIsAUniqueLocalPrefix(t *testing.T) {
	first, err := randomULA()
	if err != nil {
		t.Fatal(err)
	}

	prefix, size, err := hub.ParsePool(first)
	if err != nil {
		t.Fatalf("the hub cannot parse what init writes: %v", err)
	}
	if size != 112 {
		t.Errorf("instances get /%d, wanted /112", size)
	}
	if !prefix.Addr().Is6() || prefix.Bits() != 48 {
		t.Errorf("%s is not a /48 of IPv6", prefix)
	}
	// fd00::/8 is the half of fc00::/7 that is meant to be self assigned.
	if b := prefix.Addr().As16(); b[0] != 0xfd {
		t.Errorf("%s is not in fd00::/8", prefix)
	}

	second, err := randomULA()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("two hubs would share a prefix, which is the one thing this must not do")
	}
}
