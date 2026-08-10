package hub

import (
	"net/netip"
	"testing"
)

func TestParsePool(t *testing.T) {
	cases := []struct {
		in       string
		prefix   string
		size     int
		wantFail bool
	}{
		{in: "198.19.0.0/16/24", prefix: "198.19.0.0/16", size: 24},
		{in: "192.168.0.0/16/26", prefix: "192.168.0.0/16", size: 26},
		{in: "10.0.0.0/8/16", prefix: "10.0.0.0/8", size: 16},
		{in: "198.19.0.0/16", prefix: "198.19.0.0/16", size: 24},
		{in: "fd00::/32", prefix: "fd00::/32", size: 112},
		{in: "fd00::/32/48", prefix: "fd00::/32", size: 48},
		// A size wider than the pool would hand out addresses outside it.
		{in: "198.19.0.0/16/8", wantFail: true},
		{in: "198.19.0.0/16/40", wantFail: true},
		{in: "not-a-network", wantFail: true},
	}

	for _, c := range cases {
		prefix, size, err := ParsePool(c.in)
		if c.wantFail {
			if err == nil {
				t.Errorf("%q was accepted, want an error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %s", c.in, err)
			continue
		}
		if prefix.String() != c.prefix || size != c.size {
			t.Errorf("%q gave %s /%d, want %s /%d", c.in, prefix, size, c.prefix, c.size)
		}
	}
}

func TestAllocateOverlayWalksThePool(t *testing.T) {
	pool := []Pool{{Prefix: netip.MustParsePrefix("198.19.0.0/16"), Size: 24}}
	taken := map[netip.Prefix]struct{}{}

	want := []string{"198.19.0.0/24", "198.19.1.0/24", "198.19.2.0/24"}
	for _, expected := range want {
		got, err := allocateOverlay(pool, taken)
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != expected {
			t.Fatalf("got %s, want %s", got, expected)
		}
		taken[got] = struct{}{}
	}

	// A hole is reused rather than skipped.
	delete(taken, netip.MustParsePrefix("198.19.1.0/24"))
	got, err := allocateOverlay(pool, taken)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "198.19.1.0/24" {
		t.Fatalf("got %s, want the freed 198.19.1.0/24", got)
	}
}

func TestAllocateOverlayExhausts(t *testing.T) {
	pool := []Pool{{Prefix: netip.MustParsePrefix("10.1.0.0/30"), Size: 31}}
	taken := map[netip.Prefix]struct{}{}

	for i := 0; i < 2; i++ {
		got, err := allocateOverlay(pool, taken)
		if err != nil {
			t.Fatal(err)
		}
		taken[got] = struct{}{}
	}

	if _, err := allocateOverlay(pool, taken); err == nil {
		t.Fatal("expected the pool to run out")
	}
}

func TestAllocateOverlayIPv6(t *testing.T) {
	pool := []Pool{{Prefix: netip.MustParsePrefix("fd00:1234::/32"), Size: 48}}
	taken := map[netip.Prefix]struct{}{}

	first, err := allocateOverlay(pool, taken)
	if err != nil {
		t.Fatal(err)
	}
	taken[first] = struct{}{}

	second, err := allocateOverlay(pool, taken)
	if err != nil {
		t.Fatal(err)
	}

	if first.String() != "fd00:1234::/48" || second.String() != "fd00:1234:1::/48" {
		t.Fatalf("got %s then %s", first, second)
	}
}
