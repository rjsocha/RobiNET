package hub

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func testFile(overlays []string) *File {
	f := &File{Overlays: overlays}
	f.Public.Endpoint = "192.0.2.1"
	f.Binder = []struct {
		Name string   `yaml:"name"`
		Key  []string `yaml:"key"`
	}{}
	f.applyDefaults()
	return f
}

// The prefix says which family it is. Nothing names it, so nothing can name it
// wrong.
func TestFamilyIsReadOffThePrefix(t *testing.T) {
	f := testFile([]string{"fd02:15f8:cdc8::/48/112", "198.19.0.0/16/24"})

	cfg, err := f.Config(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overlays) != 1 || cfg.Overlays[0].Prefix.String() != "198.19.0.0/16" || cfg.Overlays[0].Size != 24 {
		t.Errorf("ipv4 pools are %v", cfg.Overlays)
	}
	if len(cfg.Overlays6) != 1 || cfg.Overlays6[0].Prefix.String() != "fd02:15f8:cdc8::/48" || cfg.Overlays6[0].Size != 112 {
		t.Errorf("ipv6 pools are %v", cfg.Overlays6)
	}
}

// More space for the same family is the point of a list: the first is filled,
// then the next.
func TestPoolsOfOneFamilyAddUp(t *testing.T) {
	f := testFile([]string{"198.19.0.0/16/24", "192.168.0.0/16/22"})

	cfg, err := f.Config(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Overlays) != 2 {
		t.Fatalf("pools are %v", cfg.Overlays)
	}

	// The first is exhausted before the second is touched, and each pool
	// carries its own instance size.
	taken := map[netip.Prefix]struct{}{}
	for i := 0; i < 256; i++ {
		got, err := allocateOverlay(cfg.Overlays, taken)
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		taken[got] = struct{}{}
	}

	next, err := allocateOverlay(cfg.Overlays, taken)
	if err != nil {
		t.Fatal(err)
	}
	if next.String() != "192.168.0.0/22" {
		t.Fatalf("after the first pool filled, allocation went to %s", next)
	}
}

// Two pools covering the same addresses would hand the same prefix out twice.
func TestOverlappingPoolsAreRefused(t *testing.T) {
	f := testFile([]string{"198.19.0.0/16/24", "198.19.4.0/22/24"})

	if _, err := f.Config(slog.Default()); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("error was %v", err)
	}
}

// Every member gets an IPv4 address, so a hub without a pool for one could
// allocate nothing at all.
func TestAnIPv6OnlyHubIsRefused(t *testing.T) {
	f := testFile([]string{"fd02:15f8:cdc8::/48/112"})

	if _, err := f.Config(slog.Default()); err == nil || !strings.Contains(err.Error(), "no IPv4 pool") {
		t.Fatalf("error was %v", err)
	}
}
