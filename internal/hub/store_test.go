package hub

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestEmptyMapsSurviveAReload covers the failure that took a hub down: an
// empty map is omitted when the state is written, comes back as nil, and the
// first write to it panics.
func TestEmptyMapsSurviveAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.json")

	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}

	inst := &Instance{
		ID:          "abc",
		Name:        "railway",
		Overlay:     netip.MustParsePrefix("198.19.0.0/24"),
		Allocations: map[string]netip.Addr{},
		Requests:    map[string]*Record{},
		Members:     map[string]*Member{},
	}
	if err := store.Add(inst); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("nothing was written")
	}

	// A fresh process, reading what the previous one wrote.
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}

	err = reopened.Update("abc", func(inst *Instance) error {
		inst.Requests["r1"] = &Record{Kind: KindConnector}
		inst.Members["m1"] = &Member{Kind: KindConnector}
		inst.Allocations["f1"] = netip.MustParseAddr("198.19.0.5")
		return nil
	})
	if err != nil {
		t.Fatalf("writing to a reloaded instance failed: %s", err)
	}
}
