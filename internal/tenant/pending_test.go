package tenant

import (
	"testing"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
)

func entry(id string) PendingEntry {
	return PendingEntry{Record: &hub.Record{Record: enroll.Record{ID: id}}}
}

func TestAShortIdThatCouldMeanTwoRequestsIsRefused(t *testing.T) {
	entries := []PendingEntry{entry("f5dbb2930a1b2c3d"), entry("f5dbb293ffffffff")}

	if _, err := matchPending(entries, "f5dbb293"); err == nil {
		t.Fatal("an ambiguous id was accepted")
	}

	got, err := matchPending(entries, "f5dbb2930")
	if err != nil {
		t.Fatalf("one more character should resolve it: %v", err)
	}
	if got.Record.ID != "f5dbb2930a1b2c3d" {
		t.Fatalf("resolved to %s", got.Record.ID)
	}
}

// A full id is a full id, whatever else is pending.
func TestAnExactIdWins(t *testing.T) {
	entries := []PendingEntry{entry("f5dbb293"), entry("f5dbb293ffffffff")}

	got, err := matchPending(entries, "f5dbb293")
	if err != nil {
		t.Fatal(err)
	}
	if got.Record.ID != "f5dbb293" {
		t.Fatalf("resolved to %s", got.Record.ID)
	}
}
