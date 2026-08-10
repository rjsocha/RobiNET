package hub

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func storeWith(t *testing.T, instances ...*Instance) *Store {
	t.Helper()

	s, err := OpenStore(filepath.Join(t.TempDir(), "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range instances {
		inst.ensureMaps()
		if err := s.Add(inst); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// A connector is pointed at an instance by whatever its operator was given,
// which is a name far more often than sixteen hex characters.
func TestResolveTakesAnIdOrAName(t *testing.T) {
	s := storeWith(t,
		&Instance{ID: "a1b2c3d4e5f60718", Name: "railway"},
		&Instance{ID: "0f1e2d3c4b5a6978", Name: "compose"},
	)

	for ref, want := range map[string]string{
		"a1b2c3d4e5f60718": "a1b2c3d4e5f60718",
		"railway":          "a1b2c3d4e5f60718",
		"compose":          "0f1e2d3c4b5a6978",
	} {
		got, err := s.Resolve(ref)
		if err != nil {
			t.Fatalf("%q: %v", ref, err)
		}
		if got.ID != want {
			t.Errorf("%q resolved to %s, wanted %s", ref, got.ID, want)
		}
	}

	// Names are folded when stored and when asked for: DNS does not
	// distinguish case, and this name is heading there.
	if got, err := s.Resolve("RAILWAY"); err != nil || got.ID != "a1b2c3d4e5f60718" {
		t.Errorf("an upper case name gave %v, %v", got, err)
	}

	if _, err := s.Resolve("nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown name gave %v", err)
	}
}

// A name is unique on a hub, which is what lets one be written into a
// connector's endpoint and read back with confidence.
func TestASharedNameIsRefusedWhenItIsTaken(t *testing.T) {
	s := storeWith(t, &Instance{ID: "a1b2c3d4e5f60718", Name: "railway", Binder: "robert"})

	err := s.Add(&Instance{ID: "0f1e2d3c4b5a6978", Name: "railway", Binder: "jacek"})
	if err == nil {
		t.Fatal("a second railway was created")
	}
	// Whose it is, because that is what the second person needs to know.
	if !strings.Contains(err.Error(), "robert") {
		t.Errorf("the refusal does not say who holds it: %v", err)
	}
}

// State written before names were unique can still hold two. Resolving one of
// those must refuse rather than hand a connector to whichever sorted first.
func TestResolveRefusesASharedNameInOlderState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.json")
	raw := `{"instances":{
		"a1b2c3d4e5f60718":{"id":"a1b2c3d4e5f60718","name":"railway","owner":"robert"},
		"0f1e2d3c4b5a6978":{"id":"0f1e2d3c4b5a6978","name":"railway","owner":"jacek"}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Resolve("railway"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("a shared name gave %v", err)
	}

	// The id still works, which is the way out of the ambiguity.
	if got, err := s.Resolve("0f1e2d3c4b5a6978"); err != nil || got.Owner != "jacek" {
		t.Fatalf("the id resolved to %v, %v", got, err)
	}
}

// An id that happens to be somebody else's name is still an id.
func TestAnIdWinsOverAName(t *testing.T) {
	s := storeWith(t,
		&Instance{ID: "railway", Name: "something"},
		&Instance{ID: "0f1e2d3c4b5a6978", Name: "railway"},
	)

	got, err := s.Resolve("railway")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "something" {
		t.Fatalf("resolved to the instance named %s", got.Name)
	}
}
