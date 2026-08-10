package hub

import "testing"

func TestNamesAreDnsLabels(t *testing.T) {
	for raw, want := range map[string]string{
		"railway":     "railway",
		"RAILWAY":     "railway",
		"  railway  ": "railway",
		"rail-way-2":  "rail-way-2",
	} {
		got, err := ParseName(raw)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("%q became %q, wanted %q", raw, got, want)
		}
	}

	for _, bad := range []string{
		"", "  ",
		"rail way",
		"rail_way",
		"rail.way",
		"-railway",
		"railway-",
		"e2063acca759f5c0", // an identifier, which would be ambiguous
	} {
		if got, err := ParseName(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}

// A member's name may be more than one label: a connector is best described by
// the environment and the project it runs in, and a hyphen between them would
// lose where one ends.
func TestAMemberNameMayHaveLabels(t *testing.T) {
	for raw, want := range map[string]string{
		"production.acme":    "production.acme",
		"Production.Acme.":   "production.acme",
		"prod.my-project":    "prod.my-project",
		"connector-69fbefaf": "connector-69fbefaf",
	} {
		got, err := ParseMemberName(raw)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("%q became %q", raw, got)
		}
	}

	// Every label is still a label.
	for _, bad := range []string{"", ".", "a..b", "prod.-acme", "prod.acme_x"} {
		if got, err := ParseMemberName(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}

// A connector is not turned away over a name it cannot have: the name is
// dropped and what it asked for is kept where the owner will see it.
func TestAnUnusableNameDoesNotRefuseTheConnector(t *testing.T) {
	for _, bad := range []string{"Żółw", "my project!", "..."} {
		if _, err := ParseMemberName(bad); err == nil {
			t.Errorf("%q was accepted as a name", bad)
		}
	}
}

// A name is the name space a member answers under, so two members cannot have
// one. A re-enrolment of the same key is not another member.
func TestTwoMembersCannotShareAName(t *testing.T) {
	s := storeWith(t, &Instance{ID: "a1b2c3d4e5f60718", Name: "example"})

	err := s.Update("a1b2c3d4e5f60718", func(inst *Instance) error {
		inst.Members["aaa"] = &Member{Kind: KindConnector, Name: "production.acme"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	inst, err := s.Get("a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}

	taken := func(fingerprint, name string) bool {
		for fp, m := range inst.Members {
			if fp != fingerprint && m.Name == name && name != "" {
				return true
			}
		}
		return false
	}

	if !taken("bbb", "production.acme") {
		t.Error("a second member with the same name was not noticed")
	}
	if taken("aaa", "production.acme") {
		t.Error("a member was refused its own name")
	}
}
