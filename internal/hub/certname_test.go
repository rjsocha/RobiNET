package hub

import "testing"

func TestCertNames(t *testing.T) {
	if got := LighthouseCertName("dom"); got != "hub.dom.instance" {
		t.Fatalf("lighthouse: %s", got)
	}

	cases := []struct {
		kind, name, want string
	}{
		{KindConnector, "production.projekt", "production.projekt.connector.dom.instance"},
		{KindTenant, "mara-studio-lan", "mara-studio-lan.tenant.dom.instance"},
		// An owner is a machine like any other, and its certificate says so.
		{KindOwner, "mara-studio-lan", "mara-studio-lan.tenant.dom.instance"},
	}

	for _, c := range cases {
		if got := MemberCertName(c.kind, c.name, "dom"); got != c.want {
			t.Errorf("%s %s: %s, wanted %s", c.kind, c.name, got, c.want)
		}
	}
}

func TestFoldLabel(t *testing.T) {
	cases := map[string]string{
		"mara@studio.lan": "mara-studio-lan",
		"MARA@Studio.LAN": "mara-studio-lan",
		"--weird--@--":    "weird",
		"":                "node",
		"@@@":             "node",
		// A name written in another script does not survive: every rune
		// outside the alphabet becomes a hyphen, and what is left is what
		// appears. This is why a machine can be registered under a name of
		// its own instead of whatever the host is called.
		"żółw":          "w",
		"mara@żółw.lan": "mara-w-lan",
	}

	for in, want := range cases {
		if got := FoldLabel(in); got != want {
			t.Errorf("%q: %q, wanted %q", in, got, want)
		}
	}

	long := make([]byte, 100)
	for i := range long {
		long[i] = 'a'
	}
	if got := FoldLabel(string(long)); len(got) != MaxNameLength {
		t.Errorf("long name folded to %d characters", len(got))
	}
}
