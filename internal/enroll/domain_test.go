package enroll

import "testing"

func TestDomainsAreHeldToWhatDnsAllows(t *testing.T) {
	for raw, want := range map[string]string{
		"railway.internal":  "railway.internal",
		"RAILWAY.Internal.": "railway.internal",
		"  compose.lan  ":   "compose.lan",
	} {
		got, err := ParseDomain(raw)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("%q became %q, wanted %q", raw, got, want)
		}
	}

	for _, bad := range []string{"", ".", "a..b", "-a.b", "a-.b", "a b.c", "a_b.c"} {
		if got, err := ParseDomain(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}
