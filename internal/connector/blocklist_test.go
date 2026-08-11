package connector

import (
	"net/netip"
	"testing"

	"github.com/rjsocha/robinet/internal/ca"
	"github.com/rjsocha/robinet/internal/enroll"
)

// A ban on this connector arrives on the same list as a ban on anybody else,
// and telling the two apart is what makes it reportable instead of being
// installed as a refusal of ourselves.
func TestAConnectorRecognizesItsOwnCertificate(t *testing.T) {
	overlay := netip.MustParsePrefix("198.19.200.0/24")

	authority, _, _, err := ca.Generate("robinet-test", []netip.Prefix{overlay}, 0)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, _, err := ca.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	issued, err := authority.Sign(ca.Host{
		Name:         "railway",
		PublicKeyPEM: pubPEM,
		Networks:     []netip.Prefix{netip.MustParsePrefix("198.19.200.10/24")},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ownFingerprint(&enroll.Bundle{Certificate: string(issued)})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("a connector holding a certificate produced no fingerprint")
	}

	// Nothing to compare against is an error rather than an empty answer that
	// would silently match nobody.
	if _, err := ownFingerprint(&enroll.Bundle{}); err == nil {
		t.Error("a bundle with no certificate produced a fingerprint")
	}
	if _, err := ownFingerprint(nil); err == nil {
		t.Error("no bundle at all produced a fingerprint")
	}
}

func TestOurOwnFingerprintIsTakenOutOfWhatWeInstall(t *testing.T) {
	list := []string{"aaa", "bbb", "ccc"}

	if got := without(list, "bbb"); len(got) != 2 || got[0] != "aaa" || got[1] != "ccc" {
		t.Fatalf("dropping bbb gave %v", got)
	}

	// Untouched when there is nothing to drop, so a connector that could not
	// read its own certificate still installs the whole list.
	if got := without(list, ""); len(got) != 3 {
		t.Fatalf("dropping nothing gave %v", got)
	}
	if got := without(list, "zzz"); len(got) != 3 {
		t.Fatalf("dropping somebody not on the list gave %v", got)
	}
}
