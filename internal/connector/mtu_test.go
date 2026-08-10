package connector

import "testing"

// Below 1280 gvisor refuses to send IPv6 at all, so a stack that small drops
// every IPv6 packet while IPv4 keeps working - which is indistinguishable from
// a network problem.
func TestTheStackIsNeverTooSmallForIPv6(t *testing.T) {
	if got := overlayMTU(1316, 0, nil); got < minimumMTU {
		t.Fatalf("a 1316 byte path produced %d", got)
	}

	if got := overlayMTU(576, 0, nil); got != minimumMTU {
		t.Fatalf("a path narrower than IPv6 allows produced %d, wanted the minimum", got)
	}
}

// An override is the operator's, and it is not second guessed.
func TestAnOverrideWins(t *testing.T) {
	if got := overlayMTU(1500, 900, nil); got != 900 {
		t.Fatalf("the override gave %d", got)
	}
}
