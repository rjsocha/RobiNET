package tenant

import "testing"

// The default is the one that matters: a machine that never said anything is
// not reachable, and nothing about joining an instance changes that.
func TestSayingNothingMeansPing(t *testing.T) {
	rules := inboundRules("")
	if len(rules) != 1 || rules[0]["proto"] != "icmp" {
		t.Fatalf("rules are %v", rules)
	}
}

func TestOpenAndNoneAreWhatTheySay(t *testing.T) {
	if rules := inboundRules(InboundOpen); len(rules) != 1 || rules[0]["proto"] != "any" {
		t.Fatalf("open is %v", rules)
	}

	// Empty rather than absent: nebula reads a missing key as its own default,
	// and an empty list as allowing nothing.
	if rules := inboundRules(InboundNone); rules == nil || len(rules) != 0 {
		t.Fatalf("none is %v", rules)
	}
}
