package tenant

import "testing"

func TestAnUnknownModeSaysWhatExists(t *testing.T) {
	_, err := lookupMode("cos")
	if err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if got := err.Error(); got != `unknown mode "cos", supported: systemd` {
		t.Fatalf("the error is %q", got)
	}
}
