package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestARequestedRestartExitsNonZero(t *testing.T) {
	// What the daemon reports, and what a signal leaves behind: the restart
	// came in as SIGTERM, so both are present at once.
	err := fmt.Errorf("daemon stopped: %w", errRestartWanted)

	if code := exitCodeFor(err, context.Canceled); code != exitRestart {
		t.Fatalf("exit code %d, wanted %d: a unit with Restart=on-failure would leave the daemon down", code, exitRestart)
	}
}

func TestBeingInterruptedIsNotAFailure(t *testing.T) {
	if code := exitCodeFor(errors.New("interrupted"), context.Canceled); code != 0 {
		t.Fatalf("exit code %d, wanted 0", code)
	}
	if code := exitCodeFor(nil, nil); code != 0 {
		t.Fatalf("exit code %d, wanted 0", code)
	}
	if code := exitCodeFor(errors.New("something broke"), nil); code != 1 {
		t.Fatalf("exit code %d, wanted 1", code)
	}
}

// A switch is typed into a platform's web form, where the case is whatever the
// person felt like. Reading OFF as on would turn DNS back on in a deployment
// that asked for it off, and nothing would say so.
func TestSwitchesAreReadWhateverTheCase(t *testing.T) {
	const name = "ROBINET_TEST_SWITCH"

	for _, off := range []string{"0", "false", "no", "off", "OFF", "False", "FALSE", "  Off  "} {
		t.Setenv(name, off)
		if envBool(name, true) {
			t.Errorf("%q was read as on", off)
		}
	}

	for _, on := range []string{"1", "true", "yes", "ON", "anything"} {
		t.Setenv(name, on)
		if !envBool(name, false) {
			t.Errorf("%q was read as off", on)
		}
	}

	// Unset is neither: whatever the command decided its default is.
	os.Unsetenv(name)
	if !envBool(name, true) || envBool(name, false) {
		t.Error("an unset switch did not fall back to the default")
	}
}
