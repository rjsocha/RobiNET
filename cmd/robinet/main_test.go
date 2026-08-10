package main

import (
	"context"
	"errors"
	"fmt"
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
