package main

import (
	"testing"

	"github.com/rjsocha/robinet/internal/version"
)

// The command line and the daemon are one binary. Two halves that were not
// built together agree only by luck, and the build is what says so.
func TestOnlyItsOwnBuildIsAccepted(t *testing.T) {
	if err := checkVersion(version.String()); err != nil {
		t.Fatalf("its own build was refused: %v", err)
	}

	// A daemon from before this header existed, which is what an upgrade
	// leaves running.
	if err := checkVersion(""); err == nil {
		t.Fatal("a daemon that says nothing was accepted")
	}
	if err := checkVersion("v0.0.1-dev-0101000000"); err == nil {
		t.Fatal("a different build was accepted")
	}
}
