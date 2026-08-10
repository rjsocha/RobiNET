package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rjsocha/robinet/internal/hub"
)

// hubUnit is the service name a hub is installed under, if it is installed at
// all. Cleanup removes it when present and says nothing when it is not.
const hubUnit = "robinet-hub.service"

// cleanupHub removes everything a hub leaves behind: the unit, the state and
// the configuration.
//
// This throws away every instance on this hub. Their tenants keep their
// authorities and their certificates, but the lighthouse they point at is gone
// and the address space is forgotten, so every connector has to enroll again
// against a new instance. Hence --force: there is no undo and no backup.
func cleanupHub(ctx context.Context, configPath string, force bool) error {
	targets := hubTargets(configPath)

	if !force {
		fmt.Println("robinet hub cleanup would remove:")
		for _, t := range targets {
			fmt.Printf("  %s\n", t)
		}
		fmt.Println()
		fmt.Println("every instance, its address space and its lighthouse would be gone,")
		fmt.Println("and every connector would have to enroll again against a new one.")
		fmt.Println()
		return errors.New("refusing to do that without --force")
	}

	// Stop first: a running hub would rewrite its state file after we removed
	// it, and leave the port bound.
	stopHubService(ctx)

	var failed []string
	for _, path := range targets {
		if isUnit(path) {
			continue
		}

		err := os.Remove(path)
		switch {
		case err == nil:
			fmt.Printf("removed %s\n", path)
		case errors.Is(err, os.ErrNotExist):
			// Nothing to say: cleanup is meant to be safe to repeat.
		default:
			failed = append(failed, fmt.Sprintf("%s: %s", path, err))
		}
	}

	// An empty state directory left behind is just litter.
	for _, dir := range []string{filepath.Dir(hubStatePath(configPath))} {
		if dir != "" && dir != "/" && dir != "." {
			if err := os.Remove(dir); err == nil {
				fmt.Printf("removed %s\n", dir)
			}
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("could not remove: %v", failed)
	}

	fmt.Println("hub cleaned up")
	return nil
}

// hubTargets is everything cleanup touches, in the order it is reported.
func hubTargets(configPath string) []string {
	state := hubStatePath(configPath)

	return []string{
		"the " + hubUnit + " service, if installed",
		state,
		state + ".tmp",
		configPath,
	}
}

func isUnit(target string) bool {
	return len(target) > 4 && target[:4] == "the "
}

// hubStatePath reads the state location out of the configuration, falling back
// to the default when the file is gone or unreadable.
func hubStatePath(configPath string) string {
	const fallback = "/var/lib/robinet/hub.json"

	file, err := hub.LoadFile(configPath)
	if err != nil || file.State.Path == "" {
		return fallback
	}
	return file.State.Path
}

// stopHubService stops and disables the unit, if systemd knows about it.
func stopHubService(ctx context.Context) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return
	}

	unitPath := hubUnitPath
	if _, err := os.Stat(unitPath); errors.Is(err, os.ErrNotExist) {
		// Not installed by us. Still ask systemd to stop it, in case it was
		// installed elsewhere, but do not touch anything.
		_ = exec.CommandContext(ctx, systemctl, "stop", hubUnit).Run()
		return
	}

	for _, args := range [][]string{{"stop", hubUnit}, {"disable", hubUnit}} {
		_ = exec.CommandContext(ctx, systemctl, args...).Run()
	}

	if err := os.Remove(unitPath); err == nil {
		fmt.Printf("removed %s\n", unitPath)
		_ = exec.CommandContext(ctx, systemctl, "daemon-reload").Run()
	}
}
