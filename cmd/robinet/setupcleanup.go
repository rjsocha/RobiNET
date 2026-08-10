package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rjsocha/robinet/internal/tenant"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

const (
	tenantUnit     = "robinet.service"
	tenantUnitPath = "/etc/systemd/system/" + tenantUnit
)

// cleanupTenant undoes setup and forgets everything this machine keeps.
//
// It destroys the certificate authority of every instance this machine owns.
// Those meshes keep running on the certificates already issued, but nobody can
// ever admit or ban anybody in them again, because the only key that could
// sign lived here. Hence --force.
func cleanupTenant(ctx context.Context, stateFlag string, force bool) error {
	path, err := statePath(stateFlag)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)

	owned := ownedInstances(path)

	if !force {
		fmt.Println("robinet setup --cleanup would remove:")
		fmt.Printf("  the %s service, if installed\n", tenantUnit)
		fmt.Printf("  any resolver configuration under %s\n", "/etc/systemd/network")
		fmt.Printf("  %s\n", dir)
		fmt.Println()

		if len(owned) > 0 {
			fmt.Println("that directory holds the certificate authority of:")
			for _, name := range owned {
				fmt.Printf("  %s\n", name)
			}
			fmt.Println()
			fmt.Println("those meshes keep running on the certificates already issued,")
			fmt.Println("but nobody could ever admit or ban anybody in them again.")
			fmt.Println()
		}

		return errors.New("refusing to do that without --force")
	}

	if systemctl, err := exec.LookPath("systemctl"); err == nil {
		for _, args := range [][]string{{"stop", tenantUnit}, {"disable", tenantUnit}} {
			_ = exec.CommandContext(ctx, systemctl, args...).Run()
		}
		if err := os.Remove(tenantUnitPath); err == nil {
			fmt.Printf("removed %s\n", tenantUnitPath)
			_ = exec.CommandContext(ctx, systemctl, "daemon-reload").Run()
		}
	}

	// The resolver files name devices that will not exist after this, so they
	// go with everything else rather than staying behind as a promise nothing
	// keeps.
	if err := tenant.RemoveAll(ctx); err != nil {
		fmt.Printf("could not remove the resolver configuration: %s\n", err)
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("could not remove %s: %w", dir, err)
	}
	fmt.Printf("removed %s\n", dir)

	fmt.Println("this machine is a stranger again: robinet join to start over")
	return nil
}

// ownedInstances names what would be lost, read from the state file rather
// than from a running daemon, which may already be stopped.
func ownedInstances(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var state struct {
		Owned map[string]struct {
			Name string `json:"name"`
		} `json:"owned"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil
	}

	var out []string
	for _, o := range state.Owned {
		out = append(out, o.Name)
	}
	sort.Strings(out)

	return out
}
