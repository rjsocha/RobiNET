package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/rjsocha/robinet/internal/hub"
)

const hubUnitPath = "/etc/systemd/system/" + hubUnit

// installHub writes the systemd unit for a hub and starts it.
//
// Absolute paths on purpose: robinet is usually installed somewhere that is
// not on root's PATH, and the configuration is not where systemd would guess.
func installHub(ctx context.Context, configPath string, configDirs []string, enable bool) error {
	// The unit gets installed either way. Whether the configuration is any
	// good is checked by the unit itself, on every start, through --test as
	// ExecStartPre: that way the reason lives in the journal next to the
	// failure rather than only in the terminal of whoever installed it.
	file, err := hub.LoadFile(configPath, configDirs...)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w (run robinet hub init first)", err)
	}
	ready := err == nil

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find this binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	if err := ensureHubUser(ctx, configPath, configDirs); err != nil {
		return err
	}

	if err := os.WriteFile(hubUnitPath, []byte(renderHubUnit(exePath, configPath, configDirs)), 0o644); err != nil {
		return fmt.Errorf("could not write %s: %w", hubUnitPath, err)
	}
	fmt.Printf("wrote %s\n", hubUnitPath)

	if !enable {
		fmt.Println("run: systemctl daemon-reload && systemctl enable --now robinet-hub")
		return nil
	}

	for _, args := range [][]string{{"daemon-reload"}, {"enable", hubUnit}} {
		if out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %v failed: %s", args, out)
		}
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "start", hubUnit).CombinedOutput(); err != nil {
		fmt.Printf("\ninstalled and enabled, but it would not start:\n\n")
		if !ready {
			// Show the actual reason rather than systemd's summary of it.
			_ = testHubConfig(configPath, configDirs)
		} else {
			fmt.Printf("%s\n", out)
		}
		fmt.Printf("\nfix that, then: systemctl start robinet-hub\n")
		return errors.New("the hub is installed but not running")
	}

	fmt.Printf("hub running on %s, endpoint %s\n", file.API.Listen, file.Public.Endpoint)
	return nil
}

func renderHubUnit(exePath, configPath string, configDirs []string) string {
	args := " --config " + configPath
	for _, dir := range configDirs {
		args += " --config-dir " + dir
	}

	// The hub needs no privilege at all: it binds high ports, writes one state
	// file and never touches an interface - a lighthouse answers where somebody
	// is and a relay forwards what is already encrypted, and neither is ever
	// the destination of a packet, so there is no device to have.
	//
	// So it runs as its own user rather than as root with the capabilities
	// taken away. Bounding capabilities stops the kernel granting anything;
	// it does not stop uid 0 reading every file on the machine, and a process
	// that needs nothing should hold nothing.
	return fmt.Sprintf(`[Unit]
Description=robinet hub
Documentation=https://github.com/rjsocha/robinet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
ExecStartPre=%s hub test%s
ExecStart=%s hub run%s
StateDirectory=robinet
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`, hubUser, hubUser, exePath, args, exePath, args)
}

// hubUser is who the hub runs as. A name rather than DynamicUser, because the
// configuration holds a token and has to be readable by exactly one account
// that does not change from boot to boot.
const hubUser = "robinet"

// ensureHubUser creates the account and gives it the configuration to read.
//
// The state directory is systemd's to own, through StateDirectory. The
// configuration is not: it was written by whoever ran init, it holds the
// registry token, and it stays root's - readable by this one group and nobody
// else.
func ensureHubUser(ctx context.Context, configPath string, configDirs []string) error {
	if _, err := user.Lookup(hubUser); err != nil {
		add, lookErr := exec.LookPath("useradd")
		if lookErr != nil {
			return fmt.Errorf("no user %s and useradd is not available: create it, then install again", hubUser)
		}

		out, err := exec.CommandContext(ctx, add,
			"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", hubUser).CombinedOutput()
		if err != nil {
			return fmt.Errorf("could not create the %s user: %s", hubUser, out)
		}
		fmt.Printf("created the %s system account\n", hubUser)
	}

	// Group readable rather than owned: root wrote it, root keeps it, and the
	// hub only ever reads.
	paths := append([]string{configPath}, configDirs...)
	for _, path := range paths {
		if err := chownGroup(path, hubUser); err != nil {
			fmt.Printf("could not give %s to %s: %s\n", path, hubUser, err)
		}
	}

	return nil
}

// chownGroup gives a path to a group and makes it readable by it, walking a
// directory rather than only its name.
func chownGroup(path, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}

	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := os.Chown(name, -1, gid); err != nil {
			return err
		}

		mode := info.Mode().Perm() | 0o040
		if info.IsDir() {
			mode |= 0o010
		}
		return os.Chmod(name, mode)
	})
}
