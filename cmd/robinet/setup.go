package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func newSetupCmd() *cobra.Command {
	var (
		state    string
		socket   string
		binary   string
		noEnable bool
		cleanup  bool
		force    bool
		logging  string
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install and start the tenant daemon as a system service",
		Long: `setup writes a systemd unit for the tenant daemon and starts it.

Run it without sudo: it elevates itself with its own absolute path, because
robinet usually lives in ~/.local/bin and that is not on root's PATH.

The unit runs as you with one capability, CAP_NET_ADMIN, for the tun device.
Everything else - the state, the keys, the socket - stays yours.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cleanup {
				if os.Geteuid() != 0 {
					return elevate()
				}
				return cleanupTenant(cmd.Context(), state, force)
			}

			// Before elevating, not after: asking for a password and then
			// refusing is a worse way to say the same thing.
			statePath, err := statePath(state)
			if err != nil {
				return err
			}
			if _, err := os.Stat(statePath); err != nil {
				return fmt.Errorf("this machine is not registered with a hub yet: robinet join")
			}

			if os.Geteuid() != 0 {
				// robinet usually lives in ~/.local/bin, which is not on
				// root's secure_path, so "sudo robinet" fails to find it.
				// Re-exec with the absolute path rather than telling people
				// to work around that themselves.
				return elevate()
			}

			sockPath, err := socketPath(socket)
			if err != nil {
				return err
			}

			exePath := binary
			if exePath == "" {
				exePath, err = os.Executable()
				if err != nil {
					return fmt.Errorf("could not find this binary: %w", err)
				}
				exePath, err = filepath.EvalSymlinks(exePath)
				if err != nil {
					return fmt.Errorf("could not resolve this binary: %w", err)
				}
			}

			owner, err := ownerOf(statePath)
			if err != nil {
				return err
			}

			unit := renderUnit(exePath, statePath, sockPath, logging, owner)
			if err := os.WriteFile(tenantUnitPath, []byte(unit), 0o644); err != nil {
				return fmt.Errorf("could not write %s: %w", tenantUnitPath, err)
			}
			fmt.Printf("wrote %s\n", tenantUnitPath)

			if noEnable {
				fmt.Println("run: systemctl daemon-reload && systemctl enable --now robinet")
				return nil
			}

			// restart rather than enable --now: running setup again after an
			// upgrade is how the daemon picks up the new binary, and
			// enable --now leaves an already running service alone.
			for _, args := range [][]string{
				{"daemon-reload"},
				{"enable", "robinet"},
				{"restart", "robinet"},
			} {
				out, err := exec.CommandContext(cmd.Context(), "systemctl", args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("systemctl %v failed: %s", args, out)
				}
			}

			fmt.Printf("robinet is running, drive it with: robinet status\n")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&state, "state", "", "state file (default is the invoking user's)")
	f.StringVar(&socket, "socket", "", "control socket")
	f.StringVar(&binary, "binary", "", "path to write into the unit (default is this binary, resolved)")
	f.BoolVar(&noEnable, "no-enable", false, "write the unit only, and leave systemd alone")
	f.BoolVar(&cleanup, "cleanup", false, "remove the service and everything this machine keeps")
	f.BoolVar(&force, "force", false, "required by --cleanup: it destroys the authorities of instances this machine owns")
	f.StringVar(&logging, "log", "info", "log level for the service")

	return cmd
}

// elevate re-runs this command under sudo, with this binary's absolute path.
func elevate() error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("setup needs root and sudo is not installed: run it as root")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find this binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	args := append([]string{"sudo", "--", exe}, os.Args[1:]...)
	fmt.Printf("elevating: sudo %s %s\n", exe, strings.Join(os.Args[1:], " "))

	// Exec rather than run, so the password prompt keeps the terminal and the
	// exit status is the command's own.
	return syscall.Exec(sudo, args, os.Environ())
}

func renderUnit(exePath, statePath, socketPath, logLevel, owner string) string {
	// The daemon runs as its owner with one capability rather than as root:
	// creating a tun device, addressing it and installing routes is all
	// CAP_NET_ADMIN, and nothing else here wants privilege.
	//
	// RuntimeDirectory gives us /run/robinet without a tmpfiles rule, owned by
	// that same user, and systemd removes it when the service stops.
	//
	// Restart=always rather than on-failure: robinet restart asks the daemon to
	// exit cleanly so it comes back on a newly installed binary, and a clean
	// exit is not a failure. Systemd's start limit still gives up on a daemon
	// that cannot start at all.
	return fmt.Sprintf(`[Unit]
Description=robinet tenant daemon
Documentation=https://github.com/rjsocha/robinet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
ExecStart=%s up --state %s --socket %s --log %s
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
DeviceAllow=/dev/net/tun rw
RuntimeDirectory=robinet
RuntimeDirectoryMode=0750
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
PrivateTmp=yes
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, owner, exePath, statePath, socketPath, logLevel, filepath.Dir(statePath))
}

// ownerOf is the user a path belongs to, which is the person who ran init.
func ownerOf(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("could not read the owner of %s", path)
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return "", fmt.Errorf("could not resolve uid %d: %w", stat.Uid, err)
	}

	return u.Username, nil
}
