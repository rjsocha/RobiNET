package tenant

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// The daemon is single user by definition: one authority, one instance, one
// person deciding. So its state lives with that person, not in a machine wide
// directory, and the only thing root is needed for is the tun device.

// DefaultStatePath returns where this user's state lives.
//
// Running as root it resolves the invoking user's home instead, because root
// running the daemon is a means to an end and not a second operator.
func DefaultStatePath() (string, error) {
	home, err := ownerHome()
	if err != nil {
		return "", err
	}

	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" && os.Geteuid() != 0 {
		return filepath.Join(xdg, "robinet", "tenant.json"), nil
	}

	return filepath.Join(home, ".local", "state", "robinet", "tenant.json"), nil
}

// DefaultSocketPath is where the control socket lives.
//
// A system path rather than XDG_RUNTIME_DIR, because /run/user/<uid> only
// exists while that user is logged in and the daemon starts at boot. The
// socket itself is chowned to the owner, so it is still theirs alone.
func DefaultSocketPath() (string, error) {
	return "/run/robinet/robinet.sock", nil
}

// ownerName is the user the daemon belongs to: the invoking one, or whoever
// called sudo.
func ownerName() (string, error) {
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			return name, nil
		}
	}

	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func ownerHome() (string, error) {
	name, err := ownerName()
	if err != nil {
		return "", err
	}

	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("could not resolve %s: %w", name, err)
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("%s has no home directory, pass --state", name)
	}

	return u.HomeDir, nil
}

func ownerIDs() (uid, gid int, _ error) {
	name, err := ownerName()
	if err != nil {
		return 0, 0, err
	}

	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}

	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}

	return uid, gid, nil
}
