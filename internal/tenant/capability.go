package tenant

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// capNetAdmin is CAP_NET_ADMIN, the bit that lets a process create a tun
// device, address it and install routes.
const capNetAdmin = 12

// CheckNetAdmin reports whether this process can bring up a tun device.
//
// Root is one way to have it, an ambient capability granted by systemd is
// another, and asking for the capability rather than for root is what lets the
// daemon run as the person who owns it.
func CheckNetAdmin() error {
	if os.Geteuid() == 0 {
		return nil
	}

	effective, err := effectiveCaps()
	if err != nil {
		return fmt.Errorf("could not read this process's capabilities: %w", err)
	}

	if effective&(1<<capNetAdmin) != 0 {
		return nil
	}

	return fmt.Errorf("no CAP_NET_ADMIN, so the tun device cannot be created: run under sudo, or let systemd grant the capability with robinet setup")
}

// effectiveCaps reads CapEff out of /proc/self/status, which avoids a
// dependency on a capability library for one bit.
func effectiveCaps() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		value, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		return strconv.ParseUint(strings.TrimSpace(value), 16, 64)
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no CapEff line in /proc/self/status")
}
