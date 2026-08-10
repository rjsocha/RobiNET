package tenant

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rjsocha/robinet/internal/hub"
)

// A mode is a way of telling this machine's resolver which connector answers
// for which names.
//
// There is one, and it is still named and looked up in a table rather than
// written as a branch: adding a second should be adding an entry, and somebody
// who asks for one that does not exist should be told what does.
//
// The daemon decides what should be configured; it does not configure it.
// Changing a resolver needs root - systemd-resolved asks polkit rather than
// looking at capabilities, and a machine without polkit refuses everybody but
// root - and this daemon deliberately holds one capability and nothing else.
// So the command line applies the plan, elevating itself the way every other
// root-needing command here does.
type mode struct {
	name string

	// install points the resolver for these domains at these addresses, on one
	// device. Replaces rather than adds, so running it twice is running it
	// once.
	install func(ctx context.Context, device string, servers []string, domains []string) error

	// remove takes it all off, for a connection that went away.
	remove func(ctx context.Context, device string) error
}

var modes = []mode{
	{
		name:    ModeSystemd,
		install: systemdInstall,
		remove:  systemdRemove,
	},
}

// Apply configures this machine's resolver from a plan. Run as root.
//
// It also takes away what is no longer in the plan: a connection that was
// detached or deleted leaves a file behind, and a file that names a device
// which no longer exists is a promise nothing keeps.
func Apply(ctx context.Context, name string, plan []DNSEntry) error {
	m, err := lookupMode(name)
	if err != nil {
		return err
	}

	keep := map[string]struct{}{}
	for _, e := range plan {
		if len(e.Domains) > 0 {
			keep[e.Device] = struct{}{}
		}
	}
	if err := sweep(ctx, keep); err != nil {
		return err
	}

	for _, e := range plan {
		if len(e.Domains) == 0 {
			if err := m.remove(ctx, e.Device); err != nil {
				return fmt.Errorf("%s: %w", e.Instance, err)
			}
			continue
		}
		if err := m.install(ctx, e.Device, e.Servers, e.Domains); err != nil {
			return fmt.Errorf("%s: %w", e.Instance, err)
		}
	}

	return nil
}

// ModeSystemd talks to systemd-resolved.
const ModeSystemd = "systemd"

// ErrNoResolver says the machine has no resolver this can talk to, which is
// not something to work around: writing /etc/resolv.conf is global, cannot say
// "this domain through this device", and is somebody else's file.
var ErrNoResolver = fmt.Errorf("resolvectl was not found, so nothing here can be told which connector answers for what")

// ModeNames is what an unrecognized mode is answered with.
func ModeNames() []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, m.name)
	}
	return out
}

func lookupMode(name string) (mode, error) {
	for _, m := range modes {
		if m.name == name {
			return m, nil
		}
	}
	return mode{}, fmt.Errorf("unknown mode %q, supported: %s", name, strings.Join(ModeNames(), ", "))
}

// DNSEntry is what one connection ended up installing.
type DNSEntry struct {
	Instance string   `json:"instance"`
	Device   string   `json:"device"`
	Servers  []string `json:"servers"`
	Domains  []string `json:"domains"`
}

// DNSPlan is what this machine's resolver should be told, one entry per
// connection.
//
// The route table already says which connector answers for which names, so
// nothing is decided here and nothing new is asked of the hub: this is that
// table, read for a different purpose.
func (d *Daemon) DNSPlan(ctx context.Context, remove bool) []DNSEntry {
	var out []DNSEntry

	for _, conn := range d.state.Connections() {
		entry := DNSEntry{Instance: conn.Name, Device: conn.Device}

		if remove || !conn.Ready() {
			// No domains means take it off, which is also what a connection
			// with nothing to answer for gets.
			out = append(out, entry)
			continue
		}

		// Read from the hub rather than from what the router happens to hold:
		// this runs the moment after a connector was admitted, and waiting for
		// the next refresh to notice would make a correct command look wrong.
		table, err := d.hub.routes(ctx, conn.InstanceID)
		if err != nil {
			d.log.Warn("could not read the route table", "instance", conn.Name, "error", err)
			out = append(out, entry)
			continue
		}

		rt := withAliases(routerTableFor(table, conn.Name), d.state.Aliases())

		// And tell the router, so what is installed and what answers are the
		// same thing.
		if err := d.startRouter(conn, table); err != nil {
			d.log.Warn("could not answer dns", "instance", conn.Name, "error", err)
		}

		// One server, this machine's own router, rather than one per
		// connector: a resolver attaches servers and domains to a link, not a
		// domain to a server, so with several connectors a query for one name
		// space could be sent to whichever of them answered first.
		entry.Domains = rt.Domains()
		if len(entry.Domains) > 0 {
			entry.Servers = []string{
				net.JoinHostPort(conn.Address.Addr().String(), strconv.Itoa(RouterPort)),
			}
		}

		out = append(out, entry)
	}

	return out
}

// networkUnitDir is where systemd-networkd reads link configuration from.
const networkUnitDir = "/etc/systemd/network"

// unitPrefix is what every file this writes is called, and 90 is not
// decoration: networkd applies the first file that matches a link, so this has
// to sort after everything that configures the machine's real interfaces and
// alongside the other overlay resolvers a machine may already carry.
const unitPrefix = "90-robinet-"

// networkUnitPath is one file per device.
func networkUnitPath(device string) string {
	return filepath.Join(networkUnitDir, unitPrefix+device+".network")
}

// systemdInstall writes the link's configuration and applies it now.
//
// A file, because the device is created afresh every time the daemon starts
// and anything set only at runtime dies with it - a resolver that has to be
// reinstalled after every restart is a resolver nobody can rely on.
//
// KeepConfiguration and the rest are what stop networkd taking the link over:
// the addresses and routes are nebula's, and this file is here to say one
// thing about names and nothing about anything else.
//
// The domains are written with ~, which makes them routing domains: queries
// for them go to this link, and nothing else about resolution changes. Without
// the tilde the link would be offered for every other name too.
func systemdInstall(ctx context.Context, device string, servers, domains []string) error {
	if err := haveResolved(ctx); err != nil {
		return err
	}

	routing := make([]string, 0, len(domains))
	for _, d := range domains {
		routing = append(routing, "~"+d)
	}

	unit := fmt.Sprintf(`# Written by robinet dns. Removed by robinet dns --remove.
#
# The addresses and routes on this link belong to nebula. This file says which
# names go to it, and nothing else.

[Match]
Name=%s

[Network]
KeepConfiguration=yes
ConfigureWithoutCarrier=yes
IgnoreCarrierLoss=yes
LinkLocalAddressing=no
LLMNR=no
DNS=%s
Domains=%s
`, device, strings.Join(servers, " "), strings.Join(routing, " "))

	if err := os.MkdirAll(networkUnitDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(networkUnitPath(device), []byte(unit), 0o644); err != nil {
		return err
	}

	reloadNetworkd(ctx)

	// And now, rather than at the next start: networkd only applies a file to a
	// link it manages, and this one may already be up under something else.
	if err := resolvectl(ctx, append([]string{"dns", device}, servers...)...); err != nil {
		return err
	}

	return resolvectl(ctx, append([]string{"domain", device}, routing...)...)
}

// systemdRemove takes the file away and clears what is set on the link, which
// is what resolvectl does with an empty list.
func systemdRemove(ctx context.Context, device string) error {
	if err := haveResolved(ctx); err != nil {
		return err
	}

	if err := os.Remove(networkUnitPath(device)); err == nil {
		reloadNetworkd(ctx)
	}

	if err := resolvectl(ctx, "domain", device); err != nil {
		return err
	}
	return resolvectl(ctx, "dns", device)
}

// reloadNetworkd tells it to read what was just written. A machine without
// networkd running is not a failure: the file is for the next start, and the
// link was configured directly anyway.
func reloadNetworkd(ctx context.Context) {
	if _, err := exec.LookPath("networkctl"); err != nil {
		return
	}
	_ = exec.CommandContext(ctx, "networkctl", "reload").Run()
}

// CheckResolver reports whether this machine has a resolver that can be told
// any of this. Reading a plan works without one, and saying so beforehand is
// better than an install that fails halfway.
func CheckResolver(ctx context.Context) error {
	return haveResolved(ctx)
}

// Only whether the binary is there. How somebody resolves names is theirs, and
// a machine can be arranged in more ways than this could ever check: what is
// left is refusing to guess and letting the real error speak if one comes.
func haveResolved(context.Context) error {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return ErrNoResolver
	}
	return nil
}

func resolvectl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "resolvectl", args...).CombinedOutput()
	if err == nil {
		return nil
	}

	text := strings.TrimSpace(string(out))

	// Changing a resolver is root's, and this is meant to be running as root
	// by the time it gets here.
	if strings.Contains(text, "Access denied") {
		return fmt.Errorf("systemd-resolved refused this: %s. It has to be run as root", text)
	}

	return fmt.Errorf("resolvectl %s: %s", strings.Join(args, " "), text)
}

// Reach is one network this machine can get to, and what to call things in it.
type Reach struct {
	Instance string       `json:"instance"`
	Network  netip.Prefix `json:"network"`

	// Carrier is the connector that carries it, and Names is the suffix its
	// names resolve under - empty when it announced no domain, which means
	// addresses are the only way in.
	Carrier string `json:"carrier"`
	Names   string `json:"names,omitempty"`

	// Installed says whether this machine's resolver has been told about it.
	Installed bool `json:"installed"`
}

// Reachable is what this machine can reach and what it may call it.
//
// The route table answers both halves and nothing else has to be asked: a
// prefix says where traffic goes, a resolver entry says which connector
// answers about names, and the two are joined by the member carrying them.
func (d *Daemon) Reachable(ctx context.Context) []Reach {
	var out []Reach

	for _, conn := range d.state.Connections() {
		if !conn.Ready() {
			continue
		}

		table, err := d.hub.routes(ctx, conn.InstanceID)
		if err != nil {
			d.log.Warn("could not read the route table", "instance", conn.Name, "error", err)
			continue
		}

		names := map[netip.Addr]string{}
		for _, r := range routerTableFor(table, conn.Name).routes {
			names[r.Via] = r.Virtual
		}

		installed := map[string]struct{}{}
		if rt, ok := d.routerTableOf(conn.InstanceID); ok {
			for _, domain := range rt.Domains() {
				installed[domain] = struct{}{}
			}
		}

		for _, route := range table.Routes {
			// Our own is not somewhere to reach: it is where we are.
			if route.Via == conn.Address.Addr() {
				continue
			}

			entry := Reach{
				Instance: conn.Name,
				Network:  route.Prefix,
				Carrier:  route.Connector,
				Names:    names[route.Via],
			}
			_, entry.Installed = installed[entry.Names]

			out = append(out, entry)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Instance != out[j].Instance {
			return out[i].Instance < out[j].Instance
		}
		return out[i].Network.String() < out[j].Network.String()
	})

	return out
}

// SetAlias gives a name space a second name on this machine, or takes one
// away when canonical is empty.
//
// Local and told to nobody: it changes what this machine calls something, not
// what anybody carries. The canonical name has to exist, because an alias for
// nothing would resolve to nothing and look like a fault.
func (d *Daemon) SetAlias(ctx context.Context, alias, canonical string) error {
	// Nothing named at all is a question, not a change: it is how asking what
	// aliases exist arrives here.
	if alias == "" && canonical == "" {
		return nil
	}

	name, err := hub.ParseMemberName(alias)
	if err != nil {
		return fmt.Errorf("%q cannot be a name: %w", alias, err)
	}

	if canonical == "" {
		return d.state.SetAlias(name, "")
	}

	target, err := hub.ParseMemberName(canonical)
	if err != nil {
		return fmt.Errorf("%q cannot be a name: %w", canonical, err)
	}

	known := false
	for _, conn := range d.state.Connections() {
		if !conn.Ready() {
			continue
		}
		table, err := d.hub.routes(ctx, conn.InstanceID)
		if err != nil {
			continue
		}
		if _, ok := routerTableFor(table, conn.Name).match(target); ok {
			known = true
			break
		}
	}

	if !known {
		return fmt.Errorf("nothing here answers for %s: robinet reach says what does", target)
	}

	if name == target {
		return fmt.Errorf("%s is already its own name", name)
	}

	return d.state.SetAlias(name, target)
}

// sweep removes the files of devices no longer being configured, and is what
// makes install idempotent rather than cumulative.
func sweep(ctx context.Context, keep map[string]struct{}) error {
	files, err := filepath.Glob(filepath.Join(networkUnitDir, unitPrefix+"*.network"))
	if err != nil {
		return err
	}

	removed := false
	for _, file := range files {
		device := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(file), unitPrefix), ".network")
		if _, wanted := keep[device]; wanted {
			continue
		}
		if err := os.Remove(file); err == nil {
			removed = true
		}
	}

	if removed {
		reloadNetworkd(ctx)
	}

	return nil
}

// RemoveAll takes every robinet resolver file away, whatever this machine is
// still connected to. It is what cleaning up after the daemon has to do.
func RemoveAll(ctx context.Context) error {
	return sweep(ctx, nil)
}
