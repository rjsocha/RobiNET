package tenant

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
)

// dualStackConnection is a member with an address of each family, which is what
// the probe route needs to be worth installing.
func dualStackConnection() *Connection {
	return &Connection{
		InstanceID:  "01HZ",
		Name:        "home",
		Certificate: "a certificate",
		CA:          "an authority",
		Device:      "robinet0",
		Address:     netip.MustParsePrefix("198.19.0.2/24"),
		Address6:    netip.MustParsePrefix("fd12:3456:789a:4::2/64"),
		Lighthouse: enroll.Lighthouse{
			OverlayAddress: netip.MustParseAddr("198.19.0.1"),
			Endpoints:      []string{"203.0.113.1:8443"},
		},
	}
}

func renderedWith(t *testing.T, conn *Connection, local choices) string {
	t.Helper()

	raw, err := renderConfig(conn, &hub.RouteTable{}, local)
	if err != nil {
		t.Fatalf("could not render the config: %v", err)
	}
	return string(raw)
}

func TestTheProbeAddressIsAbsentUntilItIsAskedFor(t *testing.T) {
	cfg := renderedWith(t, dualStackConnection(), choices{families: FamiliesBoth, inbound: InboundPing})

	if strings.Contains(cfg, chromiumProbe.String()) {
		t.Fatalf("the probe route was installed without being asked for:\n%s", cfg)
	}
}

func TestTheProbeRouteGoesToTheLighthouse(t *testing.T) {
	conn := dualStackConnection()
	cfg := renderedWith(t, conn, choices{families: FamiliesBoth, inbound: InboundPing, chromiumProbeRoute: true})

	if !strings.Contains(cfg, chromiumProbe.String()) {
		t.Fatalf("the probe route is missing:\n%s", cfg)
	}
	// A via has to be somebody, and the lighthouse is the one peer every
	// connection has.
	if !strings.Contains(cfg, conn.Lighthouse.OverlayAddress.String()) {
		t.Fatalf("the probe route has no via:\n%s", cfg)
	}
}

// Without an IPv6 address on the device the kernel has no source to answer
// with, so the probe fails anyway and the address would be hijacked for
// nothing.
func TestTheProbeRouteNeedsAnIPv6AddressToBeWorthInstalling(t *testing.T) {
	conn := dualStackConnection()
	conn.Address6 = netip.Prefix{}

	cfg := renderedWith(t, conn, choices{families: FamiliesBoth, inbound: InboundPing, chromiumProbeRoute: true})

	if strings.Contains(cfg, chromiumProbe.String()) {
		t.Fatalf("an IPv6 route was installed on a connection with no IPv6 address:\n%s", cfg)
	}
}

// A machine that installs IPv4 routes only installs no IPv6 route either, cheat
// or not: the local choice about families is not something a cheat overrides.
func TestTheProbeRouteObeysTheFamilyChoice(t *testing.T) {
	cfg := renderedWith(t, dualStackConnection(), choices{families: FamiliesIPv4, inbound: InboundPing, chromiumProbeRoute: true})

	if strings.Contains(cfg, chromiumProbe.String()) {
		t.Fatalf("an IPv6 route was installed by a machine that installs IPv4 only:\n%s", cfg)
	}
}

func TestACheatNobodyImplementsIsRefused(t *testing.T) {
	if ValidCheat("firefox", CheatChromiumProbeRoute) || ValidCheat(CheatChromium, "whatever") {
		t.Fatal("a cheat that does not exist was accepted")
	}
}

// This build is not a variant build, so nothing a state file says can turn a
// cheat on. A state file written by a build that allows them must not keep one
// alive under a build that does not.
func TestAPlainBuildAppliesNoCheatWhateverTheStateSays(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("could not open the state: %v", err)
	}

	if err := state.SetCheat(CheatChromium, CheatChromiumProbeRoute, true); err != nil {
		t.Fatalf("could not record the cheat: %v", err)
	}

	if state.choices().chromiumProbeRoute {
		t.Fatal("a plain build applied a cheat")
	}
	if len(state.CheatsOn()) != 0 {
		t.Fatalf("a plain build reported cheats: %v", state.CheatsOn())
	}
}
