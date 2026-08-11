package tenant

import (
	"net/netip"
	"testing"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"golang.org/x/net/dns/dnsmessage"
)

func railwayTable() *hub.RouteTable {
	return &hub.RouteTable{
		Instance:   "example",
		Lighthouse: enroll.Lighthouse{},
		Routes: []hub.Route{
			{Prefix: netip.MustParsePrefix("fd12:1::/64"), Via: netip.MustParseAddr("198.19.0.254"), Connector: "prod"},
			{Prefix: netip.MustParsePrefix("fd12:2::/64"), Via: netip.MustParseAddr("198.19.0.253"), Connector: "staging"},
		},
		Resolvers: []hub.Resolver{
			{Domain: "railway.internal", Via: netip.MustParseAddr("198.19.0.254"), Connector: "prod"},
			{Domain: "railway.internal", Via: netip.MustParseAddr("198.19.0.253"), Connector: "staging"},
		},
	}
}

// Two Railway projects call their network the same thing. The connector's own
// name is what tells them apart, and it is unique in an instance.
func TestOneDomainTwoConnectorsBecomeTwoNameSpaces(t *testing.T) {
	table := routerTableFor(railwayTable(), "example")

	domains := table.Domains()
	if len(domains) != 2 {
		t.Fatalf("domains are %v", domains)
	}

	prod, ok := table.match("mysql.prod.example.robinet")
	if !ok {
		t.Fatal("prod does not resolve")
	}
	if prod.Via.String() != "198.19.0.254" {
		t.Fatalf("prod goes to %s", prod.Via)
	}

	staging, ok := table.match("mysql.staging.example.robinet")
	if !ok {
		t.Fatal("staging does not resolve")
	}
	if staging.Via.String() != "198.19.0.253" {
		t.Fatalf("staging goes to %s", staging.Via)
	}

	if _, ok := table.match("mysql.railway.internal"); ok {
		t.Fatal("the platform's own name space is answered for, which is the collision this avoids")
	}
}

// The name asked about and the name the connector's resolver knows are
// different, and neither side ever sees the other's.
func TestNamesAreRewrittenBothWays(t *testing.T) {
	table := routerTableFor(railwayTable(), "example")

	route, ok := table.match("mysql.prod.example.robinet")
	if !ok {
		t.Fatal("no route")
	}

	if got := route.rewrite("mysql.prod.example.robinet."); got != "mysql.railway.internal." {
		t.Errorf("asked the connector about %q", got)
	}
	if got := route.restore("mysql.railway.internal."); got != "mysql.prod.example.robinet." {
		t.Errorf("answered with %q", got)
	}

	// A name from somewhere else is left alone rather than rewritten into
	// something it is not.
	if got := route.restore("something.else."); got != "something.else." {
		t.Errorf("a foreign name became %q", got)
	}
}

// A connector carrying only IPv6 has no IPv4 address to offer, and saying so
// beats answering with one nobody can reach.
func TestFamiliesFollowWhatIsCarried(t *testing.T) {
	table := routerTableFor(railwayTable(), "example")

	route, _ := table.match("mysql.prod.example.robinet")
	if route.IPv4 {
		t.Error("an IPv6 only connector was marked as carrying IPv4")
	}
	if !route.IPv6 {
		t.Error("an IPv6 connector was not marked as carrying IPv6")
	}
}

// A resolver says how much it can take with an OPT record. Without one the
// answer is the old 512 bytes, whatever it would like.
func TestTheClientSaysHowMuchItCanTake(t *testing.T) {
	plain := query(t, "mysql.prod.example.robinet.", 0)
	if got := udpLimit(plain); got != 512 {
		t.Errorf("a query with no OPT gave %d", got)
	}

	edns := query(t, "mysql.prod.example.robinet.", 1232)
	if got := udpLimit(edns); got != 1232 {
		t.Errorf("a query advertising 1232 gave %d", got)
	}
}

// An answer that does not fit is answered with the bit that says "ask again
// over TCP", rather than with something the asker will not read.
func TestTooBigIsTruncatedRatherThanSent(t *testing.T) {
	q := query(t, "mysql.prod.example.robinet.", 0)

	answer, err := truncate(q)
	if err != nil {
		t.Fatal(err)
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(answer)
	if err != nil {
		t.Fatal(err)
	}
	if !header.Truncated || !header.Response {
		t.Fatalf("header is %+v", header)
	}
}

func query(t *testing.T, name string, udpSize uint16) []byte {
	t.Helper()

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}

	if udpSize > 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: dnsmessage.Class(udpSize),
		}, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A connector that asked for no name is called after where it runs, because
// that is what the hints it sent are for and what somebody will recognize.
func TestANamelessConnectorIsNamedAfterWhereItRuns(t *testing.T) {
	record := &hub.Record{Kind: hub.KindConnector}
	record.Fingerprint = "69fbefafda9ea914aaaabbbbccccdddd"
	record.Request.Hints = map[string]string{
		"project":     "disciplined-caring",
		"environment": "production",
		"service":     "robinet-connector",
	}

	if got := defaultName(record); got != "production.disciplined-caring" {
		t.Fatalf("named %q", got)
	}

	// Nothing to go on: its key, which is at least unique.
	bare := &hub.Record{Kind: hub.KindConnector}
	bare.Fingerprint = "69fbefafda9ea914aaaabbbbccccdddd"
	if got := defaultName(bare); got != "connector-69fbefaf" {
		t.Fatalf("named %q", got)
	}
}

// Hints are the applicant's own words, so whatever arrives has to come out as
// something that can stand in a domain name.
func TestHintsBecomeLabels(t *testing.T) {
	for raw, want := range map[string]string{
		"My Project":     "my-project",
		"acme_prod":      "acme-prod",
		"  spaced  out ": "spaced-out",
		"--edges--":      "edges",
	} {
		got, ok := asLabel(raw)
		if !ok || got != want {
			t.Errorf("%q became %q", raw, got)
		}
	}

	if _, ok := asLabel("###"); ok {
		t.Error("something with no letters at all was accepted")
	}
}

// The lighthouse holds the one list of who is in an instance, by certificate
// name, so <instance>.instance is a name space of its own and the resolver has
// to be told about it alongside the connectors'.
func TestLighthouseNamesAreRoutedToTheLighthouse(t *testing.T) {
	table := railwayTable()
	table.Lighthouse = enroll.Lighthouse{
		OverlayAddress:  netip.MustParseAddr("198.19.128.1"),
		OverlayAddress6: netip.MustParseAddr("fd9a:336b:46f6::1"),
	}

	rt := routerTableFor(table, "example")

	var found bool
	for _, d := range rt.Domains() {
		if d == "example.instance" {
			found = true
		}
	}
	if !found {
		t.Fatalf("domains are %v, without the instance's own name space", rt.Domains())
	}

	route, ok := rt.match("hub.example.instance")
	if !ok {
		t.Fatal("a certificate name does not resolve")
	}

	// Its IPv4 address: nebula's lighthouse DNS binds one address, and that is
	// the one it binds.
	if route.Via.String() != "198.19.128.1" {
		t.Fatalf("the question goes to %s", route.Via)
	}

	// And nothing is rewritten on the way. A connector's name space stands in
	// for a name its own resolver knows; this one is already the real thing.
	if got := route.rewrite("hub.example.instance."); got != "hub.example.instance." {
		t.Fatalf("the name was rewritten to %s", got)
	}

	// Both families come back. Which address the question travelled to says
	// nothing about what the answer may hold.
	if !route.IPv4 || !route.IPv6 {
		t.Fatalf("families are v4=%v v6=%v", route.IPv4, route.IPv6)
	}
}
