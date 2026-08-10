package tenant

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rjsocha/robinet/internal/hub"
	"golang.org/x/net/dns/dnsmessage"
)

// RouterPort is where the daemon answers DNS. Fixed, because it goes into a
// resolver's configuration and into a document; not 53, because something on
// the machine may already hold that.
const RouterPort = 5354

// Suffix is what every name this machine resolves through robinet ends with.
//
// One suffix for the whole tool rather than one per hub, so a query can be
// routed at a device by domain: ~<instance>.robinet goes to the link that
// instance runs on, and nothing else changes.
const Suffix = "robinet"

// routerRoute is one name space and the connector that answers for it.
//
// Virtual is what somebody types - <connector>.<instance>.robinet - and Real is
// what the connector's own resolver knows, which on a platform is a name that
// every deployment on it shares. Rewriting between the two is the whole point:
// two Railway projects both call their network railway.internal, and without
// this only one of them could be reached by name.
type routerRoute struct {
	Virtual string
	Real    string

	Via  netip.Addr
	IPv4 bool
	IPv6 bool
}

// routerTable is what the router answers for, rebuilt whenever the route table
// changes.
type routerTable struct {
	routes []routerRoute
}

// match finds the route a question belongs to, longest suffix first so a more
// specific name space wins.
func (t routerTable) match(name string) (routerRoute, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	var best routerRoute
	found := false

	for _, r := range t.routes {
		if name != r.Virtual && !strings.HasSuffix(name, "."+r.Virtual) {
			continue
		}
		if !found || len(r.Virtual) > len(best.Virtual) {
			best, found = r, true
		}
	}

	return best, found
}

// rewrite turns a question into what the connector's resolver will recognize.
func (r routerRoute) rewrite(name string) string {
	trimmed := strings.TrimSuffix(strings.ToLower(name), ".")

	if trimmed == r.Virtual {
		return r.Real + "."
	}
	return strings.TrimSuffix(trimmed, "."+r.Virtual) + "." + r.Real + "."
}

// restore turns a name in an answer back into what was asked about, so nothing
// downstream ever sees the platform's own name space.
func (r routerRoute) restore(name string) string {
	trimmed := strings.TrimSuffix(strings.ToLower(name), ".")

	if trimmed == r.Real {
		return r.Virtual + "."
	}
	if strings.HasSuffix(trimmed, "."+r.Real) {
		return strings.TrimSuffix(trimmed, "."+r.Real) + "." + r.Virtual + "."
	}

	// A name from somewhere else entirely, which the connector's resolver is
	// entitled to return. Left alone: rewriting it would be a lie.
	return name
}

// routerTableFor builds what one connection's router answers for.
//
// The names come from the hub's route table, which already says which
// connector carries which domain, so nothing new is asked of anybody and a
// connector admitted a minute ago becomes resolvable at the next refresh.
func routerTableFor(table *hub.RouteTable, instance string) routerTable {
	carries := map[netip.Addr]struct{ v4, v6 bool }{}
	for _, route := range table.Routes {
		c := carries[route.Via]
		if route.Prefix.Addr().Is4() {
			c.v4 = true
		} else {
			c.v6 = true
		}
		carries[route.Via] = c
	}

	var out routerTable
	for _, r := range table.Resolvers {
		if !r.Via.IsValid() {
			continue
		}

		// A member admitted before names were recorded has none. Its address
		// is stable and unique in the instance, so it stands in for one rather
		// than losing the connector its names.
		connector := r.Connector
		if connector == "" {
			connector = strings.ReplaceAll(r.Via.String(), ".", "-")
			connector = strings.ReplaceAll(connector, ":", "-")
		}

		c := carries[r.Via]
		out.routes = append(out.routes, routerRoute{
			Virtual: strings.ToLower(fmt.Sprintf("%s.%s.%s", connector, instance, Suffix)),
			Real:    strings.ToLower(strings.TrimSuffix(r.Domain, ".")),
			Via:     r.Via,
			IPv4:    c.v4,
			IPv6:    c.v6,
		})
	}

	return out
}

// Domains is what a resolver should send here.
func (t routerTable) Domains() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(t.routes))

	for _, r := range t.routes {
		if _, dup := seen[r.Virtual]; dup {
			continue
		}
		seen[r.Virtual] = struct{}{}
		out = append(out, r.Virtual)
	}

	return out
}

// router answers DNS for one connection, on that connection's own overlay
// address.
//
// On its own address rather than on loopback: a resolver told to use a server
// for one link sends the query out of that link, and loopback is not reachable
// that way. Reaching it from anywhere else is refused by the inbound firewall,
// which answers ping and nothing else unless this machine says otherwise.
type router struct {
	instance string
	log      *slog.Logger

	mu    sync.RWMutex
	table routerTable

	conn     *net.UDPConn
	listener net.Listener
}

// withAliases adds the extra names this machine answers under, each pointing
// at whatever its canonical name points at.
//
// An alias is local: the hub is not told, no other member sees it, and it
// changes nothing about who carries what. It is a name for the same thing.
func withAliases(t routerTable, aliases map[string]string) routerTable {
	for alias, canonical := range aliases {
		route, ok := t.match(canonical)
		if !ok {
			continue
		}

		route.Virtual = strings.ToLower(strings.TrimSuffix(alias, "."))
		t.routes = append(t.routes, route)
	}

	return t
}

func (d *Daemon) startRouter(conn *Connection, table *hub.RouteTable) error {
	if !conn.Address.IsValid() {
		return nil
	}

	d.routers.mu.Lock()
	defer d.routers.mu.Unlock()

	if r, ok := d.routers.running[conn.InstanceID]; ok {
		r.setTable(withAliases(routerTableFor(table, conn.Name), d.state.Aliases()))
		return nil
	}

	where := netip.AddrPortFrom(conn.Address.Addr(), RouterPort)

	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(where))
	if err != nil {
		return fmt.Errorf("could not answer dns on %s: %w", where, err)
	}

	// TCP as well: an answer over 512 bytes has nowhere else to go, and
	// rewriting makes answers longer than they arrived - a name under
	// <connector>.<instance>.robinet is rarely shorter than the platform's own.
	ln, err := net.Listen("tcp", where.String())
	if err != nil {
		pc.Close()
		return fmt.Errorf("could not answer dns on %s over tcp: %w", where, err)
	}

	r := &router{
		instance: conn.Name,
		log:      d.log.With("instance", conn.Name),
		conn:     pc,
		listener: ln,
	}
	r.setTable(withAliases(routerTableFor(table, conn.Name), d.state.Aliases()))

	d.routers.running[conn.InstanceID] = r
	go r.serve()
	go r.serveTCP()

	d.log.Info("answering dns", "instance", conn.Name, "address", where)

	return nil
}

func (d *Daemon) stopRouter(instance string) {
	d.routers.mu.Lock()
	defer d.routers.mu.Unlock()

	if r, ok := d.routers.running[instance]; ok {
		r.close()
		delete(d.routers.running, instance)
	}
}

// routerTableOf is what the dns commands need: where to send which names.
func (d *Daemon) routerTableOf(instance string) (routerTable, bool) {
	d.routers.mu.Lock()
	defer d.routers.mu.Unlock()

	r, ok := d.routers.running[instance]
	if !ok {
		return routerTable{}, false
	}
	return r.currentTable(), true
}

func (r *router) close() {
	r.conn.Close()
	if r.listener != nil {
		r.listener.Close()
	}
}

func (r *router) setTable(t routerTable) {
	r.mu.Lock()
	r.table = t
	r.mu.Unlock()
}

func (r *router) currentTable() routerTable {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.table
}

func (r *router) serve() {
	buf := make([]byte, 4096)

	for {
		n, from, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		go func() {
			answer, err := r.answer(query, false)
			if err != nil {
				r.log.Debug("could not answer", "error", err)
				return
			}
			if len(answer) == 0 {
				return
			}

			// Over what the client said it could take: say so rather than
			// send something it will not read, and it will ask again over TCP.
			if limit := udpLimit(query); len(answer) > limit {
				answer, err = truncate(query)
				if err != nil {
					return
				}
			}

			_, _ = r.conn.WriteToUDP(answer, from)
		}()
	}
}

// answer routes one query: rewrite the name, ask the connector, rewrite what
// comes back.
func (r *router) answer(query []byte, overTCP bool) ([]byte, error) {
	var parser dnsmessage.Parser

	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}

	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	route, ok := r.currentTable().match(question.Name.String())
	if !ok {
		return refuse(header, question, dnsmessage.RCodeNameError)
	}

	// A question about a family this connector does not carry has one honest
	// answer: nothing exists there. Passing it on would return an address the
	// asker has no route to, which is the failure this exists to prevent.
	switch question.Type {
	case dnsmessage.TypeA:
		if !route.IPv4 {
			return refuse(header, question, dnsmessage.RCodeSuccess)
		}
	case dnsmessage.TypeAAAA:
		if !route.IPv6 {
			return refuse(header, question, dnsmessage.RCodeSuccess)
		}
	}

	asked, err := rebuild(header, question, route.rewrite(question.Name.String()))
	if err != nil {
		return nil, err
	}

	reply, err := ask(route.Via, asked, overTCP)
	if err != nil {
		return nil, err
	}

	return restore(reply, question, route)
}

// ask sends a query to a connector and reads its answer, over whichever
// transport the question arrived on.
//
// A connector forwards both, so asking over TCP when we were asked over TCP
// keeps a large answer large all the way through instead of truncating it in
// the middle of the path.
func ask(via netip.Addr, query []byte, overTCP bool) ([]byte, error) {
	where := netip.AddrPortFrom(via, 53)

	if overTCP {
		conn, err := net.DialTimeout("tcp", where.String(), 5*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return nil, err
		}
		if err := writeTCPMessage(conn, query); err != nil {
			return nil, err
		}
		return readTCPMessage(conn)
	}

	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(where))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// rebuild writes the query again with a different name.
func rebuild(header dnsmessage.Header, question dnsmessage.Question, name string) ([]byte, error) {
	renamed, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, header)
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  renamed,
		Type:  question.Type,
		Class: question.Class,
	}); err != nil {
		return nil, err
	}

	return b.Finish()
}

// restore rewrites the names in an answer back into the ones asked about, and
// drops what the asker could not reach.
func restore(reply []byte, question dnsmessage.Question, route routerRoute) ([]byte, error) {
	var parser dnsmessage.Parser

	header, err := parser.Start(reply)
	if err != nil {
		return nil, err
	}
	if _, err := parser.AllQuestions(); err != nil {
		return nil, err
	}

	answers, err := parser.AllAnswers()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return nil, err
	}

	header.Response = true
	b := dnsmessage.NewBuilder(nil, header)
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	for _, a := range answers {
		name, err := dnsmessage.NewName(route.restore(a.Header.Name.String()))
		if err != nil {
			continue
		}
		a.Header.Name = name

		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			if !route.IPv4 {
				continue
			}
			if err := b.AResource(a.Header, *body); err != nil {
				return nil, err
			}
		case *dnsmessage.AAAAResource:
			if !route.IPv6 {
				continue
			}
			if err := b.AAAAResource(a.Header, *body); err != nil {
				return nil, err
			}
		case *dnsmessage.CNAMEResource:
			target, err := dnsmessage.NewName(route.restore(body.CNAME.String()))
			if err != nil {
				continue
			}
			if err := b.CNAMEResource(a.Header, dnsmessage.CNAMEResource{CNAME: target}); err != nil {
				return nil, err
			}
		default:
			// Anything else is passed over rather than passed on: this is a
			// router for addresses, and a record it does not understand cannot
			// be rewritten honestly.
		}
	}

	return b.Finish()
}

// refuse answers without asking anybody, for a name this machine does not
// route or a family it cannot reach.
func refuse(header dnsmessage.Header, question dnsmessage.Question, code dnsmessage.RCode) ([]byte, error) {
	header.Response = true
	header.RCode = code
	header.Authoritative = true

	b := dnsmessage.NewBuilder(nil, header)
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}

	return b.Finish()
}

// serveTCP answers queries that arrive with a length prefix, which is how a
// resolver asks again for an answer that did not fit.
func (r *router) serveTCP() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}

		go func() {
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			for {
				query, err := readTCPMessage(conn)
				if err != nil {
					return
				}

				answer, err := r.answer(query, true)
				if err != nil || len(answer) == 0 {
					return
				}

				if err := writeTCPMessage(conn, answer); err != nil {
					return
				}
			}
		}()
	}
}

// readTCPMessage reads one length prefixed message.
func readTCPMessage(conn net.Conn) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}

	n := int(size[0])<<8 | int(size[1])
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("a message of %d bytes", n)
	}

	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

func writeTCPMessage(conn net.Conn, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("an answer of %d bytes", len(msg))
	}

	framed := make([]byte, 2+len(msg))
	framed[0] = byte(len(msg) >> 8)
	framed[1] = byte(len(msg))
	copy(framed[2:], msg)

	_, err := conn.Write(framed)
	return err
}

// udpLimit is how much the client said it could take: 512 unless it asked for
// more with an OPT record, which is what EDNS0 is for.
func udpLimit(query []byte) int {
	const withoutEDNS = 512

	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		return withoutEDNS
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return withoutEDNS
	}
	if err := parser.SkipAllAnswers(); err != nil {
		return withoutEDNS
	}
	if err := parser.SkipAllAuthorities(); err != nil {
		return withoutEDNS
	}

	for {
		h, err := parser.AdditionalHeader()
		if err != nil {
			return withoutEDNS
		}
		if h.Type == dnsmessage.TypeOPT {
			// The class carries the size the sender can reassemble.
			if size := int(h.Class); size > withoutEDNS {
				return size
			}
			return withoutEDNS
		}
		if err := parser.SkipAdditional(); err != nil {
			return withoutEDNS
		}
	}
}

// truncate answers the question and nothing else, with the bit that tells a
// resolver to ask again over TCP.
func truncate(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser

	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}

	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	header.Response = true
	header.Truncated = true

	b := dnsmessage.NewBuilder(nil, header)
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}

	return b.Finish()
}
