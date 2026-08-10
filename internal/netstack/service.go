// Package netstack runs a gvisor network stack on top of a nebula user space
// device. It gives a process mesh connectivity with no tun device, and it can
// forward what arrives from the mesh onto the host network.
package netstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/slackhq/nebula"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

// Device is the part of a user space overlay device this package needs.
type Device interface {
	Networks() []netip.Prefix
	Pipe() (*io.PipeReader, *io.PipeWriter)
}

// Dialer opens the outbound half of a forwarded flow. Satisfied by *net.Dialer.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options configures optional behavior. The zero value is a plain mesh member
// that neither forwards nor answers DNS.
type Options struct {
	// Gateway forwards TCP and UDP arriving for an address other than our own
	// overlay addresses onto the host network. ICMP is not forwarded.
	Gateway bool

	// GatewayUDPTimeout is how long a forwarded UDP flow may idle. Default 60s.
	GatewayUDPTimeout time.Duration

	// DNS answers queries sent to DNSPort on one of our own overlay addresses
	// by forwarding them to the resolver this host uses.
	DNS bool

	// DNSUpstreams are the resolvers to forward to. Defaults to the nameservers
	// in DNSResolvConf. Only the first is used.
	DNSUpstreams []string

	// DNSResolvConf defaults to /etc/resolv.conf.
	DNSResolvConf string

	// DNSPort defaults to 53.
	DNSPort uint16

	// DNSIdleTimeout defaults to 10s.
	DNSIdleTimeout time.Duration

	// HostDialer dials forwarded flows on the host network. Default *net.Dialer.
	HostDialer Dialer

	// HostDialTimeout defaults to 10s.
	HostDialTimeout time.Duration

	// MTU of the stack. Keep it under the host link MTU minus about sixty bytes
	// of nebula overhead. Default 1280.
	MTU uint32

	// Logger receives forwarding errors. Defaults to slog.Default().
	Logger *slog.Logger
}

func (o *Options) applyDefaults() {
	if o.HostDialer == nil {
		o.HostDialer = &net.Dialer{}
	}
	if o.HostDialTimeout == 0 {
		o.HostDialTimeout = 10 * time.Second
	}
	if o.GatewayUDPTimeout == 0 {
		o.GatewayUDPTimeout = 60 * time.Second
	}
	if o.DNSPort == 0 {
		o.DNSPort = 53
	}
	if o.DNSIdleTimeout == 0 {
		o.DNSIdleTimeout = 10 * time.Second
	}
	if o.MTU == 0 {
		o.MTU = 1280
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Service is a running network stack attached to a nebula control.
type Service struct {
	eg      *errgroup.Group
	control *nebula.Control
	ipstack *stack.Stack

	ctx  context.Context
	opts Options

	// localAddrs are our own overlay addresses. Anything else is a candidate
	// for gateway forwarding.
	localAddrs map[tcpip.Address]struct{}

	mu struct {
		sync.Mutex

		listeners map[uint16]*tcpListener
	}
}

// New starts nebula and attaches a network stack to the given device. The
// device must be the one nebula was built with.
func New(control *nebula.Control, device Device, opts Options) (_ *Service, reterr error) {
	opts.applyDefaults()

	if opts.DNS {
		if err := resolveDNSUpstreams(&opts); err != nil {
			return nil, err
		}
	}

	if err := control.Start(); err != nil {
		return nil, err
	}

	defer func() {
		if reterr != nil {
			control.Stop()
		}
	}()

	ctx := control.Context()
	eg, ctx := errgroup.WithContext(ctx)

	s := Service{
		eg:         eg,
		control:    control,
		ctx:        ctx,
		opts:       opts,
		localAddrs: map[tcpip.Address]struct{}{},
	}
	s.mu.listeners = map[uint16]*tcpListener{}

	// No duplicate address detection: there is nothing here to detect. An
	// overlay address is allocated by the hub and written into a certificate,
	// no two members can hold the same one, and the solicitation goes into a
	// mesh where nothing answers it.
	//
	// What it costs is the second after startup during which the address is
	// tentative and every packet to it is dropped without a word.
	ipv6Protocol := ipv6.NewProtocolWithOptions(ipv6.Options{
		DADConfigs: stack.DADConfigurations{DupAddrDetectTransmits: 0},
	})

	s.ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6Protocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	sackEnabled := tcpip.TCPSACKEnabled(true)
	if err := s.ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled); err != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}

	linkEP := channel.New(512, opts.MTU, "")
	if err := s.ipstack.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", err)
	}

	v4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFrom(strings.Repeat("\x00", 4)))
	v6Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFrom(strings.Repeat("\x00", 16)))
	s.ipstack.SetRouteTable([]tcpip.Route{
		{Destination: v4Subnet, NIC: nicID},
		{Destination: v6Subnet, NIC: nicID},
	})

	for _, network := range device.Networks() {
		addr := network.Addr().Unmap()
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
			Protocol:          protocolNumber(addr),
		}
		if err := s.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("could not add %s to the stack: %v", addr, err)
		}
		s.localAddrs[pa.AddressWithPrefix.Address] = struct{}{}
	}

	if opts.Gateway {
		// Accept packets not addressed to us, and let the stack answer from
		// those addresses, otherwise forwarded flows are dropped.
		if err := s.ipstack.SetPromiscuousMode(nicID, true); err != nil {
			return nil, fmt.Errorf("could not enable promiscuous mode: %v", err)
		}
		if err := s.ipstack.SetSpoofing(nicID, true); err != nil {
			return nil, fmt.Errorf("could not enable spoofing: %v", err)
		}
	}

	if opts.Gateway || opts.DNS {
		udpFwd := udp.NewForwarder(s.ipstack, s.udpHandler)
		s.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	}

	const maxInFlight = 1024
	tcpFwd := tcp.NewForwarder(s.ipstack, 0, maxInFlight, s.tcpHandler)
	s.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	reader, writer := device.Pipe()

	go func() {
		<-ctx.Done()
		reader.Close()
		writer.Close()
	}()

	eg.Go(func() error {
		buf := make([]byte, header.IPv4MaximumHeaderSize+header.IPv4MaximumPayloadSize)
		for {
			n, err := reader.Read(buf)
			if err != nil {
				return err
			}
			if n == 0 {
				continue
			}

			protocol := header.IPv4ProtocolNumber
			if buf[0]>>4 == 6 {
				protocol = header.IPv6ProtocolNumber
			}

			// At debug, because the question "does anything arrive at all" has
			// no other answer: there is no interface to watch, and a packet
			// that is dropped inside the stack leaves nothing behind.
			s.opts.Logger.Debug("packet in", describePacket(buf[:n])...)

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buf[:n])),
			})
			linkEP.InjectInbound(protocol, pkt)

			if err := ctx.Err(); err != nil {
				return err
			}
		}
	})

	eg.Go(func() error {
		for {
			pkt := linkEP.ReadContext(ctx)
			if pkt == nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				continue
			}

			view := pkt.ToView()
			if _, err := view.WriteTo(writer); err != nil {
				return err
			}
			view.Release()
		}
	})

	// The stack drops packets for a dozen different reasons and says nothing
	// about any of them. Its counters are the only place that does, so at debug
	// they are printed whenever one of them moves.
	eg.Go(func() error {
		s.watchDrops(ctx)
		return nil
	})

	eg.Go(control.Wait)

	return &s, nil
}

func protocolNumber(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

// DialContext dials through the mesh.
func (s *Service) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		full := tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFromSlice(addr.IP),
			Port: uint16(addr.Port),
		}
		return gonet.DialUDP(s.ipstack, nil, &full, protocolNumber(addr.AddrPort().Addr()))

	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		full := tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFromSlice(addr.IP),
			Port: uint16(addr.Port),
		}
		return gonet.DialContextTCP(ctx, s.ipstack, full, protocolNumber(addr.AddrPort().Addr()))

	default:
		return nil, fmt.Errorf("unknown network type: %s", network)
	}
}

// Dial dials through the mesh.
func (s *Service) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// Listen accepts mesh connections on a port. Only wildcard TCP is supported.
func (s *Service) Listen(network, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("only tcp is supported")
	}

	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	if addr.IP != nil && !bytes.Equal(addr.IP, []byte{0, 0, 0, 0}) {
		return nil, fmt.Errorf("only the wildcard address is supported, got %q", address)
	}
	if addr.Port <= 0 || addr.Port >= math.MaxUint16 {
		return nil, fmt.Errorf("invalid port %d", addr.Port)
	}

	l := &tcpListener{
		s:      s,
		addr:   addr,
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.mu.listeners[uint16(addr.Port)]; ok {
		return nil, fmt.Errorf("already listening on port %d", addr.Port)
	}
	s.mu.listeners[uint16(addr.Port)] = l

	return l, nil
}

// Wait blocks until the stack or nebula stops.
func (s *Service) Wait() error { return s.eg.Wait() }

// Close stops nebula, which stops the stack.
func (s *Service) Close() error {
	s.control.Stop()
	return nil
}

// MTU of the stack.
func (s *Service) MTU() uint32 { return s.opts.MTU }

// DNSUpstreams are the resolvers queries are forwarded to, after the host
// resolver configuration has been read.
func (s *Service) DNSUpstreams() []string {
	return append([]string(nil), s.opts.DNSUpstreams...)
}

func (s *Service) isLocalAddress(addr tcpip.Address) bool {
	_, ok := s.localAddrs[addr]
	return ok
}

func (s *Service) tcpHandler(r *tcp.ForwarderRequest) {
	id := r.ID()

	s.opts.Logger.Debug("tcp flow",
		"local", id.LocalAddress.String(), "port", id.LocalPort,
		"remote", id.RemoteAddress.String(),
		"mine", s.isLocalAddress(id.LocalAddress),
	)

	if !s.isLocalAddress(id.LocalAddress) {
		if s.opts.Gateway {
			s.forwardTCP(r, hostAddress(id))
			return
		}
		r.Complete(true)
		return
	}

	s.mu.Lock()
	l, ok := s.mu.listeners[id.LocalPort]
	s.mu.Unlock()

	if !ok {
		if s.opts.DNS && id.LocalPort == s.opts.DNSPort {
			s.forwardTCP(r, s.dnsUpstream())
			return
		}
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		s.opts.Logger.Error("could not create endpoint", "error", fmt.Sprint(err))
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)

	conn := gonet.NewTCPConn(&wq, ep)

	// Handing the connection over must not block the packet loop.
	go func() {
		select {
		case l.accept <- conn:
		case <-l.closed:
			conn.Close()
		case <-s.ctx.Done():
			conn.Close()
		}
	}()
}

// describePacket names what a packet is, for a log line. It reads the header
// and nothing else, and says so rather than guessing when it cannot.
func describePacket(b []byte) []any {
	if len(b) < 1 {
		return []any{"len", len(b)}
	}

	switch b[0] >> 4 {
	case 4:
		if len(b) < header.IPv4MinimumSize {
			return []any{"family", "ipv4", "len", len(b), "note", "too short to read"}
		}
		h := header.IPv4(b)
		return []any{
			"family", "ipv4",
			"src", h.SourceAddress().String(),
			"dst", h.DestinationAddress().String(),
			"proto", h.Protocol(),
			"len", len(b),
		}
	case 6:
		if len(b) < header.IPv6MinimumSize {
			return []any{"family", "ipv6", "len", len(b), "note", "too short to read"}
		}
		h := header.IPv6(b)
		return []any{
			"family", "ipv6",
			"src", h.SourceAddress().String(),
			"dst", h.DestinationAddress().String(),
			"proto", h.NextHeader(),
			"len", len(b),
		}
	default:
		return []any{"family", "unknown", "len", len(b)}
	}
}

// watchDrops reports the stack's own counters when they change.
//
// A packet that reaches the stack and is never seen again has left exactly one
// trace: a number. Which number it is names the reason - a destination the
// stack does not consider its own, a source it thinks is, a header it could not
// parse - and there is no other way to tell those apart from outside.
func (s *Service) watchDrops(ctx context.Context) {
	type counter struct {
		name string
		read func() uint64
	}

	ip := s.ipstack.Stats().IP
	counters := []counter{
		{"received", ip.PacketsReceived.Value},
		{"delivered", ip.PacketsDelivered.Value},
		{"invalidDestination", ip.InvalidDestinationAddressesReceived.Value},
		{"invalidSource", ip.InvalidSourceAddressesReceived.Value},
		{"malformed", ip.MalformedPacketsReceived.Value},
		{"disabled", ip.DisabledPacketsReceived.Value},
		{"ipTablesDropped", ip.IPTablesInputDropped.Value},
		{"outgoingErrors", ip.OutgoingPacketErrors.Value},
	}

	last := make([]uint64, len(counters))
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var changed []any
		for i, c := range counters {
			v := c.read()
			if v != last[i] {
				changed = append(changed, c.name, v)
				last[i] = v
			}
		}

		if len(changed) > 0 {
			s.opts.Logger.Debug("stack counters", changed...)
		}
	}
}
