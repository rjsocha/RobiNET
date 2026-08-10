package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// hostAddress renders the original destination of a forwarded flow as a
// host:port usable on the host network.
func hostAddress(id stack.TransportEndpointID) string {
	addr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return ""
	}

	return net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(int(id.LocalPort)))
}

// forwardTCP terminates a flow in the stack and splices it to dst on the host.
func (s *Service) forwardTCP(r *tcp.ForwarderRequest, dst string) {
	if dst == "" {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		s.opts.Logger.Error("could not create endpoint for a forwarded flow", "dst", dst, "error", err.String())
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)

	inbound := gonet.NewTCPConn(&wq, ep)

	// Dialing blocks, and the packet loop called us.
	go func() {
		ctx, cancel := context.WithTimeout(s.ctx, s.opts.HostDialTimeout)
		defer cancel()

		outbound, err := s.opts.HostDialer.DialContext(ctx, "tcp", dst)
		if err != nil {
			s.opts.Logger.Warn("forwarded dial failed", "dst", dst, "error", err)
			inbound.Close()
			return
		}

		spliceTCP(inbound, outbound)
	}()
}

// spliceTCP copies both ways, propagating the half close so protocols relying
// on EOF still work.
func spliceTCP(inbound, outbound net.Conn) {
	defer inbound.Close()
	defer outbound.Close()

	done := make(chan struct{}, 2)

	copyAndCloseWrite := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()

		if _, err := io.Copy(dst, src); err != nil {
			return
		}

		type closeWriter interface{ CloseWrite() error }
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}

	go copyAndCloseWrite(outbound, inbound)
	go copyAndCloseWrite(inbound, outbound)

	// A half closed connection may still have data coming back.
	<-done
	<-done
}

// udpHandler routes a UDP flow with no endpoint of its own.
func (s *Service) udpHandler(r *udp.ForwarderRequest) {
	id := r.ID()

	s.opts.Logger.Debug("udp flow",
		"local", id.LocalAddress.String(), "port", id.LocalPort,
		"remote", id.RemoteAddress.String(),
		"mine", s.isLocalAddress(id.LocalAddress),
	)

	if s.isLocalAddress(id.LocalAddress) {
		if s.opts.DNS && id.LocalPort == s.opts.DNSPort {
			s.forwardUDP(r, s.dnsUpstream(), s.opts.DNSIdleTimeout)
		}
		return
	}

	if !s.opts.Gateway {
		return
	}

	s.forwardUDP(r, hostAddress(id), s.opts.GatewayUDPTimeout)
}

func (s *Service) forwardUDP(r *udp.ForwarderRequest, dst string, timeout time.Duration) {
	if dst == "" {
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		s.opts.Logger.Error("could not create udp endpoint for a forwarded flow", "dst", dst, "error", err.String())
		return
	}

	inbound := gonet.NewUDPConn(&wq, ep)

	go func() {
		ctx, cancel := context.WithTimeout(s.ctx, s.opts.HostDialTimeout)
		defer cancel()

		outbound, err := s.opts.HostDialer.DialContext(ctx, "udp", dst)
		if err != nil {
			s.opts.Logger.Warn("forwarded udp dial failed", "dst", dst, "error", err)
			inbound.Close()
			return
		}

		spliceUDP(inbound, outbound, timeout)
	}()
}

// spliceUDP shuttles datagrams until the flow has been idle for timeout.
func spliceUDP(inbound, outbound net.Conn, timeout time.Duration) {
	defer inbound.Close()
	defer outbound.Close()

	done := make(chan struct{}, 2)

	pipe := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()

		// A datagram can be larger than the overlay MTU.
		buf := make([]byte, 65535)
		for {
			if err := src.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return
			}

			n, err := src.Read(buf)
			if n > 0 {
				if err := dst.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
					return
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go pipe(outbound, inbound)
	go pipe(inbound, outbound)

	<-done
}
