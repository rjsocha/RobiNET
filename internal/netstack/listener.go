package netstack

import (
	"io"
	"net"
	"sync"
)

type tcpListener struct {
	s      *Service
	addr   *net.TCPAddr
	accept chan net.Conn

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *tcpListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, io.EOF
	}
}

func (l *tcpListener) Close() error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()

	delete(l.s.mu.listeners, uint16(l.addr.Port))
	l.closeOnce.Do(func() { close(l.closed) })

	return nil
}

func (l *tcpListener) Addr() net.Addr { return l.addr }
