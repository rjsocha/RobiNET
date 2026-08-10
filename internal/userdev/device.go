// Package userdev implements a nebula overlay device that has no tun and no
// kernel involvement. Packets leaving the mesh are handed to whatever reads the
// pipe, which in robinet is a user space network stack.
//
// This is the piece that lets a connector run in a container with no
// capabilities and no /dev/net/tun.
package userdev

import (
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/routing"
)

// Route sends everything inside Prefix to Gateway, an address inside the mesh.
type Route struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
}

// Device is a nebula overlay.Device backed by a pair of pipes. Each write is
// exactly one packet, which is what nebula expects from a tun.
type Device struct {
	networks []netip.Prefix

	routes atomic.Pointer[bart.Table[routing.Gateways]]

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter
}

// New builds a device for the given overlay networks. Routes may be empty, in
// which case every address is assumed to be a mesh member.
func New(networks []netip.Prefix, routes []Route) *Device {
	or, ow := io.Pipe()
	ir, iw := io.Pipe()

	d := &Device{
		networks:       networks,
		outboundReader: or,
		outboundWriter: ow,
		inboundReader:  ir,
		inboundWriter:  iw,
	}
	d.SetRoutes(routes)

	return d
}

// SetRoutes replaces the routing table. Safe to call while the device is in use.
func (d *Device) SetRoutes(routes []Route) {
	if len(routes) == 0 {
		d.routes.Store(nil)
		return
	}

	table := new(bart.Table[routing.Gateways])
	for _, r := range routes {
		table.Insert(r.Prefix, routing.Gateways{routing.NewGateway(r.Gateway, 1)})
	}
	d.routes.Store(table)
}

func (d *Device) Activate() error          { return nil }
func (d *Device) Networks() []netip.Prefix { return d.networks }
func (d *Device) Name() string             { return "robinet0" }
func (d *Device) SupportsMultiqueue() bool { return true }
func (d *Device) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

// RoutesFor answers where to send a packet for an address that is not itself a
// mesh member. Anything not covered by a configured route falls back to the
// address itself, which keeps a device with no routes behaving like a plain
// mesh member.
func (d *Device) RoutesFor(ip netip.Addr) routing.Gateways {
	if table := d.routes.Load(); table != nil {
		if gateways, ok := table.Lookup(ip); ok {
			return gateways
		}
	}

	return routing.Gateways{routing.NewGateway(ip, 1)}
}

// Pipe returns the ends belonging to the network stack: a reader for packets
// nebula has decrypted, and a writer for packets to send into the mesh.
func (d *Device) Pipe() (*io.PipeReader, *io.PipeWriter) {
	return d.inboundReader, d.outboundWriter
}

func (d *Device) Read(p []byte) (int, error)  { return d.outboundReader.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.inboundWriter.Write(p) }

func (d *Device) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
