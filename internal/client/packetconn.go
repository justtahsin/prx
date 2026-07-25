package client

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/justtahsin/prx/internal/protocol"
)

// OpenPacketConn opens a UDP association and presents it as a net.PacketConn.
//
// This is what a packet-level consumer needs -- an Android VpnService tunnel
// hands us raw datagrams to forward, not a stream. The SOCKS5 front end works
// on the association directly instead, because it has to add and strip its
// own datagram headers anyway.
func (d *Dialer) OpenPacketConn(ctx context.Context) (net.PacketConn, error) {
	stream, err := d.OpenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return &packetConn{
		stream:  stream,
		readBuf: make([]byte, protocol.MaxDatagram),
	}, nil
}

// packetConn adapts one UDP association stream to net.PacketConn.
type packetConn struct {
	stream net.Conn

	readMu  sync.Mutex
	readBuf []byte

	writeMu  sync.Mutex
	writeBuf []byte
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	src, payload, err := protocol.ReadDatagram(c.stream, c.readBuf)
	if err != nil {
		return 0, nil, err
	}
	return copy(p, payload), addrOf(src), nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest, err := protocol.ParseAddr(addr.String())
	if err != nil {
		return 0, err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeBuf, err = protocol.AppendDatagram(c.writeBuf[:0], dest, p)
	if err != nil {
		return 0, err
	}
	if _, err := c.stream.Write(c.writeBuf); err != nil {
		return 0, err
	}
	// Report the payload length: a caller counts what it handed us, not what
	// the framing added.
	return len(p), nil
}

func (c *packetConn) Close() error                       { return c.stream.Close() }
func (c *packetConn) LocalAddr() net.Addr                { return c.stream.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// addrOf converts a wire address into a net.Addr.
//
// A *net.UDPAddr is returned whenever the address is a literal IP, because
// callers routinely type-assert for one. A name only comes back when the
// client sent one, and packet-level callers send addresses they already
// resolved.
func addrOf(a protocol.Addr) net.Addr {
	if ip := net.ParseIP(a.Host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(a.Port)}
	}
	return datagramAddr{addr: a}
}

type datagramAddr struct{ addr protocol.Addr }

func (d datagramAddr) Network() string { return "udp" }
func (d datagramAddr) String() string  { return d.addr.String() }
