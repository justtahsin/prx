package client

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/relay"
)

// SOCKS5 message constants. Address types deliberately match the ones in
// package protocol, so addresses pass through without re-encoding.
const (
	socksVersion = 0x05

	methodNoAuth     = 0x00
	methodNoneUsable = 0xFF

	socksConnect      = 0x01
	socksBind         = 0x02
	socksUDPAssociate = 0x03

	replySuccess          = 0x00
	replyGeneralFailure   = 0x01
	replyCommandNotSupp   = 0x07
	socksNegotiateTimeout = 30 * time.Second
)

var errNoUsableMethod = errors.New("prx: client offered no usable SOCKS5 auth method")

// unspecified is the placeholder bind address used in replies.
var unspecified = protocol.Addr{Type: protocol.AtypIPv4, Host: "0.0.0.0", Port: 0}

// SOCKS5 serves the SOCKS5 protocol on a local listener and forwards
// everything through the tunnel.
type SOCKS5 struct {
	dialer *Dialer
	log    *slog.Logger
}

// NewSOCKS5 builds a SOCKS5 front end.
func NewSOCKS5(d *Dialer, log *slog.Logger) *SOCKS5 {
	return &SOCKS5{dialer: d, log: log}
}

// Serve accepts connections until ln is closed.
func (s *SOCKS5) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5) handle(conn net.Conn) {
	defer conn.Close()
	relay.Tune(conn)

	conn.SetDeadline(time.Now().Add(socksNegotiateTimeout))
	br := bufio.NewReader(conn)

	if err := socksHandshake(br, conn); err != nil {
		s.log.Debug("socks handshake failed", "err", err)
		return
	}

	cmd, dest, err := socksReadRequest(br)
	if err != nil {
		s.log.Debug("socks request failed", "err", err)
		return
	}

	switch cmd {
	case socksConnect:
		s.handleConnect(conn, br, dest)
	case socksUDPAssociate:
		s.handleUDPAssociate(conn, br)
	default:
		socksReply(conn, replyCommandNotSupp, unspecified)
	}
}

func (s *SOCKS5) handleConnect(conn net.Conn, br *bufio.Reader, dest protocol.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout+warmDialTimeout)
	defer cancel()

	tunnel, err := s.dialer.Open(ctx, dest)
	if err != nil {
		s.log.Debug("tunnel open failed", "dest", dest.String(), "err", err)
		socksReply(conn, replyGeneralFailure, unspecified)
		return
	}
	defer tunnel.Close()

	// Success is reported as soon as the tunnel accepted the request, before
	// the far end has confirmed the destination is reachable. That is the
	// cost of not waiting for a status round trip: an unreachable
	// destination surfaces as the connection closing rather than as a SOCKS
	// error code. Applications treat both as a failed connection.
	if err := socksReply(conn, replySuccess, unspecified); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	s.log.Debug("socks connect", "dest", dest.String())
	relay.Pipe(conn, br, tunnel, nil)
}

// handleUDPAssociate sets up datagram relaying for one client.
//
// The association is owned by the TCP control connection: when that closes,
// the UDP socket and the tunnel stream go with it. That is what RFC 1928
// requires and it is also the only reliable way to reclaim the resources,
// since UDP itself never signals that a client is finished.
func (s *SOCKS5) handleUDPAssociate(ctrl net.Conn, br *bufio.Reader) {
	host, _, err := net.SplitHostPort(ctrl.LocalAddr().String())
	if err != nil {
		socksReply(ctrl, replyGeneralFailure, unspecified)
		return
	}

	packets, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		s.log.Debug("udp listen failed", "err", err)
		socksReply(ctrl, replyGeneralFailure, unspecified)
		return
	}
	defer packets.Close()

	bound, err := protocol.ParseAddr(packets.LocalAddr().String())
	if err != nil {
		socksReply(ctrl, replyGeneralFailure, unspecified)
		return
	}
	if err := socksReply(ctrl, replySuccess, bound); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout+warmDialTimeout)
	stream, err := s.dialer.OpenUDP(ctx)
	cancel()
	if err != nil {
		s.log.Debug("udp association failed", "err", err)
		return
	}
	defer stream.Close()

	assoc := &socksUDP{packets: packets, stream: stream, log: s.log}
	go assoc.appToTunnel()
	go assoc.tunnelToApp()

	// Hold the association open for as long as the control connection lives.
	ctrl.SetDeadline(time.Time{})
	io.Copy(io.Discard, br)
}

// socksUDP relays datagrams between the local SOCKS5 UDP socket and one
// tunnel stream.
type socksUDP struct {
	packets net.PacketConn
	stream  net.Conn
	log     *slog.Logger

	mu     sync.Mutex
	client net.Addr // learned from the first datagram the application sends
}

func (a *socksUDP) setClient(addr net.Addr) {
	a.mu.Lock()
	a.client = addr
	a.mu.Unlock()
}

func (a *socksUDP) clientAddr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client
}

func (a *socksUDP) appToTunnel() {
	defer a.stream.Close()

	buf := make([]byte, protocol.MaxDatagram)
	out := make([]byte, 0, protocol.MaxDatagram+64)

	for {
		n, from, err := a.packets.ReadFrom(buf)
		if err != nil {
			return
		}
		dest, payload, err := parseSOCKSDatagram(buf[:n])
		if err != nil {
			a.log.Debug("malformed socks datagram", "err", err)
			continue
		}
		a.setClient(from)

		out, err = protocol.AppendDatagram(out[:0], dest, payload)
		if err != nil {
			continue
		}
		if _, err := a.stream.Write(out); err != nil {
			return
		}
	}
}

func (a *socksUDP) tunnelToApp() {
	defer a.packets.Close()

	buf := make([]byte, protocol.MaxDatagram)
	out := make([]byte, 0, protocol.MaxDatagram+64)

	for {
		src, payload, err := protocol.ReadDatagram(a.stream, buf)
		if err != nil {
			return
		}
		client := a.clientAddr()
		if client == nil {
			continue // nothing has been sent yet, so nothing can be a reply
		}

		out = append(out[:0], 0x00, 0x00, 0x00) // RSV, RSV, FRAG
		out, err = src.AppendTo(out)
		if err != nil {
			continue
		}
		out = append(out, payload...)
		if _, err := a.packets.WriteTo(out, client); err != nil {
			return
		}
	}
}

// parseSOCKSDatagram splits a SOCKS5 UDP request into destination and payload.
func parseSOCKSDatagram(b []byte) (protocol.Addr, []byte, error) {
	if len(b) < 5 {
		return protocol.Addr{}, nil, errors.New("prx: short SOCKS5 datagram")
	}
	if b[2] != 0 {
		// Fragmentation is optional in RFC 1928 and no common client uses it.
		return protocol.Addr{}, nil, errors.New("prx: fragmented SOCKS5 datagrams are not supported")
	}

	rest := b[3:]
	reader := bufio.NewReader(newSliceReader(rest))
	dest, err := protocol.ReadAddr(reader)
	if err != nil {
		return protocol.Addr{}, nil, err
	}
	// Whatever the reader has not consumed, minus what it buffered ahead, is
	// the payload.
	consumed := len(rest) - reader.Buffered()
	return dest, rest[consumed:], nil
}

type sliceReader struct {
	b []byte
}

func newSliceReader(b []byte) *sliceReader { return &sliceReader{b: b} }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func socksHandshake(br *bufio.Reader, w io.Writer) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != socksVersion {
		return errors.New("prx: not a SOCKS5 client")
	}

	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == methodNoAuth {
			_, err := w.Write([]byte{socksVersion, methodNoAuth})
			return err
		}
	}

	w.Write([]byte{socksVersion, methodNoneUsable})
	return errNoUsableMethod
}

func socksReadRequest(br *bufio.Reader) (cmd byte, dest protocol.Addr, err error) {
	head := make([]byte, 3)
	if _, err := io.ReadFull(br, head); err != nil {
		return 0, protocol.Addr{}, err
	}
	if head[0] != socksVersion {
		return 0, protocol.Addr{}, errors.New("prx: not a SOCKS5 request")
	}

	// The address encoding is identical, so this reads the SOCKS5 request's
	// ATYP/ADDR/PORT fields directly.
	dest, err = protocol.ReadAddr(br)
	if err != nil {
		return 0, protocol.Addr{}, err
	}
	return head[1], dest, nil
}

func socksReply(w io.Writer, reply byte, bound protocol.Addr) error {
	out := []byte{socksVersion, reply, 0x00}
	out, err := bound.AppendTo(out)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}
