// Package protocol implements the prx wire protocol: a thin request layer
// that runs inside an ordinary TLS 1.3 session.
//
// A connection has three stages:
//
//  1. TLS handshake. The client mimics a real browser's ClientHello and may
//     send any SNI it likes; the server answers with a certificate matching
//     that name. To anyone on the path this is a normal HTTPS session.
//  2. Authentication (auth.go). Both sides prove knowledge of a shared key,
//     bound to this exact TLS session.
//  3. One request header, then raw bidirectional relay.
//
// The certificate is deliberately not trusted by the client. All security
// comes from stage 2 -- see the commentary in auth.go for why that is sound
// and what it buys.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// Commands a client may send in a request header.
const (
	CmdTCPConnect byte = 0x01 // stream relay to Dest
	CmdUDPAssoc   byte = 0x02 // datagram relay, destination per packet
)

// Address types. The numbering matches SOCKS5 so addresses can move between
// the two without translation.
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

const (
	// MaxPadding is the largest random padding block either side emits.
	MaxPadding = 900

	// MaxDatagram bounds a single relayed UDP payload.
	MaxDatagram = 65507

	maxDomainLen = 255
)

// Errors reported by the decoding helpers. They are all fatal for the
// connection they occur on.
var (
	ErrBadAddrType   = errors.New("prx: unknown address type")
	ErrBadPadding    = errors.New("prx: padding block too large")
	ErrDomainTooLong = errors.New("prx: domain name too long")
	ErrEmptyDomain   = errors.New("prx: empty domain name")
	ErrBadIP         = errors.New("prx: malformed IP address")
	ErrBadCommand    = errors.New("prx: unknown command")
	ErrDatagramSize  = errors.New("prx: datagram too large")
)

// Addr is a destination address as carried on the wire.
type Addr struct {
	Type byte
	Host string // literal IP or domain name, depending on Type
	Port uint16
}

// String renders the address in host:port form.
func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// AppendTo appends the wire encoding of a to b and returns the extended slice.
func (a Addr) AppendTo(b []byte) ([]byte, error) {
	switch a.Type {
	case AtypIPv4:
		ip := net.ParseIP(a.Host)
		if ip == nil || ip.To4() == nil {
			return nil, ErrBadIP
		}
		b = append(b, AtypIPv4)
		b = append(b, ip.To4()...)
	case AtypIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil || ip.To16() == nil {
			return nil, ErrBadIP
		}
		b = append(b, AtypIPv6)
		b = append(b, ip.To16()...)
	case AtypDomain:
		if len(a.Host) == 0 {
			return nil, ErrEmptyDomain
		}
		if len(a.Host) > maxDomainLen {
			return nil, ErrDomainTooLong
		}
		b = append(b, AtypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	default:
		return nil, ErrBadAddrType
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// ReadAddr decodes one address from r.
func ReadAddr(r io.Reader) (Addr, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Addr{}, err
	}

	a := Addr{Type: head[0]}
	switch a.Type {
	case AtypIPv4:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(buf[:]).String()
	case AtypIPv6:
		var buf [16]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(buf[:]).String()
	case AtypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return Addr{}, err
		}
		if n[0] == 0 {
			return Addr{}, ErrEmptyDomain
		}
		buf := make([]byte, n[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return Addr{}, err
		}
		a.Host = string(buf)
	default:
		return Addr{}, ErrBadAddrType
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Addr{}, err
	}
	a.Port = binary.BigEndian.Uint16(port[:])
	return a, nil
}

// ParseAddr converts a "host:port" string into an Addr, choosing the address
// type from the shape of the host.
func ParseAddr(hostport string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Addr{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Addr{}, err
	}

	a := Addr{Host: host, Port: uint16(port)}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		if len(host) == 0 {
			return Addr{}, ErrEmptyDomain
		}
		if len(host) > maxDomainLen {
			return Addr{}, ErrDomainTooLong
		}
		a.Type = AtypDomain
	case ip.To4() != nil:
		a.Type = AtypIPv4
		a.Host = ip.To4().String()
	default:
		a.Type = AtypIPv6
		a.Host = ip.String()
	}
	return a, nil
}

// Request is the header a client sends to open one proxied connection.
type Request struct {
	Cmd  byte
	Dest Addr // ignored for CmdUDPAssoc
}

// AppendTo appends the wire encoding of req to b.
func (req Request) AppendTo(b []byte) ([]byte, error) {
	switch req.Cmd {
	case CmdTCPConnect:
		b = append(b, req.Cmd)
		return req.Dest.AppendTo(b)
	case CmdUDPAssoc:
		// No fixed destination: each datagram carries its own.
		return append(b, req.Cmd), nil
	default:
		return nil, ErrBadCommand
	}
}

// ReadRequest decodes one request header from r.
func ReadRequest(r io.Reader) (Request, error) {
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return Request{}, err
	}

	req := Request{Cmd: cmd[0]}
	switch req.Cmd {
	case CmdTCPConnect:
		dest, err := ReadAddr(r)
		if err != nil {
			return Request{}, err
		}
		req.Dest = dest
	case CmdUDPAssoc:
	default:
		return Request{}, ErrBadCommand
	}
	return req, nil
}

// AppendDatagram appends one length-prefixed datagram to b, for use on a
// stream opened with CmdUDPAssoc.
func AppendDatagram(b []byte, addr Addr, payload []byte) ([]byte, error) {
	if len(payload) > MaxDatagram {
		return nil, ErrDatagramSize
	}
	head, err := addr.AppendTo(nil)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(head)+len(payload)))
	b = append(b, head...)
	return append(b, payload...), nil
}

// ReadDatagram decodes one datagram written by AppendDatagram. The payload is
// read into buf, which must be large enough to hold it.
func ReadDatagram(r io.Reader, buf []byte) (Addr, []byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return Addr{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))

	// The address is decoded from a limited reader so a malformed header can
	// never consume more than this datagram's worth of stream.
	lr := &io.LimitedReader{R: r, N: int64(n)}
	addr, err := ReadAddr(lr)
	if err != nil {
		return Addr{}, nil, err
	}
	rest := int(lr.N)
	if rest > len(buf) {
		return Addr{}, nil, ErrDatagramSize
	}
	if _, err := io.ReadFull(lr, buf[:rest]); err != nil {
		return Addr{}, nil, err
	}
	return addr, buf[:rest], nil
}

// AppendPadding appends a random-length block: a uint16 length followed by
// that many random bytes.
//
// Padding keeps the authentication and request records from having a fixed
// size. An observer cannot read them -- they are inside TLS -- but a constant
// number of bytes at a constant offset in every session is exactly the kind
// of shape that traffic classifiers key on.
func AppendPadding(b []byte) []byte {
	var r [2]byte
	if _, err := rand.Read(r[:]); err != nil {
		// crypto/rand does not fail on any supported platform; if it somehow
		// does, fall back to no padding rather than taking the process down.
		return binary.BigEndian.AppendUint16(b, 0)
	}
	n := int(binary.BigEndian.Uint16(r[:])) % (MaxPadding + 1)

	b = binary.BigEndian.AppendUint16(b, uint16(n))
	pad := make([]byte, n)
	if _, err := rand.Read(pad); err != nil {
		return b[:len(b)-2]
	}
	return append(b, pad...)
}

// SkipPadding consumes one padding block written by AppendPadding.
func SkipPadding(r io.Reader) error {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n > MaxPadding {
		return ErrBadPadding
	}
	if n == 0 {
		return nil
	}
	var scratch [MaxPadding]byte
	_, err := io.ReadFull(r, scratch[:n])
	return err
}
