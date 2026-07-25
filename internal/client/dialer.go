// Package client dials the prx server and exposes the tunnel to local
// applications as SOCKS5 and HTTP proxies.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/justtahsin/prx/internal/link"
	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/relay"
)

const (
	tcpDialTimeout = 10 * time.Second

	// warmTTL is how long a pooled connection may sit idle before it is
	// replaced. It is comfortably below the server's request timeout, so a
	// connection handed out of the pool is never one the server has given up
	// on.
	warmTTL = 4 * time.Minute

	warmDialTimeout = 15 * time.Second
	warmInterval    = 500 * time.Millisecond
	writeTimeout    = 15 * time.Second
)

// Dialer opens proxied connections through one prx server.
type Dialer struct {
	server      string
	key         []byte
	sni         string
	fingerprint utls.ClientHelloID
	log         *slog.Logger

	// control is applied to the socket that reaches the server; see
	// WithControl.
	control func(network, address string, c syscall.RawConn) error

	warm  chan *tunnel
	nudge chan struct{}

	stop     chan struct{}
	stopOnce sync.Once
}

// tunnel is one authenticated connection to the server.
type tunnel struct {
	conn   *utls.UConn
	opened time.Time
	pooled bool
}

// Option adjusts a Dialer at construction time.
type Option func(*Dialer)

// WithControl installs a control function on the socket used to reach the
// server.
//
// Android needs this. Under a VpnService every socket on the device is routed
// into the tunnel, including ours, which would send our traffic to the server
// back through itself. The app passes a control function that calls
// VpnService.protect on the file descriptor, exempting that one socket.
func WithControl(control func(network, address string, c syscall.RawConn) error) Option {
	return func(d *Dialer) { d.control = control }
}

// NewDialer builds a dialer from a parsed connection link.
func NewDialer(l link.Link, poolSize int, log *slog.Logger, opts ...Option) (*Dialer, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	key, err := l.KeyBytes()
	if err != nil {
		return nil, err
	}
	if poolSize < 0 {
		poolSize = 0
	}

	d := &Dialer{
		server:      l.Addr(),
		key:         key,
		sni:         l.SNI,
		fingerprint: helloID(l.Fingerprint),
		log:         log,
		warm:        make(chan *tunnel, poolSize),
		nudge:       make(chan struct{}, 1),
		stop:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(d)
	}
	if poolSize > 0 {
		go d.keepWarm()
	}
	return d, nil
}

// Close shuts the dialer down and discards pooled connections.
func (d *Dialer) Close() error {
	d.stopOnce.Do(func() {
		close(d.stop)
		for {
			select {
			case t := <-d.warm:
				t.conn.Close()
			default:
				return
			}
		}
	})
	return nil
}

// Server reports the address this dialer connects to.
func (d *Dialer) Server() string { return d.server }

// SNI reports the server name sent in the TLS handshake.
func (d *Dialer) SNI() string { return d.sni }

// Open opens a proxied TCP connection to dest.
//
// The request header is sent without waiting for a reply and the caller may
// write payload immediately: a destination that cannot be reached shows up
// as the connection closing. That removes a round trip from every request,
// which on a link with 150ms of latency is 150ms off the time to first byte.
func (d *Dialer) Open(ctx context.Context, dest protocol.Addr) (net.Conn, error) {
	header, err := protocol.Request{Cmd: protocol.CmdTCPConnect, Dest: dest}.AppendTo(nil)
	if err != nil {
		return nil, err
	}
	return d.send(ctx, protocol.AppendPadding(header))
}

// OpenUDP opens a datagram association. Frame datagrams onto the returned
// connection with protocol.AppendDatagram and read them with
// protocol.ReadDatagram.
func (d *Dialer) OpenUDP(ctx context.Context) (net.Conn, error) {
	header, err := protocol.Request{Cmd: protocol.CmdUDPAssoc}.AppendTo(nil)
	if err != nil {
		return nil, err
	}
	return d.send(ctx, protocol.AppendPadding(header))
}

// DialContext matches net.Dialer's signature so the tunnel can be handed to
// an http.Transport directly.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("prx: unsupported network %q", network)
	}
	dest, err := protocol.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	return d.Open(ctx, dest)
}

// send acquires a tunnel and writes a request header on it.
func (d *Dialer) send(ctx context.Context, header []byte) (net.Conn, error) {
	// Two attempts: a pooled connection can have been dropped by a NAT while
	// it sat idle, and that is only discovered on the first write. A fresh
	// dial is never retried.
	for attempt := 0; ; attempt++ {
		t, err := d.acquire(ctx)
		if err != nil {
			return nil, err
		}

		t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := t.conn.Write(header); err != nil {
			t.conn.Close()
			if attempt == 0 && t.pooled {
				continue
			}
			return nil, err
		}
		t.conn.SetDeadline(time.Time{})
		return t.conn, nil
	}
}

// acquire returns a ready authenticated connection, preferring a warm one.
func (d *Dialer) acquire(ctx context.Context) (*tunnel, error) {
	for {
		select {
		case t := <-d.warm:
			d.requestWarm()
			if time.Since(t.opened) < warmTTL {
				return t, nil
			}
			t.conn.Close()
			continue
		default:
		}
		break
	}

	d.requestWarm()
	return d.connect(ctx)
}

// connect performs a full TLS handshake and authentication.
func (d *Dialer) connect(ctx context.Context) (*tunnel, error) {
	dialer := net.Dialer{Timeout: tcpDialTimeout, Control: d.control}
	raw, err := dialer.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}
	relay.Tune(raw)

	cfg := &utls.Config{
		ServerName: d.sni,

		// The certificate is intentionally not validated.
		//
		// The server usually presents a self-signed certificate minted to
		// match whatever SNI was chosen, so there is no chain to validate
		// against and no name to match. Authentication happens one layer up
		// instead: both sides prove they hold the pre-shared key, and both
		// proofs are bound to this TLS session's exported keying material.
		//
		// That binding is strictly stronger than name validation here. An
		// attacker who intercepts the connection -- with a valid certificate
		// for the SNI, even -- terminates TLS and so derives different
		// keying material on each side. Their forwarded proof does not
		// verify and the handshake in protocol.ClientAuth fails. See the
		// commentary in internal/protocol/auth.go.
		InsecureSkipVerify: true,

		// Chrome offers these; omitting them would leave a hole in an
		// otherwise faithful ClientHello.
		NextProtos: []string{"h2", "http/1.1"},
	}

	spec, err := clientHelloSpec(d.fingerprint)
	if err != nil {
		raw.Close()
		return nil, err
	}

	conn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("prx: tls handshake with %s: %w", d.server, err)
	}

	state := conn.ConnectionState()
	if err := protocol.ClientAuth(conn, &state, d.key); err != nil {
		conn.Close()
		if errors.Is(err, protocol.ErrAuth) {
			// The server answered as a web server would, which is what it
			// does for anyone without a valid key.
			return nil, fmt.Errorf("prx: server rejected our key (or is not a prx server): %w", err)
		}
		return nil, err
	}

	return &tunnel{conn: conn, opened: time.Now()}, nil
}

// keepWarm maintains the pool of pre-authenticated connections.
//
// This is where the latency goes. A cold request pays a TCP handshake, a TLS
// handshake and an authentication exchange before it can even name its
// destination; a warm one pays none of them and the user sees only the
// destination's own round trip.
func (d *Dialer) keepWarm() {
	ticker := time.NewTicker(warmInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stop:
			return
		case <-d.nudge:
		case <-ticker.C:
		}

		for len(d.warm) < cap(d.warm) {
			select {
			case <-d.stop:
				return
			default:
			}

			ctx, cancel := context.WithTimeout(context.Background(), warmDialTimeout)
			t, err := d.connect(ctx)
			cancel()
			if err != nil {
				// Back off until the next tick rather than hammering an
				// unreachable server.
				d.log.Debug("warm-up dial failed", "err", err)
				break
			}
			t.pooled = true

			select {
			case d.warm <- t:
			default:
				t.conn.Close()
			}
		}
	}
}

func (d *Dialer) requestWarm() {
	select {
	case d.nudge <- struct{}{}:
	default:
	}
}

// clientHelloSpec expands a fingerprint into the ClientHello to send.
//
// The preset is used as-is except for one field: the renegotiation_info
// extension carries an internal flag that uTLS copies into the connection's
// configuration, and a connection that permits renegotiation refuses to
// export keying material -- which is exactly what authentication is bound
// to. Turning the flag off restores the export.
//
// This does not weaken the imitation. The extension's encoder writes only
// its renegotiated_connection payload, empty on an initial handshake, so the
// bytes on the wire are identical either way; uTLS documents the extension
// as being sent regardless of this setting. Renegotiation itself does not
// exist in TLS 1.3 and is not something a proxy client should accept in any
// version.
//
// A fresh spec is built per connection because the handshake mutates the
// extension objects it holds, and because randomised fingerprints are
// supposed to differ each time.
func clientHelloSpec(id utls.ClientHelloID) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("prx: building ClientHello: %w", err)
	}
	for _, ext := range spec.Extensions {
		if reneg, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			reneg.Renegotiation = utls.RenegotiateNever
		}
	}
	return &spec, nil
}

// helloID maps a fingerprint name from a link to a ClientHello template.
func helloID(name string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "random":
		return utls.HelloRandomizedALPN
	default:
		// Chrome is the most common client on the network by a wide margin,
		// which makes it the least remarkable thing to look like.
		return utls.HelloChrome_Auto
	}
}

// Fingerprints lists the names accepted in a link's fp parameter.
var Fingerprints = []string{"chrome", "firefox", "safari", "ios", "edge", "android", "random"}
