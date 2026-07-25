// Package server implements the prx daemon.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/justtahsin/prx/internal/config"
	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/relay"
	"github.com/justtahsin/prx/internal/users"
)

const (
	// handshakeTimeout bounds TLS plus authentication. Generous enough for a
	// bad mobile link, short enough that a stalled scanner cannot pin down a
	// connection slot.
	handshakeTimeout = 20 * time.Second

	// requestTimeout is how long an authenticated but idle connection may
	// wait before naming a destination. Clients keep connections warm in a
	// pool for well under this, so it is the ceiling on that, not a limit
	// users ever meet.
	requestTimeout = 10 * time.Minute

	// dialTimeout bounds a single connection attempt to a destination.
	dialTimeout = 10 * time.Second

	// reloadInterval is how often the users file is checked for changes, so
	// `prxd user add` takes effect without a restart.
	reloadInterval = 5 * time.Second

	statsInterval = 15 * time.Minute
)

// Server accepts prx connections.
type Server struct {
	cfg    config.Server
	users  *users.Store
	certs  *certSource
	tlsCfg *tls.Config
	log    *slog.Logger

	blockedPorts map[int]bool

	stop     chan struct{}
	stopOnce sync.Once

	listeners sync.Map // net.Listener -> struct{}

	stats stats
}

type stats struct {
	accepted      atomic.Int64
	authenticated atomic.Int64
	rejected      atomic.Int64
	active        atomic.Int64
	bytesOut      atomic.Int64
	bytesIn       atomic.Int64
}

// New builds a server from its configuration and credential store.
func New(cfg config.Server, store *users.Store, log *slog.Logger) (*Server, error) {
	certs, err := newCertSource(cfg.CertMode, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	blocked := make(map[int]bool, len(cfg.BlockPorts))
	for _, p := range cfg.BlockPorts {
		blocked[p] = true
	}

	s := &Server{
		cfg:          cfg,
		users:        store,
		certs:        certs,
		log:          log,
		blockedPorts: blocked,
		stop:         make(chan struct{}),
	}
	s.tlsCfg = &tls.Config{
		GetCertificate: certs.getCertificate,
		// TLS 1.2 is still accepted so that a probe using an older client
		// gets a normal handshake rather than a distinctive rejection. Real
		// clients negotiate 1.3; either way the channel binding the
		// authentication depends on is available.
		MinVersion: tls.VersionTLS12,
		NextProtos: alpnFor(cfg.Fallback),
	}
	return s, nil
}

// ListenAndServe starts the daemon and blocks until it is closed.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("prx: listening on %s: %w", s.cfg.Listen, err)
	}

	total, enabled := s.users.Count()
	s.log.Info("prx server listening",
		"addr", ln.Addr().String(),
		"cert_mode", s.cfg.CertMode,
		"users", total,
		"enabled", enabled,
		"fallback", fallbackLabel(s.cfg.Fallback))

	go s.users.Watch(s.stop, reloadInterval, func(err error) {
		s.log.Error("reloading users failed", "err", err)
	})
	go s.reportStats()

	return s.Serve(ln)
}

// Serve accepts connections on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.listeners.Store(ln, struct{}{})
	defer s.listeners.Delete(ln)
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return nil
			default:
			}
			// A per-connection failure (out of file descriptors, for
			// instance) must not take the listener down.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Error("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handleConn(conn)
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.listeners.Range(func(k, _ any) bool {
			k.(net.Listener).Close()
			return true
		})
	})
	return nil
}

func (s *Server) handleConn(raw net.Conn) {
	defer raw.Close()

	relay.Tune(raw)
	s.stats.accepted.Add(1)
	s.stats.active.Add(1)
	defer s.stats.active.Add(-1)

	raw.SetDeadline(time.Now().Add(handshakeTimeout))
	conn := tls.Server(raw, s.tlsCfg)
	if err := conn.Handshake(); err != nil {
		// A failed TLS handshake is what any web server would give a
		// malformed client; nothing further to say.
		s.log.Debug("tls handshake failed", "peer", raw.RemoteAddr().String(), "err", err)
		return
	}

	br := bufio.NewReader(conn)

	// A visitor speaking HTTP is recognised before we wait for a full
	// authentication record. Without this, a complete but short request such
	// as "GET / HTTP/1.0" -- 18 bytes, fewer than the 48 an authentication
	// record occupies -- would leave us blocked until the handshake timeout
	// while a real web server answered at once. That difference is precisely
	// what a scanner measures.
	if prefix, err := br.Peek(httpPrefixLen); err == nil && looksLikeHTTP(prefix) {
		s.stats.rejected.Add(1)
		s.serveDecoy(conn, br, nil)
		return
	}

	record := make([]byte, protocol.AuthRequestSize)
	n, err := io.ReadFull(br, record)
	if err != nil {
		s.stats.rejected.Add(1)
		s.serveDecoy(conn, br, record[:n])
		return
	}

	state := conn.ConnectionState()
	binding, err := protocol.Binding(&state)
	if err != nil {
		s.stats.rejected.Add(1)
		s.serveDecoy(conn, br, record)
		return
	}

	nonce, clientTag := record[:protocol.NonceSize], record[protocol.NonceSize:]
	user, key, ok := s.users.Match(binding, nonce, clientTag)
	if !ok {
		s.stats.rejected.Add(1)
		s.serveDecoy(conn, br, record)
		return
	}

	if err := protocol.SkipPadding(br); err != nil {
		return
	}
	if err := protocol.ServerAccept(conn, key, binding, nonce); err != nil {
		return
	}
	s.stats.authenticated.Add(1)

	s.serveRequest(conn, br, user)
}

func (s *Server) serveRequest(conn net.Conn, br *bufio.Reader, user users.User) {
	conn.SetDeadline(time.Now().Add(requestTimeout))
	req, err := protocol.ReadRequest(br)
	if err != nil {
		return
	}
	if err := protocol.SkipPadding(br); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	switch req.Cmd {
	case protocol.CmdTCPConnect:
		s.handleTCP(conn, br, user, req.Dest)
	case protocol.CmdUDPAssoc:
		s.handleUDP(conn, br, user)
	}
}

func (s *Server) handleTCP(conn net.Conn, br *bufio.Reader, user users.User, dest protocol.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	target, err := s.dial(ctx, dest)
	if err != nil {
		// There is no reply message: the client learns of a failed
		// destination from the connection closing. Skipping a status round
		// trip is what keeps added latency to the destination's own RTT.
		s.log.Debug("dial failed", "user", user.Name, "dest", dest.String(), "err", err)
		return
	}
	defer target.Close()
	relay.Tune(target)

	s.log.Debug("relaying", "user", user.Name, "dest", dest.String())
	out, in := relay.Pipe(conn, br, target, nil)
	s.stats.bytesOut.Add(out)
	s.stats.bytesIn.Add(in)
}

// Errors reported when a destination is refused by policy.
var (
	errBlockedPort   = errors.New("prx: destination port is blocked")
	errPrivateDest   = errors.New("prx: destination is a private address")
	errNoUsableAddrs = errors.New("prx: destination has no usable addresses")
)

// dial opens a connection to dest, applying the server's destination policy.
//
// Names are resolved here rather than inside net.Dialer so that every
// candidate address can be checked before it is used. Dialling the exact
// address that passed the check is also what closes the rebinding hole: a
// name that resolves to a public address on the first lookup cannot come back
// as 127.0.0.1 on a second one, because there is no second one.
func (s *Server) dial(ctx context.Context, dest protocol.Addr) (net.Conn, error) {
	if s.blockedPorts[int(dest.Port)] {
		return nil, errBlockedPort
	}

	var candidates []net.IP
	if dest.Type == protocol.AtypDomain {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, dest.Host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			candidates = append(candidates, a.IP)
		}
	} else {
		ip := net.ParseIP(dest.Host)
		if ip == nil {
			return nil, protocol.ErrBadIP
		}
		candidates = []net.IP{ip}
	}

	allowed := candidates[:0]
	for _, ip := range candidates {
		if !s.cfg.AllowPrivate && isPrivate(ip) {
			continue
		}
		allowed = append(allowed, ip)
	}
	if len(allowed) == 0 {
		if len(candidates) > 0 {
			return nil, errPrivateDest
		}
		return nil, errNoUsableAddrs
	}

	var dialer net.Dialer
	var lastErr error
	for _, ip := range allowed {
		addr := net.JoinHostPort(ip.String(), fmt.Sprint(dest.Port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// isPrivate reports whether an address belongs to a range a public proxy has
// no business reaching on a client's behalf.
func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT, is not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

func (s *Server) reportStats() {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.log.Info("stats",
				"accepted", s.stats.accepted.Load(),
				"authenticated", s.stats.authenticated.Load(),
				"rejected", s.stats.rejected.Load(),
				"active", s.stats.active.Load(),
				"bytes_out", s.stats.bytesOut.Load(),
				"bytes_in", s.stats.bytesIn.Load())
		}
	}
}

// httpPrefixLen is how many leading bytes identify an HTTP request.
const httpPrefixLen = 4

// httpPrefixes are the first four bytes of the request methods a visitor
// might open with, plus the HTTP/2 connection preface ("PRI ").
//
// An authentication record starts with 16 random bytes, so a genuine client
// collides with one of these about once in four billion connections and
// simply reconnects.
var httpPrefixes = [][]byte{
	[]byte("GET "), []byte("POST"), []byte("HEAD"), []byte("PUT "),
	[]byte("DELE"), []byte("OPTI"), []byte("PATC"), []byte("TRAC"),
	[]byte("CONN"), []byte("PRI "),
}

func looksLikeHTTP(prefix []byte) bool {
	for _, m := range httpPrefixes {
		if bytes.Equal(prefix, m) {
			return true
		}
	}
	return false
}

// alpnFor decides which HTTP versions to offer in the handshake.
//
// Whatever is offered has to be something an unauthenticated visitor can
// actually be served, since they are the only ones who speak HTTP here. The
// built-in decoy handles both versions. A configured fallback is reached
// over cleartext HTTP/1.1, so offering HTTP/2 would leave those visitors
// with a protocol error.
func alpnFor(fallback string) []string {
	if fallback == "" {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func fallbackLabel(addr string) string {
	if addr == "" {
		return "built-in page"
	}
	return addr
}
