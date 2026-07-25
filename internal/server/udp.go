package server

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/users"
)

const (
	// udpIdleTimeout closes an association that has gone quiet in both
	// directions. UDP has no close, so a timer is the only way to reclaim it.
	udpIdleTimeout = 2 * time.Minute

	// udpResolveLimit caps the per-association name and origin caches so a
	// client cannot grow one without bound.
	udpResolveLimit = 512
)

// handleUDP relays datagrams for one association.
//
// The client opens a stream with CmdUDPAssoc and then sends length-prefixed
// datagrams over it, each carrying its own destination. One unconnected UDP
// socket on this side serves the whole association, which is what makes NAT
// traversal behave: every destination sees the same source port, so replies
// to a QUIC or DNS exchange come back where they are expected.
func (s *Server) handleUDP(conn net.Conn, br *bufio.Reader, user users.User) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		s.log.Debug("udp socket failed", "user", user.Name, "err", err)
		return
	}

	assoc := &udpAssoc{
		origins:  make(map[string]protocol.Addr),
		resolved: make(map[string]*net.UDPAddr),
	}

	var once sync.Once
	finish := func() {
		once.Do(func() {
			pc.Close()
			conn.Close()
		})
	}
	defer finish()

	s.log.Debug("udp association open", "user", user.Name, "local", pc.LocalAddr().String())

	go func() {
		defer finish()
		s.udpFromClient(conn, br, pc, assoc)
	}()
	s.udpToClient(conn, pc, assoc)
}

// udpFromClient forwards datagrams the client sent out to the internet.
func (s *Server) udpFromClient(conn net.Conn, br *bufio.Reader, pc net.PacketConn, assoc *udpAssoc) {
	buf := make([]byte, protocol.MaxDatagram)
	for {
		conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		dest, payload, err := protocol.ReadDatagram(br, buf)
		if err != nil {
			return
		}

		target, err := s.resolveUDP(dest, assoc)
		if err != nil {
			// One rejected destination does not end the association; the
			// client may be spraying to several and only some are allowed.
			s.log.Debug("udp destination refused", "dest", dest.String(), "err", err)
			continue
		}
		assoc.remember(target, dest)

		pc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := pc.WriteTo(payload, target); err != nil {
			return
		}
		s.stats.bytesOut.Add(int64(len(payload)))
	}
}

// udpToClient forwards replies back down the stream.
func (s *Server) udpToClient(conn net.Conn, pc net.PacketConn, assoc *udpAssoc) {
	buf := make([]byte, protocol.MaxDatagram)
	out := make([]byte, 0, protocol.MaxDatagram+64)

	for {
		pc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		// Report the reply under the name the client used, not the address
		// it resolved to: an application that sent to "dns.google" and gets
		// a packet from 8.8.8.8 may discard it.
		src := assoc.origin(from)
		out, err = protocol.AppendDatagram(out[:0], src, buf[:n])
		if err != nil {
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
		s.stats.bytesIn.Add(int64(n))
	}
}

// resolveUDP applies the destination policy and turns an address into a
// concrete UDP endpoint.
func (s *Server) resolveUDP(dest protocol.Addr, assoc *udpAssoc) (*net.UDPAddr, error) {
	if s.blockedPorts[int(dest.Port)] {
		return nil, errBlockedPort
	}

	if dest.Type != protocol.AtypDomain {
		ip := net.ParseIP(dest.Host)
		if ip == nil {
			return nil, protocol.ErrBadIP
		}
		if !s.cfg.AllowPrivate && isPrivate(ip) {
			return nil, errPrivateDest
		}
		return &net.UDPAddr{IP: ip, Port: int(dest.Port)}, nil
	}

	if cached, ok := assoc.lookup(dest.String()); ok {
		return cached, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, dest.Host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if !s.cfg.AllowPrivate && isPrivate(a.IP) {
			continue
		}
		target := &net.UDPAddr{IP: a.IP, Port: int(dest.Port)}
		assoc.cache(dest.String(), target)
		return target, nil
	}
	return nil, errPrivateDest
}

// udpAssoc holds the per-association state: which name each destination was
// reached under, and the result of each name lookup.
type udpAssoc struct {
	mu       sync.Mutex
	origins  map[string]protocol.Addr
	resolved map[string]*net.UDPAddr
}

func (a *udpAssoc) remember(target *net.UDPAddr, dest protocol.Addr) {
	if dest.Type != protocol.AtypDomain {
		return // the reply address already matches what the client sent
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.origins) >= udpResolveLimit {
		clear(a.origins)
	}
	a.origins[target.String()] = dest
}

func (a *udpAssoc) origin(from net.Addr) protocol.Addr {
	a.mu.Lock()
	dest, ok := a.origins[from.String()]
	a.mu.Unlock()
	if ok {
		return dest
	}

	addr, err := protocol.ParseAddr(from.String())
	if err != nil {
		return protocol.Addr{Type: protocol.AtypIPv4, Host: "0.0.0.0"}
	}
	return addr
}

func (a *udpAssoc) lookup(key string) (*net.UDPAddr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	addr, ok := a.resolved[key]
	return addr, ok
}

func (a *udpAssoc) cache(key string, addr *net.UDPAddr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.resolved) >= udpResolveLimit {
		clear(a.resolved)
	}
	a.resolved[key] = addr
}
