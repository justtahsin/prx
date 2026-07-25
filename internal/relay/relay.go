// Package relay copies bytes between two connections.
//
// This is the hot path: every proxied byte passes through it twice, so it
// avoids per-connection allocation and preserves half-close semantics.
package relay

import (
	"io"
	"net"
	"sync"
	"time"
)

// BufferSize is the copy buffer size. 32 KiB is large enough to keep syscall
// overhead low on fast links while staying small enough that thousands of
// concurrent connections do not dominate memory.
const BufferSize = 32 * 1024

var buffers = sync.Pool{
	New: func() any {
		b := make([]byte, BufferSize)
		return &b
	},
}

// closeWriter is implemented by *net.TCPConn, *tls.Conn and *utls.UConn.
type closeWriter interface {
	CloseWrite() error
}

// halfClose shuts down the write side of c if it can, so the peer sees a
// clean end-of-stream. Protocols that signal "request finished" by closing
// one direction -- HTTP without content-length, some database clients --
// break if the whole connection is torn down instead.
func halfClose(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	c.Close()
}

// Copy moves bytes from src to dst using a pooled buffer, then half-closes
// dst. srcReader may be a buffered reader wrapping src; pass nil to read from
// src directly.
func Copy(dst net.Conn, src net.Conn, srcReader io.Reader) (int64, error) {
	if srcReader == nil {
		srcReader = src
	}
	buf := buffers.Get().(*[]byte)
	defer buffers.Put(buf)

	n, err := io.CopyBuffer(onlyWriter{dst}, srcReader, *buf)
	halfClose(dst)
	return n, err
}

// onlyWriter hides any ReadFrom method on the destination so io.CopyBuffer
// actually uses our pooled buffer instead of allocating its own.
type onlyWriter struct{ io.Writer }

// Pipe copies in both directions until both are finished, then closes both
// connections. aReader and bReader may be buffered readers wrapping a and b
// respectively; pass nil to read from the connection.
//
// It returns bytes sent from a to b and from b to a.
func Pipe(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		aToB, _ = Copy(b, a, aReader)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = Copy(a, b, bReader)
	}()

	wg.Wait()
	a.Close()
	b.Close()
	return aToB, bToA
}

// Tune applies the socket options every relayed connection wants.
//
// TCP_NODELAY matters because a proxy forwards whatever it is handed:
// without it, small writes from an interactive session queue behind Nagle's
// algorithm and add latency the user notices. Keepalives matter because idle
// pooled connections otherwise get silently dropped by NAT.
func Tune(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
}
