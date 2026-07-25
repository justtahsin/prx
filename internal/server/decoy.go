package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/justtahsin/prx/internal/relay"
)

// Anything that reaches the server without a valid key is treated as an
// ordinary visitor rather than an intruder. It is handed either to a real
// web server (config "fallback") or to the built-in page below.
//
// This is the difference between a port that can be identified by probing
// and one that cannot. A scanner that connects, speaks TLS and sends an HTTP
// request gets a web server's response; nothing in the exchange distinguishes
// this host from any other HTTPS site. Closing the connection instead, or
// answering with an error, is itself the signal a scanner is looking for.
//
// The built-in page is convincing to a scanner but not to a determined
// fingerprinter: Go's HTTP server orders headers differently from nginx.
// Operators expecting that level of attention should point "fallback" at a
// real web server, which makes the imitation exact because it is not one.

const (
	decoyReadTimeout = 30 * time.Second
	decoyIdleTimeout = 60 * time.Second
	fallbackTimeout  = 5 * time.Second
)

var decoyPage = []byte(`<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`)

// serveDecoy disposes of an unauthenticated connection. seen holds bytes
// already read from it, which are replayed so the visitor's request is not
// lost, and br is the buffered reader holding anything after that.
func (s *Server) serveDecoy(conn net.Conn, br io.Reader, seen []byte) {
	// Whatever we read while deciding this was not a client belongs to the
	// visitor's request; splice it back on the front.
	var reader io.Reader = br
	if len(seen) > 0 {
		reader = io.MultiReader(bytes.NewReader(seen), br)
	}
	conn.SetDeadline(time.Now().Add(decoyIdleTimeout))

	if s.cfg.Fallback != "" {
		if s.relayToFallback(conn, reader) {
			return
		}
		// Falling through on a failed dial is deliberate: a backend that is
		// down must not turn into a distinguishable "connection closed".
	}
	s.serveDecoyPage(conn, reader)
}

// relayToFallback hands the connection to the configured web server and
// reports whether it managed to.
func (s *Server) relayToFallback(conn net.Conn, reader io.Reader) bool {
	backend, err := net.DialTimeout("tcp", s.cfg.Fallback, fallbackTimeout)
	if err != nil {
		s.log.Debug("fallback dial failed", "addr", s.cfg.Fallback, "err", err)
		return false
	}
	relay.Tune(backend)
	conn.SetDeadline(time.Time{})
	relay.Pipe(conn, reader, backend, nil)
	return true
}

// serveDecoyPage answers the visitor with the built-in page, over whichever
// HTTP version was negotiated during the handshake.
//
// Honouring the negotiation matters: a server that agrees to HTTP/2 in ALPN
// and then answers in HTTP/1.1 produces a protocol error, and a port that
// breaks in a distinctive way is worse than one that never offered HTTP/2.
func (s *Server) serveDecoyPage(conn net.Conn, reader io.Reader) {
	front := &prefixConn{Conn: conn, reader: reader}
	conn.SetDeadline(time.Now().Add(decoyIdleTimeout))

	if negotiatedProtocol(conn) == "h2" {
		(&http2.Server{IdleTimeout: decoyIdleTimeout}).ServeConn(front, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(decoyHandler),
		})
		return
	}

	ln := &oneShotListener{conn: front, done: make(chan struct{})}

	srv := &http.Server{
		Handler:     http.HandlerFunc(decoyHandler),
		ReadTimeout: decoyReadTimeout,
		IdleTimeout: decoyIdleTimeout,
		ErrorLog:    nil,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				ln.finish()
			}
		},
	}
	_ = srv.Serve(ln)
}

// negotiatedProtocol reports the ALPN protocol agreed during the handshake.
func negotiatedProtocol(conn net.Conn) string {
	stater, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return ""
	}
	return stater.ConnectionState().NegotiatedProtocol
}

func decoyHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")
	h.Set("Accept-Ranges", "bytes")

	if r.URL.Path != "/" {
		h.Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n"+
				"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"+
				"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
		}
		return
	}

	http.ServeContent(w, r, "index.html", decoyModTime, bytes.NewReader(decoyPage))
}

// decoyModTime is fixed at process start so the page has a stable
// Last-Modified across requests, the way a static file would.
var decoyModTime = time.Now().Add(-72 * time.Hour).Truncate(time.Second)

// prefixConn is a connection whose reads come from an alternate reader,
// used to put already-consumed bytes back in front of the stream.
type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// oneShotListener presents a single existing connection as a net.Listener so
// it can be handed to net/http, which handles request parsing, keep-alive
// and malformed input correctly without us reimplementing any of it.
type oneShotListener struct {
	conn net.Conn

	once sync.Once
	done chan struct{}
	mu   sync.Mutex
	sent bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.sent {
		l.sent = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()

	// The single connection is gone; block until it finishes so http.Server
	// keeps serving it, then report closure to end Serve.
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneShotListener) finish() { l.once.Do(func() { close(l.done) }) }

func (l *oneShotListener) Close() error {
	l.finish()
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
