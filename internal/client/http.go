package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/relay"
)

// HTTPProxy serves an HTTP forward proxy on a local listener. It handles
// both CONNECT tunnels, which is what browsers use for HTTPS, and plain
// absolute-URI requests.
type HTTPProxy struct {
	dialer    *Dialer
	log       *slog.Logger
	transport *http.Transport
}

// NewHTTPProxy builds an HTTP proxy front end over the tunnel.
func NewHTTPProxy(d *Dialer, log *slog.Logger) *HTTPProxy {
	return &HTTPProxy{
		dialer: d,
		log:    log,
		transport: &http.Transport{
			DialContext:           d.DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ExpectContinueTimeout: time.Second,
			// Plain HTTP through a forward proxy is HTTP/1.1; TLS traffic
			// takes the CONNECT path and negotiates its own version
			// end to end.
			ForceAttemptHTTP2: false,
		},
	}
}

// Serve accepts connections until ln is closed.
func (p *HTTPProxy) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:     p,
		ReadTimeout: 0, // a tunnelled connection may idle indefinitely
		ErrorLog:    nil,
	}
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forward(w, r)
}

// connect implements the CONNECT method: open a tunnel, then get out of the
// way and copy bytes.
func (p *HTTPProxy) connect(w http.ResponseWriter, r *http.Request) {
	dest, err := protocol.ParseAddr(withDefaultPort(r.Host, "443"))
	if err != nil {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), tcpDialTimeout+warmDialTimeout)
	tunnel, err := p.dialer.Open(ctx, dest)
	cancel()
	if err != nil {
		p.log.Debug("connect failed", "dest", dest.String(), "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer tunnel.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "not supported", http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	relay.Tune(conn)

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	p.log.Debug("http connect", "dest", dest.String())
	// Anything the client pipelined after CONNECT is already in the
	// hijacked reader and must be forwarded before the socket itself.
	relay.Pipe(conn, buffered, tunnel, nil)
}

// forward relays a plain (non-CONNECT) proxy request.
func (p *HTTPProxy) forward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "this is a proxy; use an absolute URL or CONNECT", http.StatusBadRequest)
		return
	}

	outreq := r.Clone(r.Context())
	outreq.RequestURI = ""
	stripHopByHop(outreq.Header)

	resp, err := p.transport.RoundTrip(outreq)
	if err != nil {
		p.log.Debug("forward failed", "url", r.URL.String(), "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stripHopByHop(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// hopByHop are the headers that apply to a single transport hop and must not
// be passed on (RFC 9110 section 7.6.1).
var hopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHop(h http.Header) {
	// Connection may name further headers that are themselves hop-by-hop.
	for _, name := range h.Values("Connection") {
		for _, part := range strings.Split(name, ",") {
			if part = strings.TrimSpace(part); part != "" {
				h.Del(part)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func withDefaultPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, port)
}
