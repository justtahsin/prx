package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/justtahsin/prx/internal/link"
)

// Options configures a local client.
type Options struct {
	Link     link.Link
	SOCKS    string // local SOCKS5 listen address, empty to disable
	HTTP     string // local HTTP proxy listen address, empty to disable
	PoolSize int
}

// Client runs the local proxy listeners over one tunnel.
type Client struct {
	opts   Options
	dialer *Dialer
	log    *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
}

// New builds a client from its options.
func New(opts Options, log *slog.Logger) (*Client, error) {
	if opts.SOCKS == "" && opts.HTTP == "" {
		return nil, errors.New("prx: nothing to do: enable the SOCKS or HTTP listener")
	}
	dialer, err := NewDialer(opts.Link, opts.PoolSize, log)
	if err != nil {
		return nil, err
	}
	return &Client{opts: opts, dialer: dialer, log: log}, nil
}

// Dialer exposes the underlying tunnel dialer.
func (c *Client) Dialer() *Dialer { return c.dialer }

// Run starts the listeners and blocks until ctx is cancelled or a listener
// fails.
func (c *Client) Run(ctx context.Context) error {
	errs := make(chan error, 2)
	started := 0

	if addr := c.opts.SOCKS; addr != "" {
		ln, err := c.listen(addr)
		if err != nil {
			c.Close()
			return err
		}
		c.log.Info("socks5 proxy listening", "addr", ln.Addr().String())
		warnIfExposed(c.log, "socks5", ln.Addr())
		started++
		go func() { errs <- NewSOCKS5(c.dialer, c.log).Serve(ln) }()
	}

	if addr := c.opts.HTTP; addr != "" {
		ln, err := c.listen(addr)
		if err != nil {
			c.Close()
			return err
		}
		c.log.Info("http proxy listening", "addr", ln.Addr().String())
		warnIfExposed(c.log, "http", ln.Addr())
		started++
		go func() { errs <- NewHTTPProxy(c.dialer, c.log).Serve(ln) }()
	}

	c.log.Info("tunnel ready",
		"server", c.dialer.Server(),
		"sni", c.dialer.SNI(),
		"pool", c.opts.PoolSize)

	select {
	case <-ctx.Done():
		c.Close()
		// Drain so the listener goroutines are not left blocked on send.
		for i := 0; i < started; i++ {
			<-errs
		}
		return nil
	case err := <-errs:
		c.Close()
		return err
	}
}

func (c *Client) listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("prx: listening on %s: %w", addr, err)
	}
	c.mu.Lock()
	c.listeners = append(c.listeners, ln)
	c.mu.Unlock()
	return ln, nil
}

// Close stops the listeners and the tunnel.
func (c *Client) Close() error {
	c.mu.Lock()
	listeners := c.listeners
	c.listeners = nil
	c.mu.Unlock()

	for _, ln := range listeners {
		ln.Close()
	}
	return c.dialer.Close()
}

// warnIfExposed points out a listener that is reachable from outside this
// machine. Neither front end asks for credentials, because a loopback
// listener does not need any -- but bound to a public interface it is an
// open proxy for anyone who finds it.
func warnIfExposed(log *slog.Logger, name string, addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return
	}
	log.Warn("listener is reachable from the network and has no authentication",
		"listener", name, "addr", addr.String())
}

// ProbeResult reports what a connectivity check found.
type ProbeResult struct {
	Handshake time.Duration // time to an authenticated tunnel
	Request   time.Duration // time to a response through the tunnel
	Status    string
	ExitIP    string
}

// DefaultProbeURL is fetched by Probe to confirm traffic flows end to end.
// It is a small, well-known endpoint that reports the requesting address.
const DefaultProbeURL = "https://api.ipify.org"

// Probe checks that the tunnel authenticates and carries traffic.
func Probe(ctx context.Context, l link.Link, probeURL string, log *slog.Logger, opts ...Option) (ProbeResult, error) {
	var result ProbeResult

	// Pool size zero: a probe should measure a cold connection, which is
	// what tells the operator whether the server is reachable at all.
	dialer, err := NewDialer(l, 0, log, opts...)
	if err != nil {
		return result, err
	}
	defer dialer.Close()

	start := time.Now()
	tunnel, err := dialer.connect(ctx)
	if err != nil {
		return result, err
	}
	tunnel.conn.Close()
	result.Handshake = time.Since(start)

	if probeURL == "" {
		probeURL = DefaultProbeURL
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return result, err
	}

	start = time.Now()
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return result, fmt.Errorf("prx: request through tunnel failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	result.Request = time.Since(start)
	result.Status = resp.Status
	result.ExitIP = strings.TrimSpace(string(body))
	return result, nil
}
