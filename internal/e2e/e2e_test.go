// Package e2e exercises a real client against a real server over a real
// socket: TLS handshake, authentication, relaying and the decoy path.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/justtahsin/prx/internal/client"
	"github.com/justtahsin/prx/internal/config"
	"github.com/justtahsin/prx/internal/link"
	"github.com/justtahsin/prx/internal/logging"
	"github.com/justtahsin/prx/internal/protocol"
	"github.com/justtahsin/prx/internal/server"
	"github.com/justtahsin/prx/internal/users"
)

func testLogger() *slog.Logger { return logging.New("error") }

// startServer brings up a server on a loopback port and returns its address
// and a link for the user it created.
func startServer(t *testing.T, tweak func(*config.Server)) link.Link {
	t.Helper()

	cfg := config.DefaultServer()
	cfg.Listen = "127.0.0.1:0"
	cfg.UsersFile = filepath.Join(t.TempDir(), "users.json")
	// Test destinations are all on loopback, which the default policy
	// exists to refuse.
	cfg.AllowPrivate = true
	cfg.BlockPorts = nil
	if tweak != nil {
		tweak(&cfg)
	}

	store, err := users.Open(cfg.UsersFile)
	if err != nil {
		t.Fatalf("opening user store: %v", err)
	}
	user, err := store.Add("tester", "")
	if err != nil {
		t.Fatalf("adding user: %v", err)
	}

	srv, err := server.New(cfg, store, testLogger())
	if err != nil {
		t.Fatalf("building server: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	return link.Link{
		Host:        host,
		Port:        port,
		Key:         user.Key,
		SNI:         "www.example.com",
		Fingerprint: "chrome",
		Label:       "tester",
	}
}

func TestTunnelCarriesHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	defer origin.Close()

	l := startServer(t, nil)
	dialer, err := client.NewDialer(l, 2, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	resp, err := httpClient.Get(origin.URL + "/greeting")
	if err != nil {
		t.Fatalf("request through the tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from /greeting" {
		t.Errorf("got %q", body)
	}
}

func TestTunnelMovesLargePayloadIntact(t *testing.T) {
	// A payload well past the relay buffer and the TLS record size, so that
	// framing errors in either direction would show up as corruption.
	payload := make([]byte, 4<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(received, payload) {
			http.Error(w, "upload corrupted", http.StatusBadRequest)
			return
		}
		w.Write(payload)
	}))
	defer origin.Close()

	l := startServer(t, nil)
	dialer, err := client.NewDialer(l, 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	resp, err := httpClient.Post(origin.URL, "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %s: %s", resp.Status, body)
	}
	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Errorf("download corrupted: %d bytes back, wanted %d", len(echoed), len(payload))
	}
}

func TestWrongKeyGetsTheDecoy(t *testing.T) {
	l := startServer(t, nil)

	// A different key of the correct length: the server must not reveal that
	// it is anything but a web server.
	wrong, err := users.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l.Key = wrong

	dialer, err := client.NewDialer(l, 0, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dest, _ := protocol.ParseAddr("example.com:80")
	if _, err := dialer.Open(ctx, dest); err == nil {
		t.Fatal("a wrong key was accepted")
	}
}

func TestDisabledUserIsRefused(t *testing.T) {
	cfg := config.DefaultServer()
	cfg.Listen = "127.0.0.1:0"
	cfg.UsersFile = filepath.Join(t.TempDir(), "users.json")
	cfg.AllowPrivate = true

	store, err := users.Open(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.Add("tester", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnabled("tester", false); err != nil {
		t.Fatal(err)
	}

	srv, err := server.New(cfg, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l := link.Link{Host: host, Port: port, Key: user.Key, SNI: "x.example", Fingerprint: "chrome"}

	dialer, err := client.NewDialer(l, 0, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dest, _ := protocol.ParseAddr("example.com:80")
	if _, err := dialer.Open(ctx, dest); err == nil {
		t.Fatal("a disabled user was let in")
	}
}

// TestProbeSeesAWebServer is the probe-resistance check: connect the way a
// scanner would and confirm the answer is an ordinary web page, promptly.
func TestProbeSeesAWebServer(t *testing.T) {
	l := startServer(t, nil)

	for _, request := range []string{
		"GET / HTTP/1.0\r\n\r\n",                          // shorter than an auth record
		"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", // longer than one
		"HEAD / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
	} {
		t.Run(strings.Fields(request)[0]+strconv.Itoa(len(request)), func(t *testing.T) {
			conn, err := tls.Dial("tcp", l.Addr(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "www.example.com",
				NextProtos:         []string{"http/1.1"},
			})
			if err != nil {
				t.Fatalf("tls dial: %v", err)
			}
			defer conn.Close()

			// A real web server answers immediately. This deadline is what
			// makes the test meaningful: without the HTTP detection in the
			// server, the short request blocks until the handshake timeout.
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(conn, request); err != nil {
				t.Fatalf("write: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("no HTTP response to a probe: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status %s, want 200", resp.Status)
			}
			if got := resp.Header.Get("Server"); got != "nginx" {
				t.Errorf("Server header %q", got)
			}
		})
	}
}

func TestProbeCertificateMatchesRequestedSNI(t *testing.T) {
	l := startServer(t, nil)

	const name = "shop.example.org"
	conn, err := tls.Dial("tcp", l.Addr(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         name,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no certificate presented")
	}
	if err := certs[0].VerifyHostname(name); err != nil {
		t.Errorf("certificate does not match the requested SNI: %v", err)
	}
}

func TestSOCKS5RelaysTCP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "socks ok")
	}))
	defer origin.Close()

	socksAddr := startSOCKS(t, startServer(t, nil))

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	originAddr, err := protocol.ParseAddr(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if err := socksConnect(conn, originAddr); err != nil {
		t.Fatal(err)
	}

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", originAddr); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "socks ok") {
		t.Errorf("unexpected response: %q", resp)
	}
}

func TestSOCKS5RelaysUDP(t *testing.T) {
	// An echo server standing in for DNS or QUIC: the point is that
	// datagrams survive the round trip with their addressing intact.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	socksAddr := startSOCKS(t, startServer(t, nil))

	ctrl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(15 * time.Second))

	relayAddr, err := socksUDPAssociate(ctrl)
	if err != nil {
		t.Fatal(err)
	}

	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	local.SetDeadline(time.Now().Add(15 * time.Second))

	target, err := protocol.ParseAddr(echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	datagram := []byte{0x00, 0x00, 0x00}
	datagram, err = target.AppendTo(datagram)
	if err != nil {
		t.Fatal(err)
	}
	datagram = append(datagram, []byte("ping")...)

	if _, err := local.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, _, err := local.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reply came back through the tunnel: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("echo:ping")) {
		t.Errorf("unexpected datagram: %q", buf[:n])
	}
}

// TestPacketConnRelaysUDP covers the datagram path the Android client takes.
// Its network stack asks for a net.PacketConn per association rather than
// speaking SOCKS5, so this is a different adapter over the same association.
func TestPacketConnRelaysUDP(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	dialer, err := client.NewDialer(startServer(t, nil), 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	packets, err := dialer.OpenPacketConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	packets.SetDeadline(time.Now().Add(15 * time.Second))

	target, err := net.ResolveUDPAddr("udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Several datagrams in a row: the association is one stream, so a
	// framing mistake would show up as the second one being misread.
	for i, payload := range []string{"one", "two", "three"} {
		if _, err := packets.WriteTo([]byte(payload), target); err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}

		buf := make([]byte, 2048)
		n, from, err := packets.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if got, want := string(buf[:n]), "echo:"+payload; got != want {
			t.Errorf("datagram %d: got %q, want %q", i, got, want)
		}
		if from.String() != target.String() {
			t.Errorf("datagram %d: reply came from %s, want %s", i, from, target)
		}
	}
}

func TestBlockedPortIsRefused(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	_, portStr, _ := net.SplitHostPort(origin.Addr().String())
	port, _ := strconv.Atoi(portStr)

	l := startServer(t, func(cfg *config.Server) {
		cfg.BlockPorts = []int{port}
	})

	dialer, err := client.NewDialer(l, 0, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	assertDestinationRefused(t, dialer, origin.Addr().String())
}

func TestPrivateDestinationIsRefusedByDefault(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	// The default policy: a public server must not be usable as a way into
	// the operator's own network.
	l := startServer(t, func(cfg *config.Server) { cfg.AllowPrivate = false })

	dialer, err := client.NewDialer(l, 0, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	assertDestinationRefused(t, dialer, origin.Addr().String())
}

// assertDestinationRefused checks that a destination the policy rejects
// yields a closed tunnel rather than a working one.
func assertDestinationRefused(t *testing.T, dialer *client.Dialer, addr string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dest, err := protocol.ParseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Open(ctx, dest)
	if err != nil {
		return // refused before the tunnel opened, which is also correct
	}
	defer conn.Close()

	// The refusal is expressed by closing, so a read must not return data.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("destination was reachable: read %d bytes", n)
	}
}

func TestLinkSurvivesRoundTrip(t *testing.T) {
	key, err := users.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	want := link.Link{
		Host:        "203.0.113.9",
		Port:        443,
		Key:         key,
		SNI:         "www.some-site.example",
		Fingerprint: "firefox",
		Label:       "phone",
	}

	got, err := link.Parse(want.String())
	if err != nil {
		t.Fatalf("parsing %q: %v", want.String(), err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestLinkDefaultsAndRejections(t *testing.T) {
	key, _ := users.NewKey()

	// A link with no SNI still has to produce a usable one, since the field
	// is optional in the URL.
	minimal := fmt.Sprintf("prx://%s@198.51.100.4:443", key)
	l, err := link.Parse(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if l.SNI != link.DefaultSNI || l.Fingerprint != link.DefaultFingerprint {
		t.Errorf("defaults not applied: %+v", l)
	}

	for _, bad := range []string{
		"http://" + key + "@1.2.3.4:443", // wrong scheme
		"prx://1.2.3.4:443",              // no key
		"prx://" + key + "@1.2.3.4",      // no port
		"prx://tooshort@1.2.3.4:443",     // key of the wrong length
	} {
		if _, err := link.Parse(bad); err == nil {
			t.Errorf("link.Parse(%q) accepted a malformed link", bad)
		}
	}
}

func TestUserStoreReloadsAfterChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	store, err := users.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("first", ""); err != nil {
		t.Fatal(err)
	}

	// A second handle stands in for the running server: adding a user with
	// the CLI has to reach it without a restart.
	running, err := users.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if total, _ := running.Count(); total != 1 {
		t.Fatalf("expected 1 user, got %d", total)
	}

	added, err := store.Add("second", "")
	if err != nil {
		t.Fatal(err)
	}
	// Timestamps have one-second resolution on some filesystems, so make the
	// change unambiguous.
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))

	if err := running.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := running.Get(added.Name); err != nil {
		t.Errorf("reload did not pick up the new user: %v", err)
	}
}

// ---------------------------------------------------------------- helpers

// startSOCKS runs a client's SOCKS5 front end and returns its address.
func startSOCKS(t *testing.T, l link.Link) string {
	t.Helper()

	dialer, err := client.NewDialer(l, 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialer.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go client.NewSOCKS5(dialer, testLogger()).Serve(ln)
	return ln.Addr().String()
}

// socksConnect performs a SOCKS5 greeting and CONNECT request.
func socksConnect(conn net.Conn, dest protocol.Addr) error {
	if err := socksGreet(conn); err != nil {
		return err
	}

	request := []byte{0x05, 0x01, 0x00}
	request, err := dest.AppendTo(request)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return err
	}
	return socksReadReply(conn)
}

// socksUDPAssociate performs a SOCKS5 UDP ASSOCIATE and returns the relay
// address the client should send datagrams to.
func socksUDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	if err := socksGreet(conn); err != nil {
		return nil, err
	}

	request := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	head := make([]byte, 3)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP associate refused: code %d", head[1])
	}
	bound, err := protocol.ReadAddr(conn)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", bound.String())
}

func socksGreet(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 greeting refused: %v", reply)
	}
	return nil
}

func socksReadReply(conn net.Conn) error {
	head := make([]byte, 3)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 request refused: code %d", head[1])
	}
	_, err := protocol.ReadAddr(conn)
	return err
}
