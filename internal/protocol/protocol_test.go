package protocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestAddrRoundTrip(t *testing.T) {
	cases := []Addr{
		{Type: AtypIPv4, Host: "1.2.3.4", Port: 80},
		{Type: AtypIPv6, Host: "2606:4700:4700::1111", Port: 443},
		{Type: AtypDomain, Host: "example.com", Port: 8443},
		{Type: AtypDomain, Host: strings.Repeat("a", maxDomainLen), Port: 1},
		{Type: AtypIPv4, Host: "0.0.0.0", Port: 0},
		{Type: AtypIPv4, Host: "255.255.255.255", Port: 65535},
	}

	for _, want := range cases {
		encoded, err := want.AppendTo(nil)
		if err != nil {
			t.Fatalf("AppendTo(%v): %v", want, err)
		}

		got, err := ReadAddr(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("ReadAddr(%v): %v", want, err)
		}
		if got != want {
			t.Errorf("round trip: got %+v, want %+v", got, want)
		}
	}
}

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		want Addr
	}{
		{"1.2.3.4:80", Addr{Type: AtypIPv4, Host: "1.2.3.4", Port: 80}},
		{"[::1]:53", Addr{Type: AtypIPv6, Host: "::1", Port: 53}},
		{"example.com:443", Addr{Type: AtypDomain, Host: "example.com", Port: 443}},
	}
	for _, c := range cases {
		got, err := ParseAddr(c.in)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseAddr(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"", "no-port", "host:99999", "host:abc"} {
		if _, err := ParseAddr(bad); err == nil {
			t.Errorf("ParseAddr(%q) accepted a malformed address", bad)
		}
	}
}

func TestReadAddrRejectsGarbage(t *testing.T) {
	// An unknown address type is how an HTTP request looks when it reaches
	// the address decoder, so it has to be an error rather than a panic.
	if _, err := ReadAddr(bytes.NewReader([]byte("GET / HTTP/1.1\r\n"))); err == nil {
		t.Fatal("ReadAddr accepted an HTTP request")
	}
	if _, err := ReadAddr(bytes.NewReader([]byte{AtypDomain, 0})); !errors.Is(err, ErrEmptyDomain) {
		t.Fatalf("ReadAddr with a zero-length domain: got %v, want ErrEmptyDomain", err)
	}
	if _, err := ReadAddr(bytes.NewReader([]byte{AtypIPv4, 1, 2})); err == nil {
		t.Fatal("ReadAddr accepted a truncated address")
	}
}

func TestRequestRoundTrip(t *testing.T) {
	want := Request{Cmd: CmdTCPConnect, Dest: Addr{Type: AtypDomain, Host: "example.com", Port: 443}}
	encoded, err := want.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	udp := Request{Cmd: CmdUDPAssoc}
	encoded, err = udp.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = ReadRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmd != CmdUDPAssoc {
		t.Errorf("got command %d, want CmdUDPAssoc", got.Cmd)
	}

	if _, err := ReadRequest(bytes.NewReader([]byte{0x7f})); !errors.Is(err, ErrBadCommand) {
		t.Fatalf("ReadRequest with an unknown command: got %v, want ErrBadCommand", err)
	}
}

func TestPaddingVariesAndIsConsumed(t *testing.T) {
	sizes := make(map[int]bool)
	for i := 0; i < 64; i++ {
		block := AppendPadding(nil)
		sizes[len(block)] = true

		r := bytes.NewReader(block)
		if err := SkipPadding(r); err != nil {
			t.Fatalf("SkipPadding: %v", err)
		}
		if r.Len() != 0 {
			t.Fatalf("SkipPadding left %d bytes behind", r.Len())
		}
	}
	// Padding exists to keep the record from having a constant length; if it
	// always came out the same size it would not be doing anything.
	if len(sizes) < 8 {
		t.Errorf("padding produced only %d distinct sizes over 64 tries", len(sizes))
	}
}

func TestSkipPaddingRejectsOversizedBlock(t *testing.T) {
	// A claimed length beyond the cap must be refused rather than believed:
	// it would otherwise let a peer make us read an arbitrary amount.
	oversized := []byte{0xff, 0xff}
	if err := SkipPadding(bytes.NewReader(oversized)); !errors.Is(err, ErrBadPadding) {
		t.Fatalf("got %v, want ErrBadPadding", err)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	dest := Addr{Type: AtypDomain, Host: "dns.example", Port: 53}
	payload := []byte("query bytes")

	framed, err := AppendDatagram(nil, dest, payload)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, MaxDatagram)
	gotAddr, gotPayload, err := ReadDatagram(bytes.NewReader(framed), buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != dest {
		t.Errorf("address: got %+v, want %+v", gotAddr, dest)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q, want %q", gotPayload, payload)
	}
}

func TestDatagramStreamStaysAligned(t *testing.T) {
	// Several datagrams back to back must decode individually: the length
	// prefix is the only thing keeping the stream framed.
	var stream []byte
	want := []string{"one", "two", "three"}
	for _, s := range want {
		var err error
		stream, err = AppendDatagram(stream, Addr{Type: AtypIPv4, Host: "9.9.9.9", Port: 53}, []byte(s))
		if err != nil {
			t.Fatal(err)
		}
	}

	r := bytes.NewReader(stream)
	buf := make([]byte, MaxDatagram)
	for _, expected := range want {
		_, payload, err := ReadDatagram(r, buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != expected {
			t.Fatalf("got %q, want %q", payload, expected)
		}
	}
	if r.Len() != 0 {
		t.Errorf("%d bytes left over", r.Len())
	}
}

// fakeExporter stands in for a TLS connection state.
type fakeExporter struct{ material []byte }

func (f fakeExporter) ExportKeyingMaterial(_ string, _ []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	copy(out, f.material)
	return out, nil
}

func TestTagsAreBoundToTheSession(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	sessionA := bytes.Repeat([]byte{0xAA}, ExporterLen)
	sessionB := bytes.Repeat([]byte{0xBB}, ExporterLen)

	// This is the property the whole security argument rests on: a tag made
	// for one TLS session must not verify in another. It is what defeats
	// both replay and an intermediary that terminates TLS on both sides.
	if bytes.Equal(ClientTag(key, sessionA, nonce), ClientTag(key, sessionB, nonce)) {
		t.Error("client tag is identical across two different TLS sessions")
	}
	if bytes.Equal(ServerTag(key, sessionA, nonce), ServerTag(key, sessionB, nonce)) {
		t.Error("server tag is identical across two different TLS sessions")
	}

	// The two directions must also differ, or a client's tag could be
	// replayed back at it as the server's answer.
	if bytes.Equal(ClientTag(key, sessionA, nonce), ServerTag(key, sessionA, nonce)) {
		t.Error("client and server tags are identical")
	}

	other := make([]byte, KeySize)
	rand.Read(other)
	if bytes.Equal(ClientTag(key, sessionA, nonce), ClientTag(other, sessionA, nonce)) {
		t.Error("tag does not depend on the key")
	}
}

func TestClientAuthRejectsWrongServerTag(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	state := fakeExporter{material: bytes.Repeat([]byte{0x11}, ExporterLen)}

	// A server that does not hold the key cannot answer correctly; whatever
	// it sends back must be refused.
	wrong := make([]byte, MACSize)
	transcript := &halfDuplex{toClient: bytes.NewReader(append(wrong, 0x00, 0x00))}

	err := ClientAuth(transcript, state, key)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestClientAuthRejectsShortKey(t *testing.T) {
	state := fakeExporter{material: bytes.Repeat([]byte{0x11}, ExporterLen)}
	err := ClientAuth(&halfDuplex{toClient: bytes.NewReader(nil)}, state, []byte("too short"))
	if !errors.Is(err, ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

// halfDuplex is a ReadWriter that discards writes and replays a fixed
// response, standing in for a peer.
type halfDuplex struct {
	toClient io.Reader
	written  bytes.Buffer
}

func (h *halfDuplex) Read(p []byte) (int, error)  { return h.toClient.Read(p) }
func (h *halfDuplex) Write(p []byte) (int, error) { return h.written.Write(p) }
