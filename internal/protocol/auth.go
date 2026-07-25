package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

// Authentication proves, in both directions, that the peer knows a 32-byte
// pre-shared key -- and that it is the peer at the other end of this exact
// TLS session.
//
// Both tags cover the RFC 5705 exported keying material of the enclosing TLS
// connection. That binding is what makes an untrusted certificate safe, and
// it is worth spelling out what it rules out:
//
//   - Machine-in-the-middle. An attacker who terminates TLS sees binding B1
//     towards the client and B2 towards the server. The client's tag is
//     computed over B1, so forwarding it to the server (which checks against
//     B2) fails; forging the server's tag needs the key. Both sides abort.
//     This holds even though the client never validates the certificate.
//   - Replay. A recorded tag is useless: every TLS session derives a fresh
//     binding, so an old tag never validates again. No nonce database, no
//     clock synchronisation, no replay window to tune.
//   - Active probing. A scanner that does not hold the key cannot produce a
//     valid tag, and the server answers it from the decoy site instead. The
//     port is indistinguishable from an ordinary web server.
//
// No user identifier ever appears on the wire. The server finds the matching
// key by trying each one, which costs a single HMAC per user per connection.

const (
	// ExporterLabel is the RFC 5705 label used to derive the channel binding.
	ExporterLabel = "EXPORTER-prx-auth-v1"

	// ExporterLen is how many bytes of keying material the tags bind to.
	ExporterLen = 32

	// NonceSize is the client's per-connection random nonce.
	NonceSize = 16

	// MACSize is the length of an authentication tag.
	MACSize = sha256.Size

	// KeySize is the required pre-shared key length.
	KeySize = 32

	// AuthRequestSize is the fixed prefix a server reads before it can tell
	// a genuine client from a stray probe.
	AuthRequestSize = NonceSize + MACSize
)

// Errors returned by the authentication helpers.
var (
	ErrAuth    = errors.New("prx: authentication failed")
	ErrKeySize = errors.New("prx: pre-shared key must be 32 bytes")
)

// Exporter is satisfied by *tls.ConnectionState from both crypto/tls and
// utls, which is all either side needs from its TLS stack.
type Exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// Binding extracts the channel binding value from a completed handshake.
func Binding(e Exporter) ([]byte, error) {
	return e.ExportKeyingMaterial(ExporterLabel, nil, ExporterLen)
}

func tag(key, binding, nonce []byte, direction string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(direction))
	h.Write(binding)
	h.Write(nonce)
	return h.Sum(nil)
}

// ClientTag is the tag a client sends to prove it holds key.
func ClientTag(key, binding, nonce []byte) []byte {
	return tag(key, binding, nonce, "prx-client-v1")
}

// ServerTag is the tag a server sends back to prove the same.
func ServerTag(key, binding, nonce []byte) []byte {
	return tag(key, binding, nonce, "prx-server-v1")
}

// ClientAuth runs the client half of the handshake over an established TLS
// connection and reports whether the server holds the same key.
func ClientAuth(rw io.ReadWriter, state Exporter, key []byte) error {
	if len(key) != KeySize {
		return ErrKeySize
	}
	binding, err := Binding(state)
	if err != nil {
		return err
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	out := make([]byte, 0, AuthRequestSize+2+MaxPadding)
	out = append(out, nonce...)
	out = append(out, ClientTag(key, binding, nonce)...)
	out = AppendPadding(out)
	if _, err := rw.Write(out); err != nil {
		return err
	}

	var got [MACSize]byte
	if _, err := io.ReadFull(rw, got[:]); err != nil {
		// A server that rejected us hands the connection to its decoy, so
		// what arrives here is whatever that decoy said -- never a valid tag.
		return ErrAuth
	}
	if subtle.ConstantTimeCompare(got[:], ServerTag(key, binding, nonce)) != 1 {
		return ErrAuth
	}
	return SkipPadding(rw)
}

// ServerAccept completes the server half once the client's key has been
// identified, telling the client it was recognised.
func ServerAccept(w io.Writer, key, binding, nonce []byte) error {
	out := make([]byte, 0, MACSize+2+MaxPadding)
	out = append(out, ServerTag(key, binding, nonce)...)
	out = AppendPadding(out)
	_, err := w.Write(out)
	return err
}
