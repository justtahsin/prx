// Package link encodes and decodes prx:// connection URLs.
//
// One URL carries everything a client needs, which is the whole point: the
// operator runs `prxd user add`, the user pastes one string (or scans one QR
// code) and is connected. There is no config file to hand around and no
// second channel to get wrong.
//
// Form:
//
//	prx://<key>@<host>:<port>?sni=<name>&fp=<fingerprint>#<label>
//
// key  base64url-encoded 32-byte pre-shared key
// sni  the server name to put in the TLS handshake; free to choose, see
//
//	the note on Link.SNI
//
// fp   which browser's ClientHello to imitate (default chrome)
package link

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/justtahsin/prx/internal/users"
)

// Scheme is the URL scheme for connection links.
const Scheme = "prx"

// DefaultSNI is used when a link does not name one.
const DefaultSNI = "www.cloudflare.com"

// DefaultFingerprint is used when a link does not name one.
const DefaultFingerprint = "chrome"

// Errors returned when parsing a link.
var (
	ErrScheme  = errors.New("prx: not a prx:// link")
	ErrNoKey   = errors.New("prx: link has no key")
	ErrNoHost  = errors.New("prx: link has no host:port")
	ErrBadPort = errors.New("prx: link has a malformed port")
)

// Link is a parsed connection URL.
type Link struct {
	Host string // server address
	Port int    // server port
	Key  string // base64url pre-shared key

	// SNI is the server name sent in the TLS ClientHello. The server answers
	// with a certificate for whatever is asked, and the client authenticates
	// through the pre-shared key rather than the certificate, so this can be
	// set to any name that looks unremarkable from where the user is
	// connecting -- it is a camouflage setting, not a routing one.
	SNI string

	// Fingerprint selects which browser's ClientHello to imitate.
	Fingerprint string

	// Label is the human-readable name shown in clients.
	Label string
}

// Addr returns the server address in host:port form.
func (l Link) Addr() string {
	return net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
}

// KeyBytes decodes the link's pre-shared key.
func (l Link) KeyBytes() ([]byte, error) {
	return users.DecodeKey(l.Key)
}

// Validate reports whether the link is usable.
func (l Link) Validate() error {
	if l.Host == "" {
		return ErrNoHost
	}
	if l.Port <= 0 || l.Port > 65535 {
		return ErrBadPort
	}
	if l.Key == "" {
		return ErrNoKey
	}
	if _, err := l.KeyBytes(); err != nil {
		return err
	}
	return nil
}

// String renders the link as a prx:// URL.
func (l Link) String() string {
	q := url.Values{}
	if l.SNI != "" && l.SNI != DefaultSNI {
		q.Set("sni", l.SNI)
	}
	if l.Fingerprint != "" && l.Fingerprint != DefaultFingerprint {
		q.Set("fp", l.Fingerprint)
	}

	u := url.URL{
		Scheme:   Scheme,
		User:     url.User(l.Key),
		Host:     l.Addr(),
		RawQuery: q.Encode(),
		Fragment: l.Label,
	}
	return u.String()
}

// Parse reads a prx:// URL.
func Parse(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return Link{}, fmt.Errorf("prx: parsing link: %w", err)
	}
	if !strings.EqualFold(u.Scheme, Scheme) {
		return Link{}, ErrScheme
	}
	if u.User == nil || u.User.Username() == "" {
		return Link{}, ErrNoKey
	}

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Link{}, ErrNoHost
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Link{}, ErrBadPort
	}

	q := u.Query()
	l := Link{
		Host:        host,
		Port:        port,
		Key:         u.User.Username(),
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		Label:       u.Fragment,
	}
	if l.SNI == "" {
		l.SNI = DefaultSNI
	}
	if l.Fingerprint == "" {
		l.Fingerprint = DefaultFingerprint
	}
	return l, l.Validate()
}
