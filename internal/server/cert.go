package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// certSource supplies the certificate for each TLS handshake.
//
// In "auto" mode it mints a self-signed certificate whose name matches
// whatever SNI the client asked for. That is what lets a user choose any SNI
// in their link with no setup on the server: ask for www.cloudflare.com and
// that is the name in the certificate you get back.
//
// None of this is load-bearing for security. Clients authenticate the server
// through the pre-shared key bound to the TLS session, not through PKI, so a
// self-signed certificate is no weaker than a real one here. What a real
// certificate does buy is resistance to an active prober: someone who points
// a browser at the port sees a trust warning with a self-signed certificate
// and a normal page with a real one. Operators who own a domain should
// configure cert_mode "file" for that reason.
type certSource struct {
	// key is generated once and reused for every issued leaf. Certificate
	// generation then costs one signature rather than a fresh P-256 keygen,
	// which keeps a burst of new SNIs from being an easy way to load the CPU.
	key *ecdsa.PrivateKey

	fixed *tls.Certificate // set in "file" mode; used for every handshake

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// certCacheLimit caps how many generated certificates are retained. Reaching
// it means a client is cycling through SNIs, so the cache is simply dropped
// rather than grown without bound.
const certCacheLimit = 512

func newCertSource(mode, certFile, keyFile string) (*certSource, error) {
	cs := &certSource{cache: make(map[string]*tls.Certificate)}

	switch mode {
	case "file":
		if certFile == "" || keyFile == "" {
			return nil, errors.New("prx: cert_mode \"file\" needs cert_file and key_file")
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cs.fixed = &pair
		return cs, nil

	case "", "auto":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		cs.key = key
		return cs, nil

	default:
		return nil, errors.New("prx: cert_mode must be \"auto\" or \"file\"")
	}
}

// getCertificate is the tls.Config.GetCertificate callback.
func (cs *certSource) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cs.fixed != nil {
		return cs.fixed, nil
	}

	name := sanitizeSNI(hello.ServerName)

	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cert, ok := cs.cache[name]; ok {
		return cert, nil
	}
	if len(cs.cache) >= certCacheLimit {
		cs.cache = make(map[string]*tls.Certificate)
	}

	cert, err := cs.issue(name)
	if err != nil {
		return nil, err
	}
	cs.cache[name] = cert
	return cert, nil
}

func (cs *certSource) issue(name string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		// A ~90 day window matches what publicly trusted certificates look
		// like today; a 10 year self-signed certificate stands out.
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &cs.key.PublicKey, cs.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  cs.key,
		Leaf:        leaf,
	}, nil
}

// sanitizeSNI reduces a client-supplied server name to something safe to put
// in a certificate. The name reaches us straight off the network, so it is
// checked rather than trusted.
func sanitizeSNI(name string) string {
	const fallback = "localhost"

	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 253 {
		return fallback
	}
	if net.ParseIP(name) != nil {
		return name
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fallback
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '*':
			default:
				return fallback
			}
		}
	}
	return name
}
