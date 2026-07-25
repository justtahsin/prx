// Package config holds the on-disk settings for the server and the client.
//
// Every field has a working default. A server config file that contains only
// "{}" produces a usable server, and the client can run from a link alone
// with no file at all.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Server is the daemon's configuration.
type Server struct {
	// Listen is the address to accept connections on. Port 443 is strongly
	// preferred: it is where HTTPS is expected to be.
	Listen string `json:"listen"`

	// CertMode is "auto" or "file".
	//
	// In "auto" mode the server mints a self-signed certificate matching
	// whatever SNI each client asks for. That is what lets a user pick any
	// SNI they like with no setup and no domain name. The certificate is not
	// what authenticates the server -- the pre-shared key is -- so a
	// self-signed one costs nothing in security. It does mean an active
	// prober with a browser sees an untrusted certificate, which is why
	// operators who own a domain should use "file" with a real certificate.
	CertMode string `json:"cert_mode"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// Fallback is the address unauthenticated connections are handed to,
	// for example "127.0.0.1:8080" for a local web server. When empty a
	// built-in decoy page is served instead.
	Fallback string `json:"fallback"`

	// UsersFile is where credentials live. Relative paths resolve against
	// the config file's directory.
	UsersFile string `json:"users_file"`

	// PublicHost and PublicPort are what gets printed in connection links.
	// PublicHost defaults to the machine's public IP when left empty.
	PublicHost string `json:"public_host"`
	PublicPort int    `json:"public_port,omitempty"`

	// DefaultSNI is the SNI put into generated links.
	DefaultSNI string `json:"default_sni"`

	// AllowPrivate permits proxying to loopback and RFC1918 destinations.
	// Off by default: a public proxy that will connect to 127.0.0.1 or
	// 10.0.0.0/8 on request is a way into the operator's own network.
	AllowPrivate bool `json:"allow_private"`

	// BlockPorts are destination ports the server refuses. Port 25 is
	// blocked by default so the server cannot be used to relay spam, which
	// is the fastest way to get a host's IP address blacklisted.
	BlockPorts []int `json:"block_ports"`

	// LogLevel is "error", "info" or "debug".
	LogLevel string `json:"log_level"`
}

// DefaultServer returns a server config with every field populated.
func DefaultServer() Server {
	return Server{
		Listen:       ":443",
		CertMode:     "auto",
		Fallback:     "",
		UsersFile:    "users.json",
		DefaultSNI:   "www.cloudflare.com",
		AllowPrivate: false,
		BlockPorts:   []int{25},
		LogLevel:     "info",
	}
}

// Client is the local client's configuration.
type Client struct {
	// Link is a prx:// URL. When set it supplies the server address, key,
	// SNI and fingerprint, and the fields below are only overrides.
	Link string `json:"link,omitempty"`

	Server      string `json:"server,omitempty"`
	Key         string `json:"key,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// SOCKS and HTTP are the local listen addresses. Either may be empty to
	// disable that listener.
	SOCKS string `json:"socks"`
	HTTP  string `json:"http"`

	// PoolSize is how many authenticated connections to keep warm. Warm
	// connections are what remove the TLS and authentication round trips
	// from the critical path of a new request.
	PoolSize int `json:"pool_size"`

	LogLevel string `json:"log_level"`
}

// DefaultClient returns a client config with every field populated.
func DefaultClient() Client {
	return Client{
		SOCKS:    "127.0.0.1:1080",
		HTTP:     "127.0.0.1:1081",
		PoolSize: 4,
		LogLevel: "info",
	}
}

// LoadServer reads a server config, filling unset fields with defaults.
func LoadServer(path string) (Server, error) {
	cfg := DefaultServer()
	if err := load(path, &cfg); err != nil {
		return Server{}, err
	}
	if cfg.UsersFile != "" && !filepath.IsAbs(cfg.UsersFile) {
		cfg.UsersFile = filepath.Join(filepath.Dir(path), cfg.UsersFile)
	}
	return cfg, nil
}

// LoadClient reads a client config, filling unset fields with defaults.
func LoadClient(path string) (Client, error) {
	cfg := DefaultClient()
	if err := load(path, &cfg); err != nil {
		return Client{}, err
	}
	return cfg, nil
}

func load(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Unmarshalling into an already-populated struct leaves absent keys at
	// their default, which is how partial config files stay valid.
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("prx: parsing %s: %w", path, err)
	}
	return nil
}

// Save writes a config file with restrictive permissions.
func Save(path string, cfg any) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Dir returns the directory config files live in: /etc/prx for root,
// ~/.config/prx otherwise.
func Dir() string {
	if os.Geteuid() == 0 {
		return "/etc/prx"
	}
	if home, err := os.UserConfigDir(); err == nil {
		return filepath.Join(home, "prx")
	}
	return ".prx"
}
