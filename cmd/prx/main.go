// Command prx is the prx client. It opens a tunnel to a prx server and
// exposes it locally as a SOCKS5 and an HTTP proxy.
//
// The short version:
//
//	prx 'prx://KEY@server:443?sni=www.cloudflare.com#home'
//
// Everything the client needs is in that one link, including the SNI it
// should present, which can be changed with -sni or by editing the URL.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/justtahsin/prx/internal/cliargs"
	"github.com/justtahsin/prx/internal/client"
	"github.com/justtahsin/prx/internal/config"
	"github.com/justtahsin/prx/internal/link"
	"github.com/justtahsin/prx/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// `prx <link>` is the same as `prx run <link>`, because that is what
	// almost every invocation is.
	args := os.Args[1:]
	cmd := args[0]
	if strings.HasPrefix(cmd, link.Scheme+"://") {
		cmd, args = "run", append([]string{"run"}, args...)
	}

	var err error
	switch cmd {
	case "run":
		err = cmdRun(args[1:])
	case "test":
		err = cmdTest(args[1:])
	case "show":
		err = cmdShow(args[1:])
	case "version", "-v", "--version":
		fmt.Println("prx", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "prx: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "prx:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `prx - prx proxy client

Usage:
  prx <link>               Connect using a prx:// link
  prx run <link> [flags]   Same, with options
  prx run -c <file>        Connect using a saved config file
  prx test <link>          Check that the tunnel works and report the exit IP
  prx show <link>          Print what a link contains
  prx version

Fingerprints for -fp: %s

Run any command with -h for its flags.
`, strings.Join(client.Fingerprints, ", "))
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("c", "", "config file to read instead of a link")
	socks := fs.String("socks", "", "local SOCKS5 address (default 127.0.0.1:1080, \"off\" to disable)")
	httpAddr := fs.String("http", "", "local HTTP proxy address (default 127.0.0.1:1081, \"off\" to disable)")
	sni := fs.String("sni", "", "override the SNI from the link")
	fp := fs.String("fp", "", "override the TLS fingerprint from the link")
	pool := fs.Int("pool", -1, "how many connections to keep warm (default 4)")
	level := fs.String("log", "", "log level: error, warn, info, debug")

	positional, err := cliargs.Parse(fs, args)
	if err != nil {
		return err
	}

	cfg := config.DefaultClient()
	if *configPath != "" {
		loaded, err := config.LoadClient(*configPath)
		if err != nil {
			return err
		}
		cfg = loaded
	}

	raw := cfg.Link
	if len(positional) > 0 {
		raw = positional[0]
	}
	if raw == "" {
		return errors.New("need a prx:// link (or -c with a config file that has one)")
	}

	l, err := link.Parse(raw)
	if err != nil {
		return err
	}
	if *sni != "" {
		l.SNI = *sni
	}
	if *fp != "" {
		l.Fingerprint = *fp
	}

	if *socks != "" {
		cfg.SOCKS = *socks
	}
	if *httpAddr != "" {
		cfg.HTTP = *httpAddr
	}
	if *pool >= 0 {
		cfg.PoolSize = *pool
	}
	if *level != "" {
		cfg.LogLevel = *level
	}

	opts := client.Options{
		Link:     l,
		SOCKS:    listenAddr(cfg.SOCKS),
		HTTP:     listenAddr(cfg.HTTP),
		PoolSize: cfg.PoolSize,
	}

	log := logging.New(cfg.LogLevel)
	c, err := client.New(opts, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.Run(ctx)
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	sni := fs.String("sni", "", "override the SNI from the link")
	fp := fs.String("fp", "", "override the TLS fingerprint from the link")
	url := fs.String("url", client.DefaultProbeURL, "URL to fetch through the tunnel")
	timeout := fs.Duration("timeout", 30*time.Second, "give up after this long")
	level := fs.String("log", "error", "log level: error, warn, info, debug")

	positional, err := cliargs.Parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: prx test <link>")
	}
	l, err := link.Parse(positional[0])
	if err != nil {
		return err
	}
	if *sni != "" {
		l.SNI = *sni
	}
	if *fp != "" {
		l.Fingerprint = *fp
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Printf("server:      %s\n", l.Addr())
	fmt.Printf("sni:         %s\n", l.SNI)
	fmt.Printf("fingerprint: %s\n\n", l.Fingerprint)

	result, err := client.Probe(ctx, l, *url, logging.New(*level))
	if err != nil {
		return err
	}

	fmt.Printf("handshake:   %v (TCP + TLS + authentication)\n", result.Handshake.Round(time.Millisecond))
	fmt.Printf("request:     %v (%s)\n", result.Request.Round(time.Millisecond), *url)
	fmt.Printf("status:      %s\n", result.Status)
	if result.ExitIP != "" {
		fmt.Printf("exit ip:     %s\n", result.ExitIP)
	}
	fmt.Println("\nok - the tunnel works.")
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	positional, err := cliargs.Parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: prx show <link>")
	}

	l, err := link.Parse(positional[0])
	if err != nil {
		return err
	}
	fmt.Printf("label:       %s\n", l.Label)
	fmt.Printf("server:      %s\n", l.Addr())
	fmt.Printf("sni:         %s\n", l.SNI)
	fmt.Printf("fingerprint: %s\n", l.Fingerprint)
	fmt.Printf("key:         %s… (%d chars)\n", l.Key[:8], len(l.Key))
	return nil
}

// listenAddr maps the "off" sentinel to an empty address, which disables the
// listener.
func listenAddr(addr string) string {
	if strings.EqualFold(strings.TrimSpace(addr), "off") {
		return ""
	}
	return addr
}
