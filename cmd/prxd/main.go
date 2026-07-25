// Command prxd is the prx server.
//
// Getting a working server takes two commands:
//
//	prxd init          # write config, create the first user, print a link
//	prxd install       # run it under systemd from now on
//
// Everything after that is user management: `prxd user add <name>` prints a
// link the new user can paste into a client, and takes effect immediately.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/justtahsin/prx/internal/cliargs"
	"github.com/justtahsin/prx/internal/config"
	"github.com/justtahsin/prx/internal/link"
	"github.com/justtahsin/prx/internal/logging"
	"github.com/justtahsin/prx/internal/server"
	"github.com/justtahsin/prx/internal/users"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd := os.Args[1]; cmd {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "user":
		err = cmdUser(os.Args[2:])
	case "link":
		err = cmdLink(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("prxd", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "prxd: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "prxd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `prxd - prx proxy server

Usage:
  prxd init [flags]        Create the config and the first user
  prxd run [-c config]     Run the server in the foreground
  prxd user <sub> [args]   Manage users: add, ls, rm, enable, disable, rotate
  prxd link <name>         Print a user's connection link and QR code
  prxd install [-c config] Install and start a systemd service
  prxd version

Run any command with -h for its flags.
`)
}

func defaultConfigPath() string {
	return filepath.Join(config.Dir(), "server.json")
}

// ---------------------------------------------------------------- init

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := fs.String("c", defaultConfigPath(), "config file to create")
	listen := fs.String("listen", ":443", "address to listen on")
	host := fs.String("host", "", "public host or IP for connection links (detected when empty)")
	sni := fs.String("sni", link.DefaultSNI, "SNI to put in generated links")
	user := fs.String("user", "default", "name of the first user")
	fallback := fs.String("fallback", "", "web server to hand unauthenticated visitors to (empty: built-in page)")
	certFile := fs.String("cert", "", "TLS certificate file (enables cert_mode \"file\")")
	keyFile := fs.String("key", "", "TLS private key file")
	force := fs.Bool("force", false, "overwrite an existing config")
	noQR := fs.Bool("no-qr", false, "do not print a QR code")
	if _, err := cliargs.Parse(fs, args); err != nil {
		return err
	}

	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists (use -force to overwrite)", *path)
	}

	cfg := config.DefaultServer()
	cfg.Listen = *listen
	cfg.DefaultSNI = *sni
	cfg.Fallback = *fallback
	cfg.PublicHost = *host
	if *certFile != "" || *keyFile != "" {
		cfg.CertMode = "file"
		cfg.CertFile = *certFile
		cfg.KeyFile = *keyFile
	}

	if err := config.Save(*path, cfg); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *path)

	loaded, err := config.LoadServer(*path)
	if err != nil {
		return err
	}
	store, err := users.Open(loaded.UsersFile)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\n", store.Path())

	u, err := store.Add(*user, "created by prxd init")
	if err != nil {
		return err
	}

	l, warning, err := linkFor(loaded, u)
	if err != nil {
		return err
	}
	printLink(u.Name, l, !*noQR)
	if warning != "" {
		fmt.Fprintf(os.Stderr, "\nnote: %s\n", warning)
	}

	fmt.Print(`
Next steps:
  prxd install     install and start the systemd service
  prxd run         or just run it here in the foreground
`)
	return nil
}

// ---------------------------------------------------------------- run

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("c", defaultConfigPath(), "config file")
	level := fs.String("log", "", "log level: error, warn, info, debug (overrides the config)")
	if _, err := cliargs.Parse(fs, args); err != nil {
		return err
	}

	cfg, err := config.LoadServer(*path)
	if err != nil {
		return err
	}
	if *level != "" {
		cfg.LogLevel = *level
	}
	log := logging.New(cfg.LogLevel)

	store, err := users.Open(cfg.UsersFile)
	if err != nil {
		return err
	}
	if total, _ := store.Count(); total == 0 {
		log.Warn("no users configured; every connection will be served the decoy page",
			"file", store.Path(), "hint", "prxd user add <name>")
	}

	srv, err := server.New(cfg, store, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		srv.Close()
	}()

	return srv.ListenAndServe()
}

// ---------------------------------------------------------------- user

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: prxd user <add|ls|rm|enable|disable|rotate> [args]")
	}

	fs := flag.NewFlagSet("user", flag.ExitOnError)
	path := fs.String("c", defaultConfigPath(), "config file")
	note := fs.String("note", "", "note to store with the user (add only)")
	noQR := fs.Bool("no-qr", false, "do not print a QR code")

	positional, err := cliargs.Parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return errors.New("usage: prxd user <add|ls|rm|enable|disable|rotate> [args]")
	}
	sub, rest := positional[0], positional[1:]

	cfg, err := config.LoadServer(*path)
	if err != nil {
		return err
	}
	store, err := users.Open(cfg.UsersFile)
	if err != nil {
		return err
	}

	switch sub {
	case "add":
		if len(rest) != 1 {
			return errors.New("usage: prxd user add <name>")
		}
		u, err := store.Add(rest[0], *note)
		if err != nil {
			return err
		}
		l, warning, err := linkFor(cfg, u)
		if err != nil {
			return err
		}
		printLink(u.Name, l, !*noQR)
		if warning != "" {
			fmt.Fprintf(os.Stderr, "\nnote: %s\n", warning)
		}
		return nil

	case "ls", "list":
		list := store.List()
		if len(list) == 0 {
			fmt.Println("no users yet - add one with: prxd user add <name>")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATE\tCREATED\tNOTE")
		for _, u := range list {
			state := "enabled"
			if !u.Enabled {
				state = "disabled"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Name, state,
				u.Created.Local().Format(time.DateOnly), u.Note)
		}
		return w.Flush()

	case "rm", "remove", "del":
		if len(rest) != 1 {
			return errors.New("usage: prxd user rm <name>")
		}
		if err := store.Remove(rest[0]); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", rest[0])
		return nil

	case "enable", "disable":
		if len(rest) != 1 {
			return fmt.Errorf("usage: prxd user %s <name>", sub)
		}
		if err := store.SetEnabled(rest[0], sub == "enable"); err != nil {
			return err
		}
		fmt.Printf("%sd %s\n", sub, rest[0])
		return nil

	case "rotate":
		if len(rest) != 1 {
			return errors.New("usage: prxd user rotate <name>")
		}
		u, err := store.Rotate(rest[0])
		if err != nil {
			return err
		}
		l, _, err := linkFor(cfg, u)
		if err != nil {
			return err
		}
		fmt.Printf("rotated %s - the previous link no longer works\n\n", u.Name)
		printLink(u.Name, l, !*noQR)
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// ---------------------------------------------------------------- link

func cmdLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	path := fs.String("c", defaultConfigPath(), "config file")
	sni := fs.String("sni", "", "override the SNI in the link")
	fp := fs.String("fp", "", "override the TLS fingerprint in the link")
	noQR := fs.Bool("no-qr", false, "do not print a QR code")

	positional, err := cliargs.Parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: prxd link <name>")
	}

	cfg, err := config.LoadServer(*path)
	if err != nil {
		return err
	}
	store, err := users.Open(cfg.UsersFile)
	if err != nil {
		return err
	}
	u, err := store.Get(positional[0])
	if err != nil {
		return err
	}

	l, warning, err := linkFor(cfg, u)
	if err != nil {
		return err
	}
	if *sni != "" {
		l.SNI = *sni
	}
	if *fp != "" {
		l.Fingerprint = *fp
	}

	printLink(u.Name, l, !*noQR)
	if warning != "" {
		fmt.Fprintf(os.Stderr, "\nnote: %s\n", warning)
	}
	return nil
}

// linkFor builds a connection link for a user, returning a warning when the
// address it had to guess is unlikely to be reachable.
func linkFor(cfg config.Server, u users.User) (link.Link, string, error) {
	host, warning := publicHost(cfg)
	port := cfg.PublicPort
	if port == 0 {
		p, err := listenPort(cfg.Listen)
		if err != nil {
			return link.Link{}, "", err
		}
		port = p
	}

	sni := cfg.DefaultSNI
	if sni == "" {
		sni = link.DefaultSNI
	}

	l := link.Link{
		Host:        host,
		Port:        port,
		Key:         u.Key,
		SNI:         sni,
		Fingerprint: link.DefaultFingerprint,
		Label:       u.Name,
	}
	return l, warning, l.Validate()
}

// publicHost decides what address to advertise in links.
func publicHost(cfg config.Server) (host, warning string) {
	if cfg.PublicHost != "" {
		return cfg.PublicHost, ""
	}

	ip := outboundIP()
	if ip == nil {
		return "SERVER-ADDRESS", "could not detect this machine's address; " +
			"set public_host in the config and reissue the link"
	}
	if ip.IsPrivate() {
		return ip.String(), fmt.Sprintf("%s is a private address, so this link only works "+
			"on the local network; set public_host in the config to your public address", ip)
	}
	return ip.String(), ""
}

// outboundIP reports the source address the kernel would use to reach the
// internet. Opening a UDP socket only asks the routing table -- no packet is
// sent and nothing external is contacted.
func outboundIP() net.IP {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return nil
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP
}

func listenPort(listen string) (int, error) {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("cannot read a port out of listen address %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("malformed port in listen address %q", listen)
	}
	return port, nil
}

func printLink(name string, l link.Link, qr bool) {
	url := l.String()
	fmt.Printf("user: %s\n\n%s\n", name, url)
	if qr {
		fmt.Println()
		qrterminal.GenerateHalfBlock(url, qrterminal.L, os.Stdout)
	}
}

// ---------------------------------------------------------------- install

const systemdUnitPath = "/etc/systemd/system/prxd.service"

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	path := fs.String("c", defaultConfigPath(), "config file the service should use")
	svcUser := fs.String("user", "prx", "system user to run the service as")
	start := fs.Bool("start", true, "enable and start the service immediately")
	if _, err := cliargs.Parse(fs, args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("install needs root: try sudo prxd install")
	}
	if _, err := os.Stat(*path); err != nil {
		return fmt.Errorf("%s does not exist - run prxd init first", *path)
	}

	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return err
	}

	if err := ensureSystemUser(*svcUser); err != nil {
		return err
	}

	// The service runs unprivileged, so it needs to own its state directory
	// in order to reload the users file.
	dir := filepath.Dir(*path)
	if err := chownTree(dir, *svcUser); err != nil {
		return err
	}

	unit := systemdUnit(binary, *path, *svcUser)
	if err := os.WriteFile(systemdUnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", systemdUnitPath)

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if !*start {
		fmt.Println("run: systemctl enable --now prxd")
		return nil
	}
	if err := run("systemctl", "enable", "--now", "prxd"); err != nil {
		return err
	}

	fmt.Print(`
prxd is running.

  systemctl status prxd     check it
  journalctl -u prxd -f     follow the log
  prxd user add <name>      add a user (takes effect immediately)
`)
	return nil
}

// systemdUnit builds a unit that runs the server unprivileged.
//
// The only privilege it keeps is CAP_NET_BIND_SERVICE, for port 443. The
// rest of the hardening is what systemd gives for free and there is no
// reason to decline: the server's job is to accept anonymous connections
// from the internet, so it should be able to do as little as possible if one
// of them ever goes wrong.
func systemdUnit(binary, configPath, svcUser string) string {
	return fmt.Sprintf(`[Unit]
Description=prx proxy server
Documentation=https://github.com/justtahsin/prx
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=3s
User=%s
Group=%s

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, binary, configPath, svcUser, svcUser, filepath.Dir(configPath))
}

func ensureSystemUser(name string) error {
	if _, err := lookupUser(name); err == nil {
		return nil
	}
	if err := run("useradd", "--system", "--no-create-home",
		"--shell", "/usr/sbin/nologin", name); err != nil {
		return fmt.Errorf("creating system user %q: %w", name, err)
	}
	fmt.Printf("created system user %s\n", name)
	return nil
}

func chownTree(root, svcUser string) error {
	u, err := lookupUser(svcUser)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, u.uid, u.gid)
	})
}

type sysUser struct{ uid, gid int }

func lookupUser(name string) (sysUser, error) {
	u, err := osUserLookup(name)
	if err != nil {
		return sysUser{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return sysUser{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return sysUser{}, err
	}
	return sysUser{uid: uid, gid: gid}, nil
}

func run(name string, args ...string) error {
	cmd := execCommand(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
