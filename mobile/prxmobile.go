// Package prxmobile is the prx client packaged for mobile platforms.
//
// It is bound with gomobile and consumed from Kotlin. Everything below the
// surface is the same client the desktop binary uses; what this package adds
// is the glue an Android VpnService needs:
//
//   - the tunnel device's file descriptor is turned into a network stack, so
//     that IP packets from the whole phone become connections we can carry;
//   - the socket that reaches the server is protected, so our own traffic is
//     not routed back into the tunnel we are providing.
//
// The API is deliberately small and made of scalars: gomobile only bridges a
// narrow set of types, and a narrow surface is easier to keep stable across
// both sides.
package prxmobile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/justtahsin/prx/internal/client"
	"github.com/justtahsin/prx/internal/link"
)

// DefaultMTU matches what the VpnService builder is configured with.
const DefaultMTU = 1500

// Logger receives log lines. Implemented on the Kotlin side.
type Logger interface {
	Log(line string)
}

// Protector exempts a socket from the device-wide tunnel. Implemented on the
// Kotlin side by calling VpnService.protect.
//
// Without it the connection to the server would be routed into the tunnel
// that connection is carrying, and nothing would work.
type Protector interface {
	Protect(fd int) bool
}

// Tunnel is a running client. Hold it, then call Stop.
type Tunnel struct {
	dialer *client.Dialer
	device device.Device
	stack  *stack.Stack
	log    *slog.Logger

	server string
	sni    string

	closeOnce sync.Once
}

// Start brings up the tunnel over an existing VpnService descriptor.
//
// tunFd must be a descriptor this package may own and close; on Android that
// means passing ParcelFileDescriptor.detachFd(). sni and fingerprint override
// what the link carries when they are non-empty.
func Start(rawLink, sni, fingerprint string, tunFd, mtu int, protector Protector, logger Logger) (*Tunnel, error) {
	log := newLogger(logger)

	l, err := link.Parse(strings.TrimSpace(rawLink))
	if err != nil {
		return nil, err
	}
	if sni = strings.TrimSpace(sni); sni != "" {
		l.SNI = sni
	}
	if fingerprint = strings.TrimSpace(fingerprint); fingerprint != "" {
		l.Fingerprint = fingerprint
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if tunFd <= 0 {
		return nil, errors.New("prx: no tunnel file descriptor")
	}

	dialer, err := client.NewDialer(l, warmPoolSize, log, client.WithControl(controlFor(protector)))
	if err != nil {
		return nil, err
	}

	// The descriptor is handed to the network stack, which owns it from here.
	dev, err := fdbased.Open(strconv.Itoa(tunFd), uint32(mtu), 0)
	if err != nil {
		dialer.Close()
		return nil, fmt.Errorf("prx: opening tunnel device: %w", err)
	}

	tunnel.T().SetProxy(&tunnelProxy{dialer: dialer, log: log})
	netStack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tunnel.T(),
	})
	if err != nil {
		dev.Close()
		dialer.Close()
		return nil, fmt.Errorf("prx: creating network stack: %w", err)
	}

	log.Info("tunnel up", "server", l.Addr(), "sni", l.SNI, "fingerprint", l.Fingerprint, "mtu", mtu)

	return &Tunnel{
		dialer: dialer,
		device: dev,
		stack:  netStack,
		log:    log,
		server: l.Addr(),
		sni:    l.SNI,
	}, nil
}

// warmPoolSize is smaller than the desktop default. Idle connections cost a
// phone radio wakeups, and a handset opens far fewer connections at once than
// a desktop browser does.
const warmPoolSize = 2

// Stop tears the tunnel down. It is safe to call more than once.
func (t *Tunnel) Stop() {
	t.closeOnce.Do(func() {
		t.log.Info("tunnel down")
		// Order matters: stop feeding the stack, then let it drain, then
		// drop the connections it was using.
		t.device.Close()
		t.stack.Close()
		t.stack.Wait()
		t.dialer.Close()
	})
}

// Server reports the address this tunnel connects to.
func (t *Tunnel) Server() string { return t.server }

// SNI reports the server name sent in the TLS handshake.
func (t *Tunnel) SNI() string { return t.sni }

// Check verifies that a link works and returns the address traffic exits
// from, for a "test connection" button. It does not need a tunnel device, so
// it can be called before connecting.
func Check(rawLink, sni, fingerprint string, timeoutSeconds int, protector Protector, logger Logger) (string, error) {
	l, err := link.Parse(strings.TrimSpace(rawLink))
	if err != nil {
		return "", err
	}
	if sni = strings.TrimSpace(sni); sni != "" {
		l.SNI = sni
	}
	if fingerprint = strings.TrimSpace(fingerprint); fingerprint != "" {
		l.Fingerprint = fingerprint
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 20
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	result, err := client.Probe(ctx, l, "", newLogger(logger), client.WithControl(controlFor(protector)))
	if err != nil {
		return "", err
	}
	return result.ExitIP, nil
}

// Describe renders what a link contains, so the app can show it without
// reimplementing the URL format.
func Describe(rawLink string) (string, error) {
	l, err := link.Parse(strings.TrimSpace(rawLink))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\n%s\n%s\n%s", l.Label, l.Addr(), l.SNI, l.Fingerprint), nil
}

// DefaultSNI is what a link without one falls back to, so the app can show it
// as a placeholder.
func DefaultSNI() string { return link.DefaultSNI }

// controlFor turns a Protector into a net.Dialer control function.
func controlFor(protector Protector) func(network, address string, c syscall.RawConn) error {
	if protector == nil {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var protectErr error
		err := c.Control(func(fd uintptr) {
			if !protector.Protect(int(fd)) {
				protectErr = errors.New("prx: VpnService.protect refused the socket")
			}
		})
		if err != nil {
			return err
		}
		return protectErr
	}
}
