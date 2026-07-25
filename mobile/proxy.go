package prxmobile

import (
	"context"
	"log/slog"
	"net"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/justtahsin/prx/internal/client"
	"github.com/justtahsin/prx/internal/protocol"
)

// udpOpenTimeout bounds how long opening a datagram association may take.
const udpOpenTimeout = 15 * time.Second

// tunnelProxy connects the phone's network stack to the prx tunnel.
//
// The stack hands us a destination that is already an IP address and port:
// the phone resolved the name, or rather it sent a DNS query that arrived
// here as UDP to the resolver the VpnService advertised, and that query went
// through the tunnel too. So names are resolved at the far end, which is what
// keeps a local resolver from seeing where the user is going.
type tunnelProxy struct {
	dialer *client.Dialer
	log    *slog.Logger
}

func (p *tunnelProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	dest, err := protocol.ParseAddr(m.DestinationAddress())
	if err != nil {
		return nil, err
	}
	return p.dialer.Open(ctx, dest)
}

func (p *tunnelProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	// Each association gets its own stream; the destination travels with
	// every datagram rather than being fixed here.
	ctx, cancel := context.WithTimeout(context.Background(), udpOpenTimeout)
	defer cancel()
	return p.dialer.OpenPacketConn(ctx)
}
