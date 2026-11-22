package anytls

import (
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// isUoTDestination reports whether destination is the address sing's
// UDP-over-TCP uses to mark a stream that carries datagrams.
func isUoTDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}

// uotStream carries a UDP-over-TCP stream. It hides the stream's front
// headroom and buffer writer: uot.Conn builds each packet itself and writes it
// with Write, so the headroom would only make sing's packet copy reserve
// seven unused bytes, shrinking the largest datagram that fits a buffer and
// copying packets that lack the room. Without Upstream, sing's headroom
// lookup stops here.
type uotStream struct {
	net.Conn
}

var (
	_ N.HandshakeFailure = (*uotStream)(nil)
	_ N.HandshakeSuccess = (*uotStream)(nil)
)

// HandshakeFailure and HandshakeSuccess pass on what the router reports, so
// that the client still learns why its UDP request failed.
func (c *uotStream) HandshakeFailure(err error) error {
	if conn, ok := c.Conn.(N.HandshakeFailure); ok {
		return conn.HandshakeFailure(err)
	}
	return nil
}

func (c *uotStream) HandshakeSuccess() error {
	if conn, ok := c.Conn.(N.HandshakeSuccess); ok {
		return conn.HandshakeSuccess()
	}
	return nil
}

func wrapUoTStream(conn net.Conn, destination M.Socksaddr) net.Conn {
	if isUoTDestination(destination) {
		return &uotStream{Conn: conn}
	}
	return conn
}
