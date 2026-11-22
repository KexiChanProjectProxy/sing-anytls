package anytls

import (
	"errors"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// headroomConn stands in for a session stream: it asks for front headroom
// and records handshake reports.
type headroomConn struct {
	net.Conn
	failure error
	success bool
}

func (c *headroomConn) FrontHeadroom() int { return 7 }

func (c *headroomConn) HandshakeFailure(err error) error {
	c.failure = err
	return nil
}

func (c *headroomConn) HandshakeSuccess() error {
	c.success = true
	return nil
}

func TestWrapUoTStreamHidesHeadroom(t *testing.T) {
	for _, destination := range []M.Socksaddr{
		uot.RequestDestination(uot.Version),
		uot.RequestDestination(uot.LegacyVersion),
	} {
		stream := &headroomConn{}
		conn := wrapUoTStream(stream, destination)
		if conn == net.Conn(stream) {
			t.Fatalf("%s: stream not wrapped", destination)
		}
		packetConn := uot.NewConn(conn, uot.Request{})
		if got := N.CalculateFrontHeadroom(packetConn); got != 0 {
			t.Fatalf("%s: UoT conn front headroom %d, want 0", destination, got)
		}
	}
}

func TestWrapUoTStreamKeepsTCPStreams(t *testing.T) {
	stream := &headroomConn{}
	conn := wrapUoTStream(stream, M.ParseSocksaddrHostPort("example.com", 443))
	if conn != net.Conn(stream) {
		t.Fatal("TCP stream was wrapped")
	}
	if got := N.CalculateFrontHeadroom(conn); got != 7 {
		t.Fatalf("TCP stream front headroom %d, want 7", got)
	}
}

func TestUoTStreamForwardsHandshake(t *testing.T) {
	stream := &headroomConn{}
	conn := wrapUoTStream(stream, uot.RequestDestination(uot.Version))
	want := errors.New("refused")
	// ReportHandshakeFailure returns the reported error itself.
	if err := N.ReportHandshakeFailure(conn, want); !errors.Is(err, want) {
		t.Fatalf("ReportHandshakeFailure = %v, want %v", err, want)
	}
	if !errors.Is(stream.failure, want) {
		t.Fatalf("stream saw failure %v, want %v", stream.failure, want)
	}
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		t.Fatalf("ReportHandshakeSuccess: %v", err)
	}
	if !stream.success {
		t.Fatal("stream did not see the handshake success")
	}
}
