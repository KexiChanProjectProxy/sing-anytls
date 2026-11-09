package session

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func waitClosed(t *testing.T, s *Session) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !s.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatal("session did not close")
		}
		time.Sleep(time.Millisecond)
	}
}

// drainPair connects a client session to a server session whose streams are
// handed to the returned channel, then echoed until they end.
func drainPair(t *testing.T) (*Session, *Session, chan *Stream) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	pad := testPadding()
	streams := make(chan *Stream, 4)
	server := NewServerSession(serverConn, func(stream *Stream) {
		streams <- stream
		_, _ = io.Copy(stream, stream)
	}, pad, logger.NOP())
	go server.Run()
	client := NewClientSession(clientConn, pad, logger.NOP(), 0, "")
	client.Run()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server, streams
}

func openEchoed(t *testing.T, client *Session) *Stream {
	t.Helper()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	echo(t, stream)
	return stream
}

func echo(t *testing.T, stream *Stream) {
	t.Helper()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply := make([]byte, 4)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("Read: %v", err)
	}
}

func TestDrainClosesIdleSession(t *testing.T) {
	client, server, _ := drainPair(t)
	server.Drain()
	waitClosed(t, server)
	waitClosed(t, client)
}

func TestDrainWaitsForPeerToEndStream(t *testing.T) {
	client, server, _ := drainPair(t)
	stream := openEchoed(t, client)

	server.Drain()
	time.Sleep(50 * time.Millisecond)
	if server.IsClosed() {
		t.Fatal("session closed with a stream still open")
	}
	echo(t, stream)

	stream.Close()
	waitClosed(t, server)
	waitClosed(t, client)
}

func TestDrainWaitsForServerToEndStream(t *testing.T) {
	client, server, streams := drainPair(t)
	openEchoed(t, client)
	serverStream := <-streams

	server.Drain()
	if server.IsClosed() {
		t.Fatal("session closed with a stream still open")
	}

	serverStream.Close()
	waitClosed(t, server)
	waitClosed(t, client)
}

func TestDrainWaitsForEveryStream(t *testing.T) {
	client, server, _ := drainPair(t)
	first := openEchoed(t, client)
	second := openEchoed(t, client)

	server.Drain()
	first.Close()
	echo(t, second)
	if server.IsClosed() {
		t.Fatal("session closed with a stream still open")
	}

	second.Close()
	waitClosed(t, server)
}

func TestNewStreamWhileDrainingClosesSession(t *testing.T) {
	client, server, _ := drainPair(t)
	active := openEchoed(t, client)

	server.Drain()
	// The server closes as soon as it reads the SYN, so writing it may fail.
	_, _ = client.OpenStream()
	waitClosed(t, server)
	waitClosed(t, client)

	_ = active.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := active.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream outlived its session")
	}
}

func TestCloseHookRunsOnce(t *testing.T) {
	_, serverConn := net.Pipe()
	server := NewServerSession(serverConn, nil, testPadding(), logger.NOP())
	calls := 0
	server.SetCloseHook(func() { calls++ })
	server.Close()
	server.Close()
	if calls != 1 {
		t.Fatalf("close hook ran %d times", calls)
	}
}
