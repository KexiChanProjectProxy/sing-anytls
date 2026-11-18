package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// refusingTestClient returns a client whose servers refuse a stream with an
// error SYNACK while refuse reports true and echo it otherwise, and the number
// of sessions it has dialed.
func refusingTestClient(t *testing.T, refuse *atomic.Bool) (*Client, func() int) {
	t.Helper()
	var lock sync.Mutex
	var servers []*Session
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		server := NewServerSession(serverConn, func(stream *Stream) {
			if refuse.Load() {
				_ = stream.HandshakeFailure(errors.New("dial failed"))
				stream.Close()
				return
			}
			_ = stream.HandshakeSuccess()
			_, _ = io.Copy(stream, stream)
		}, testPadding(), logger.NOP())
		go server.Run()
		lock.Lock()
		servers = append(servers, server)
		lock.Unlock()
		return clientConn, nil
	}, testPadding(), 0, 0, 0, 0, 0, 0, 0, 0, 0, false, nil, "")
	t.Cleanup(func() {
		client.Close()
		lock.Lock()
		defer lock.Unlock()
		for _, server := range servers {
			server.Close()
		}
	})
	return client, func() int {
		lock.Lock()
		defer lock.Unlock()
		return len(servers)
	}
}

// openStream opens a stream, sends a byte and reads one back. It returns the
// error the stream ends with, nil when the byte came back.
func openStream(t *testing.T, client *Client) error {
	t.Helper()
	stream, err := client.CreateStream(testContext(t))
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte{1}); err != nil {
		return err
	}
	_, err = io.ReadFull(stream, make([]byte, 1))
	return err
}

// waitIdle waits until the session of the last stream is back in the pool or
// gone, so that the next stream sees the pool the last one left.
func waitIdle(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		client.sessionsLock.Lock()
		total := len(client.sessions)
		client.sessionsLock.Unlock()
		client.idleSessionLock.Lock()
		idle := client.idleSession.Len()
		client.idleSessionLock.Unlock()
		if idle == total {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d sessions idle", idle, total)
		}
		time.Sleep(time.Millisecond)
	}
}

func requireRefused(t *testing.T, client *Client) {
	t.Helper()
	err := openStream(t, client)
	if err == nil || !strings.Contains(err.Error(), "remote: dial failed") {
		t.Fatalf("stream error = %v, want the server's refusal", err)
	}
	waitIdle(t, client)
}

// A session whose streams the server keeps refusing is closed after
// maxHandshakeFailures of them, and the next stream gets a new session.
func TestSessionClosedAfterRepeatedHandshakeFailures(t *testing.T) {
	checkLeaks(t)
	var refuse atomic.Bool
	refuse.Store(true)
	client, dialed := refusingTestClient(t, &refuse)
	for i := 0; i < maxHandshakeFailures; i++ {
		requireRefused(t, client)
		if dialed() != 1 {
			t.Fatalf("after %d refusals: %d sessions dialed, want 1", i+1, dialed())
		}
	}
	refuse.Store(false)
	if err := openStream(t, client); err != nil {
		t.Fatalf("stream on a new session: %v", err)
	}
	if dialed() != 2 {
		t.Fatalf("%d sessions dialed, want 2", dialed())
	}
}

// An accepted stream resets the count, so refusals separated by accepted
// streams keep the session.
func TestHandshakeSuccessResetsFailures(t *testing.T) {
	checkLeaks(t)
	var refuse atomic.Bool
	client, dialed := refusingTestClient(t, &refuse)
	for round := 0; round < 3; round++ {
		refuse.Store(true)
		for i := 0; i < maxHandshakeFailures-1; i++ {
			requireRefused(t, client)
		}
		refuse.Store(false)
		if err := openStream(t, client); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		waitIdle(t, client)
	}
	if dialed() != 1 {
		t.Fatalf("%d sessions dialed, want 1", dialed())
	}
}
