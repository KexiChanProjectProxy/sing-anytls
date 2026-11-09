package anytls

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// testHandler echoes every stream and hands it to streams first.
type testHandler struct {
	streams chan net.Conn
}

func (h *testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.streams <- conn
	_, _ = io.Copy(conn, conn)
}

func newTestService(t *testing.T, drainTimeout time.Duration, users ...User) (*Service, *testHandler) {
	t.Helper()
	handler := &testHandler{streams: make(chan net.Conn, 4)}
	service, err := NewService(ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Users:         users,
		Handler:       handler,
		Logger:        logger.NOP(),
		DrainTimeout:  drainTimeout,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { service.Close() })
	return service, handler
}

// connect opens an authenticated session. Run returning means the server read
// the settings frame, so the session is registered by then.
func connect(t *testing.T, service *Service, password string) *session.Session {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- service.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil)
	}()
	hello := sha256.Sum256([]byte(password))
	if _, err := clientConn.Write(append(hello[:], 0, 0)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	client := session.NewClientSession(clientConn, &pad, logger.NOP(), 0, "")
	client.Run()
	t.Cleanup(func() { client.Close() })
	return client
}

// openStream opens a stream and waits until the handler has it.
func openStream(t *testing.T, client *session.Session, handler *testHandler) (net.Conn, net.Conn) {
	t.Helper()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	destination := M.ParseSocksaddrHostPort("127.0.0.1", 80)
	if err = M.SocksaddrSerializer.WriteAddrPort(stream, destination); err != nil {
		t.Fatalf("write destination: %v", err)
	}
	select {
	case serverStream := <-handler.streams:
		return stream, serverStream
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not get the stream")
		return nil, nil
	}
}

func waitClosed(t *testing.T, s *session.Session) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !s.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatal("session did not close")
		}
		time.Sleep(time.Millisecond)
	}
}

// staysOpen gives a close that should not happen the time to show up.
func staysOpen(t *testing.T, s *session.Session) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if s.IsClosed() {
		t.Fatal("session closed")
	}
}

func TestUpdateUsersClosesRemovedUser(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "pa"}, User{"b", "pb"})
	a, b := connect(t, service, "pa"), connect(t, service, "pb")

	service.UpdateUsers([]User{{"b", "pb"}})
	waitClosed(t, a)
	staysOpen(t, b)
}

func TestUpdateUsersClosesOnPasswordChange(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "old"})
	a := connect(t, service, "old")

	service.UpdateUsers([]User{{"a", "new"}})
	waitClosed(t, a)
	connect(t, service, "new")
}

func TestUpdateUsersClosesWhenPasswordChangesHands(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "shared"})
	a := connect(t, service, "shared")

	service.UpdateUsers([]User{{"b", "shared"}})
	waitClosed(t, a)
}

func TestUpdateUsersKeepsUnchangedUsers(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "pa"})
	a := connect(t, service, "pa")

	service.UpdateUsers([]User{{"a", "pa"}, {"b", "pb"}})
	staysOpen(t, a)
}

func TestDrainClosesIdleAndWaitsForActive(t *testing.T) {
	service, handler := newTestService(t, 0, User{"a", "pa"})
	idle, active := connect(t, service, "pa"), connect(t, service, "pa")
	stream, _ := openStream(t, active, handler)

	service.Drain()
	waitClosed(t, idle)
	staysOpen(t, active)

	stream.Close()
	waitClosed(t, active)
}

func TestDrainTimeoutClosesActive(t *testing.T) {
	service, handler := newTestService(t, 50*time.Millisecond, User{"a", "pa"})
	active := connect(t, service, "pa")
	openStream(t, active, handler)

	service.Drain()
	waitClosed(t, active)
}

func TestSessionAfterDrainIsClosed(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "pa"})
	service.Drain()

	waitClosed(t, connect(t, service, "pa"))
}

func TestCloseInterruptsActive(t *testing.T) {
	service, handler := newTestService(t, 0, User{"a", "pa"})
	active := connect(t, service, "pa")
	openStream(t, active, handler)

	service.Close()
	waitClosed(t, active)
}

func TestClosedSessionsAreForgotten(t *testing.T) {
	service, _ := newTestService(t, 0, User{"a", "pa"})
	a := connect(t, service, "pa")
	a.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		service.sessionLock.Lock()
		remaining := len(service.sessions)
		service.sessionLock.Unlock()
		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions still tracked", remaining)
		}
		time.Sleep(time.Millisecond)
	}
}
