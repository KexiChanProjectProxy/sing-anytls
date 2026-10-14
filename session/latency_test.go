package session

import (
	"context"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/logger"
)

// rawServer answers a client session frame by frame: settings and heartbeats
// after the given delays, SYN at once, and data by echoing it. It never stops
// reading, because net.Pipe is synchronous and the client's writes would
// otherwise block. Delayed answers are written from timers, under one lock.
func rawServer(t *testing.T, conn net.Conn, settingsDelay, heartbeatDelay time.Duration) {
	t.Helper()
	var writeAccess sync.Mutex
	write := func(cmd byte, sid uint32, data []byte) {
		writeAccess.Lock()
		defer writeAccess.Unlock()
		_ = writeRawFrame(conn, cmd, sid, data)
	}
	later := func(delay time.Duration, cmd byte, sid uint32, data []byte) {
		if delay <= 0 {
			go write(cmd, sid, data)
			return
		}
		time.AfterFunc(delay, func() { write(cmd, sid, data) })
	}
	go func() {
		for {
			frame, err := readRawFrame(conn)
			if err != nil {
				return
			}
			switch frame.cmd {
			case cmdSettings:
				later(settingsDelay, cmdServerSettings, 0, util.StringMap{"v": "2"}.ToBytes())
			case cmdHeartRequest:
				later(heartbeatDelay, cmdHeartResponse, frame.sid, nil)
			case cmdSYN:
				later(0, cmdSYNACK, frame.sid, nil)
			case cmdPSH:
				later(0, cmdPSH, frame.sid, frame.data)
			}
		}
	}()
}

func newLatencyClient(conn net.Conn, heartbeat time.Duration, clientMetadata string) *Client {
	return NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return conn, nil
	}, testPadding(), 0, 0, 0, 0, 0, 0, 0, 0, heartbeat, false, nil, clientMetadata)
}

func anySession(c *Client) *Session {
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	for _, session := range c.sessions {
		return session
	}
	return nil
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A session is measured as soon as it opens, before carrying any stream, which
// is what lets pre-created idle sessions be ranked.
func TestSessionMeasuredOnCreation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	rawServer(t, serverConn, 50*time.Millisecond, 0)
	client := newLatencyClient(clientConn, 0, "")
	defer client.Close()

	session, err := client.createSession(context.Background())
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	waitFor(t, "the settings sample", func() bool { return session.Latency().Samples == 1 })
	latency := session.Latency()
	if latency.Smoothed < 50*time.Millisecond || latency.Smoothed > 500*time.Millisecond {
		t.Fatalf("settings round trip = %v, want about 50ms", latency.Smoothed)
	}
}

// Heartbeats keep measuring a session while it sits idle in the pool.
func TestHeartbeatKeepsMeasuringIdleSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	rawServer(t, serverConn, 0, 10*time.Millisecond)
	client := newLatencyClient(clientConn, 20*time.Millisecond, "")
	defer client.Close()

	roundTrip(t, client)
	session := anySession(client)
	if session == nil {
		t.Fatal("no session")
	}
	waitFor(t, "heartbeat samples", func() bool { return session.Latency().Samples >= 4 })
	if last := session.Latency().Last; last < 10*time.Millisecond || last > 500*time.Millisecond {
		t.Fatalf("heartbeat round trip = %v, want about 10ms", last)
	}
}

// While a heartbeat is unanswered a second one must not restart the clock: the
// next response belongs to the first request.
func TestOutstandingHeartbeatKeepsFirstTimestamp(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	rawServer(t, serverConn, 0, 100*time.Millisecond)
	client := newLatencyClient(clientConn, 0, "")
	defer client.Close()

	session, err := client.createSession(context.Background())
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	waitFor(t, "the settings sample", func() bool { return session.Latency().Samples == 1 })
	if err = session.sendHeartbeat(); err != nil {
		t.Fatalf("sendHeartbeat: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err = session.sendHeartbeat(); err != nil {
		t.Fatalf("sendHeartbeat: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	latency := session.Latency()
	if latency.Samples != 2 {
		t.Fatalf("samples = %d, want the settings sample and one heartbeat sample", latency.Samples)
	}
	if latency.Last < 90*time.Millisecond {
		t.Fatalf("heartbeat round trip = %v, want it timed from the first request", latency.Last)
	}
}

func settingsOf(t *testing.T, clientMetadata string) util.StringMap {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := newLatencyClient(clientConn, 0, clientMetadata)
	defer client.Close()
	go func() { _, _ = client.createSession(context.Background()) }()
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		frame, err := readRawFrame(serverConn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if frame.cmd == cmdSettings {
			return util.StringMapFromBytes(frame.data)
		}
	}
}

func TestClientMetadataInSettings(t *testing.T) {
	if got := settingsOf(t, "custom/1.0")["client"]; got != "custom/1.0" {
		t.Fatalf("client = %q", got)
	}
	settings := settingsOf(t, "")
	if got, present := settings["client"]; !present || got != "" {
		t.Fatalf("client = %q (present %v), want present and empty", got, present)
	}
}

// idleTestSession builds a pooled session without a connection behind it.
// latency 0 means unmeasured.
func idleTestSession(seq uint64, latency time.Duration) *Session {
	s := &Session{seq: seq, die: make(chan struct{}), logger: logger.NOP(), streams: make(map[uint32]*Stream)}
	if latency > 0 {
		s.latencySmoothed.Store(int64(latency))
		s.latencyLast.Store(int64(latency))
		s.latencySamples.Store(1)
	}
	return s
}

func TestGetIdleSessionPrefersLowestLatency(t *testing.T) {
	client := newLatencyClient(nil, 0, "")
	defer client.Close()
	latencies := map[uint64]time.Duration{
		1: 30 * time.Millisecond,
		2: 10 * time.Millisecond,
		3: 0,
		4: 20 * time.Millisecond,
		5: 0,
		6: 5 * time.Millisecond, // closed, must be skipped
	}
	for seq, latency := range latencies {
		session := idleTestSession(seq, latency)
		if seq == 6 {
			close(session.die)
		}
		client.idleSession.Insert(math.MaxUint64-seq, session)
	}
	var order []uint64
	for {
		session := client.getIdleSession()
		if session == nil {
			break
		}
		order = append(order, session.seq)
	}
	want := []uint64{2, 4, 1, 5, 3}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// pooledSession is an idle session with a connection, so that cleanup can
// close it.
func pooledSession(t *testing.T, client *Client, seq uint64, latency time.Duration, createdAt time.Time) *Session {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	session := idleTestSession(seq, latency)
	session.conn = conn
	session.createdAt = createdAt
	session.idleSince = createdAt
	session.maxLifetime = client.maxConnectionLifetime
	client.idleSession.Insert(math.MaxUint64-seq, session)
	return session
}

func TestAgeCleanupClosesHighestLatencyFirst(t *testing.T) {
	client := NewClient(context.Background(), logger.NOP(), nil, testPadding(),
		time.Hour, time.Hour, time.Second, 0, 0, 2, 0, 0, 0, false, nil, "")
	defer client.Close()
	old := time.Now().Add(-2 * time.Second)
	unmeasured := pooledSession(t, client, 1, 0, old)
	fast := pooledSession(t, client, 2, 10*time.Millisecond, old)
	slow := pooledSession(t, client, 3, 50*time.Millisecond, old)
	medium := pooledSession(t, client, 4, 30*time.Millisecond, old)

	client.ageCleanup()
	waitFor(t, "two sessions to close", func() bool { return unmeasured.IsClosed() && slow.IsClosed() })
	if fast.IsClosed() || medium.IsClosed() {
		t.Fatal("age cleanup closed a lower-latency session")
	}
	if client.idleSession.Len() != 2 {
		t.Fatalf("idle sessions = %d, want 2", client.idleSession.Len())
	}
}

func TestIdleCleanupProtectsLowestLatency(t *testing.T) {
	client := NewClient(context.Background(), logger.NOP(), nil, testPadding(),
		time.Hour, time.Hour, 0, 0, 1, 0, 0, 0, 0, false, nil, "")
	defer client.Close()
	old := time.Now().Add(-time.Minute)
	slow := pooledSession(t, client, 1, 50*time.Millisecond, old)
	fast := pooledSession(t, client, 2, 10*time.Millisecond, old)
	unmeasured := pooledSession(t, client, 3, 0, old)

	client.idleCleanupExpTime(time.Now())
	if !slow.IsClosed() || !unmeasured.IsClosed() {
		t.Fatal("idle cleanup kept a session it should have closed")
	}
	if fast.IsClosed() {
		t.Fatal("idle cleanup closed the lowest-latency session")
	}
	if !fast.idleSince.After(old) {
		t.Fatal("the protected session's idle time was not reset")
	}
}
