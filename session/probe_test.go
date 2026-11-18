package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
)

// testRun is a meter that records what it was told, converges after a set
// number of polls, and can hold the sender in Converged until released.
type testRun struct {
	direction  ProbeDirection
	convergeAt int
	polls      atomic.Int32
	finished   atomic.Int64
	hold       chan struct{}
	holding    chan struct{}
	holdOnce   sync.Once
}

func (r *testRun) Converged() bool {
	if r.hold != nil {
		r.holdOnce.Do(func() { close(r.holding) })
		<-r.hold
	}
	polls := r.polls.Add(1)
	return r.convergeAt > 0 && int(polls) >= r.convergeAt
}

func (r *testRun) Finish(bytes int64) util.StringMap {
	r.finished.Store(bytes)
	return util.StringMap{"meter_bytes": strconv.FormatInt(bytes, 10), "dir": r.direction.String()}
}

// probeTestClient returns a client whose sessions reach a server offering
// probes under config, nil for a server without probes.
func probeTestClient(t *testing.T, config *ProbeConfig) *Client {
	t.Helper()
	var probeServer *ProbeServer
	if config != nil {
		probeServer = NewProbeServer(*config)
	}
	var lock sync.Mutex
	var servers []*Session
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		server := NewServerSession(serverConn, func(stream *Stream) {
			_, _ = io.Copy(stream, stream)
		}, testPadding(), logger.NOP())
		server.SetProbeServer(context.Background(), probeServer)
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
	return client
}

func TestProbeDownload(t *testing.T) {
	checkLeaks(t)
	var serverRun *testRun
	client := probeTestClient(t, &ProbeConfig{
		MaxBytes: 1 << 20,
		Meter: func(_ context.Context, _ net.Conn, direction ProbeDirection) ProbeRun {
			serverRun = &testRun{direction: direction}
			return serverRun
		},
	})
	localRun := &testRun{}
	result, err := client.Probe(testContext(t), ProbeRequest{
		Direction: ProbeDownload,
		Meter: func(_ context.Context, _ net.Conn, direction ProbeDirection) ProbeRun {
			localRun.direction = direction
			return localRun
		},
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.MaxBytes != 1<<20 || result.MaxDuration != DefaultProbeMaxDuration {
		t.Fatalf("accepted limits = %d bytes, %v", result.MaxBytes, result.MaxDuration)
	}
	if result.Reason != ProbeReasonBytes || result.Bytes != 1<<20 {
		t.Fatalf("reason %q after %d bytes", result.Reason, result.Bytes)
	}
	if result.Server["bytes"] != strconv.Itoa(1<<20) || result.Server["meter_bytes"] != strconv.Itoa(1<<20) || result.Server["dir"] != "down" {
		t.Fatalf("server result = %v", result.Server)
	}
	if serverRun.polls.Load() == 0 {
		t.Fatal("the sending server never asked its meter for convergence")
	}
	if result.Local["meter_bytes"] != strconv.Itoa(1<<20) || localRun.polls.Load() != 0 {
		t.Fatalf("local result = %v after %d polls; a receiver is never polled", result.Local, localRun.polls.Load())
	}
	if result.Duration <= 0 {
		t.Fatalf("duration = %v", result.Duration)
	}
	// The session goes back to the pool, measured as before.
	if idle := client.IdleSessions(); len(idle) != 1 || idle[0].Seq != result.Seq {
		t.Fatalf("idle sessions after the probe = %+v", idle)
	}
}

func TestProbeUpload(t *testing.T) {
	checkLeaks(t)
	var serverRun *testRun
	client := probeTestClient(t, &ProbeConfig{
		Meter: func(_ context.Context, _ net.Conn, direction ProbeDirection) ProbeRun {
			serverRun = &testRun{direction: direction}
			return serverRun
		},
	})
	result, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeUpload, MaxBytes: 300_000})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.MaxBytes != 300_000 {
		t.Fatalf("accepted %d bytes", result.MaxBytes)
	}
	if result.Bytes != 300_000 || result.Server["bytes"] != "300000" || result.Server["dir"] != "up" {
		t.Fatalf("sent %d, server result %v", result.Bytes, result.Server)
	}
	// The client stops the upload once it has sent what was allowed.
	if result.Reason != ProbeReasonStop {
		t.Fatalf("reason = %q", result.Reason)
	}
	if serverRun.polls.Load() != 0 {
		t.Fatal("a receiving server was polled for convergence")
	}
}

func TestProbeUploadConvergesOnClientMeter(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{})
	run := &testRun{convergeAt: 2}
	result, err := client.Probe(testContext(t), ProbeRequest{
		Direction: ProbeUpload,
		Meter:     func(context.Context, net.Conn, ProbeDirection) ProbeRun { return run },
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.Reason != ProbeReasonStop || result.Bytes != 2*probeChunk || result.Server["bytes"] != strconv.Itoa(2*probeChunk) {
		t.Fatalf("reason %q, sent %d, server %v", result.Reason, result.Bytes, result.Server)
	}
}

func TestProbeDownloadStopsWhenConverged(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{
		Meter: func(context.Context, net.Conn, ProbeDirection) ProbeRun { return &testRun{convergeAt: 3} },
	})
	result, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.Reason != ProbeReasonConverged || result.Bytes != 3*probeChunk {
		t.Fatalf("reason %q after %d bytes", result.Reason, result.Bytes)
	}
}

func TestProbeDownloadTimeLimit(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{
		// Slow the sender down so that time runs out first.
		Meter: func(context.Context, net.Conn, ProbeDirection) ProbeRun { return slowRun{} },
	})
	result, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload, MaxDuration: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.MaxDuration != 100*time.Millisecond || result.Reason != ProbeReasonTime {
		t.Fatalf("limit %v, reason %q", result.MaxDuration, result.Reason)
	}
}

type slowRun struct{}

func (slowRun) Converged() bool {
	time.Sleep(10 * time.Millisecond)
	return false
}

func (slowRun) Finish(int64) util.StringMap { return nil }

func TestProbeUnsupported(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, nil)
	if _, err := client.Probe(testContext(t), ProbeRequest{}); !errors.Is(err, ErrProbeUnsupported) {
		t.Fatalf("Probe = %v", err)
	}
	// The session is still good for streams.
	if idle := client.IdleSessions(); len(idle) != 1 {
		t.Fatalf("idle sessions = %d", len(idle))
	}
}

func TestProbeCooldownPerDirection(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{MaxBytes: probeChunk})
	first, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
	if err != nil {
		t.Fatalf("first probe: %v", err)
	}
	_, err = client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload, Seq: first.Seq})
	var refused *ProbeRefusedError
	if !errors.As(err, &refused) || refused.Reason != ProbeReasonCooldown || refused.RetryAfter <= 0 || refused.RetryAfter > DefaultProbeCooldown {
		t.Fatalf("second probe = %v", err)
	}
	if _, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeUpload, Seq: first.Seq}); err != nil {
		t.Fatalf("upload after a download: %v", err)
	}
}

func TestProbeConcurrencyLimit(t *testing.T) {
	checkLeaks(t)
	run := &testRun{hold: make(chan struct{}), holding: make(chan struct{})}
	var calls atomic.Int32
	client := probeTestClient(t, &ProbeConfig{
		MaxConcurrent: 1,
		MaxBytes:      probeChunk,
		Meter: func(context.Context, net.Conn, ProbeDirection) ProbeRun {
			if calls.Add(1) == 1 {
				return run
			}
			return nil
		},
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
		firstDone <- err
	}()
	<-run.holding
	// The first probe holds its session, so this one dials another.
	_, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
	var refused *ProbeRefusedError
	if !errors.As(err, &refused) || refused.Reason != ProbeReasonBusy {
		t.Fatalf("concurrent probe = %v", err)
	}
	close(run.hold)
	if err := <-firstDone; err != nil {
		t.Fatalf("first probe: %v", err)
	}
}

func TestProbeCancelKeepsSession(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{
		Cooldown: -1,
		Meter:    func(context.Context, net.Conn, ProbeDirection) ProbeRun { return slowRun{} },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err := client.Probe(ctx, ProbeRequest{Direction: ProbeDownload})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Probe = %v", err)
	}
	// The server confirmed the stop, so the session is reused.
	again, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload, Seq: result.Seq, MaxBytes: probeChunk})
	if err != nil {
		t.Fatalf("probe after cancel: %v", err)
	}
	if again.Bytes != probeChunk {
		t.Fatalf("second probe received %d bytes", again.Bytes)
	}
}

func TestProbeUnknownSession(t *testing.T) {
	checkLeaks(t)
	client := probeTestClient(t, &ProbeConfig{})
	if _, err := client.Probe(testContext(t), ProbeRequest{Seq: 42}); !errors.Is(err, ErrProbeSessionUnavailable) {
		t.Fatalf("Probe = %v", err)
	}
}

// A stream opened while a probe holds the session goes on another one.
func TestProbeHoldsSessionFromStreams(t *testing.T) {
	checkLeaks(t)
	run := &testRun{hold: make(chan struct{}), holding: make(chan struct{})}
	client := probeTestClient(t, &ProbeConfig{
		MaxBytes: probeChunk,
		Meter:    func(context.Context, net.Conn, ProbeDirection) ProbeRun { return run },
	})
	done := make(chan ProbeResult, 1)
	go func() {
		result, _ := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
		done <- result
	}()
	<-run.holding
	var placed uint64
	client.SetSelectHandler(func(_ context.Context, info SessionInfo) { placed = info.Seq })
	stream, err := client.CreateStream(testContext(t))
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	stream.Close()
	close(run.hold)
	if result := <-done; result.Seq == placed {
		t.Fatalf("stream placed on the probed session %d", placed)
	}
}

// A server only offers probes when configured to.
func TestProbeOfferedInSettings(t *testing.T) {
	checkLeaks(t)
	for _, offered := range []bool{false, true} {
		clientConn, serverConn := net.Pipe()
		server := NewServerSession(serverConn, nil, testPadding(), logger.NOP())
		if offered {
			server.SetProbeServer(context.Background(), NewProbeServer(ProbeConfig{}))
		}
		go server.Run()
		client := NewClientSession(clientConn, testPadding(), logger.NOP(), 0, "")
		client.Run()
		select {
		case <-client.dnsClient.ready:
		case <-time.After(3 * time.Second):
			t.Fatal("no server settings")
		}
		if client.ProbeSupported() != offered {
			t.Fatalf("offered=%v, client sees %v", offered, client.ProbeSupported())
		}
		client.Close()
		server.Close()
	}
}

type accountEntry struct {
	user      string
	direction ProbeDirection
	bytes     int64
}

// accountRecorder records what a server accounts.
type accountRecorder struct {
	access  sync.Mutex
	entries []accountEntry
}

func (r *accountRecorder) account(ctx context.Context, direction ProbeDirection, bytes int64) {
	user, _ := auth.UserFromContext[string](ctx)
	r.access.Lock()
	r.entries = append(r.entries, accountEntry{user, direction, bytes})
	r.access.Unlock()
}

func (r *accountRecorder) total(direction ProbeDirection) int64 {
	r.access.Lock()
	defer r.access.Unlock()
	var total int64
	for _, entry := range r.entries {
		if entry.direction == direction {
			total += entry.bytes
		}
	}
	return total
}

func TestProbeAccountsFiller(t *testing.T) {
	checkLeaks(t)
	recorder := &accountRecorder{}
	client := probeTestClient(t, &ProbeConfig{MaxBytes: 200_000, Account: recorder.account})
	down, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeDownload})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	up, err := client.Probe(testContext(t), ProbeRequest{Direction: ProbeUpload})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := recorder.total(ProbeDownload); got != down.Bytes || got != 200_000 {
		t.Fatalf("accounted %d of a %d byte download", got, down.Bytes)
	}
	if got := recorder.total(ProbeUpload); got != up.Bytes || got != 200_000 {
		t.Fatalf("accounted %d of a %d byte upload", got, up.Bytes)
	}
}

// rawProbeServer starts a server session offering probes under config, for a
// test that speaks the protocol itself on the returned connection, and
// returns a channel of the frames the server sends.
func rawProbeServer(t *testing.T, ctx context.Context, server *ProbeServer, read bool) (net.Conn, *Session, chan rawFrame) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	session := NewServerSession(serverConn, nil, testPadding(), logger.NOP())
	session.SetProbeServer(ctx, server)
	go session.Run()
	t.Cleanup(func() {
		clientConn.Close()
		session.Close()
	})
	frames := make(chan rawFrame, 64)
	settings := util.StringMap{"v": "2", "padding-md5": testPadding().Load().Md5}
	if err := writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes()); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if read {
		go func() {
			defer close(frames)
			for {
				frame, err := readRawFrame(clientConn)
				if err != nil {
					return
				}
				if frame.cmd == cmdProbeStatus {
					frames <- frame
				}
			}
		}()
	} else {
		// Take only the server's settings, then stop reading.
		if frame, err := readRawFrame(clientConn); err != nil || frame.cmd != cmdServerSettings {
			t.Fatalf("server settings: %v %v", frame, err)
		}
	}
	return clientConn, session, frames
}

func waitClosed(t *testing.T, session *Session, within time.Duration) {
	t.Helper()
	select {
	case <-session.die:
	case <-time.After(within):
		t.Fatal("session still open")
	}
}

// A client that starts a download and stops reading has its session closed
// once the probe overruns, which frees the probe's slot.
func TestProbeWatchdogFreesStalledDownload(t *testing.T) {
	checkLeaks(t)
	defer func(grace time.Duration) { probeWatchdogGrace = grace }(probeWatchdogGrace)
	probeWatchdogGrace = 100 * time.Millisecond
	server := NewProbeServer(ProbeConfig{MaxConcurrent: 1, MaxDuration: 100 * time.Millisecond})
	conn, session, _ := rawProbeServer(t, context.Background(), server, false)
	start := util.StringMap{"action": "start", "dir": "down"}
	if err := writeRawFrame(conn, cmdProbeRequest, 1, start.ToBytes()); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitClosed(t, session, 3*time.Second)
	waitFor(t, "the probe slot to be released", func() bool { return len(server.running) == 0 })
}

// Filler sent outside an upload is accounted, and a session that sends more
// of it than one upload allows is closed.
func TestProbeStrayFillerIsAccountedAndBounded(t *testing.T) {
	checkLeaks(t)
	recorder := &accountRecorder{}
	server := NewProbeServer(ProbeConfig{MaxBytes: 3 * probeChunk, Account: recorder.account})
	ctx := auth.ContextWithUser(context.Background(), "mallory")
	conn, session, _ := rawProbeServer(t, ctx, server, true)
	for i := 0; i < 4; i++ {
		if err := writeRawFrame(conn, cmdProbeData, 9, probeFiller); err != nil {
			break
		}
	}
	waitClosed(t, session, 3*time.Second)
	if got := recorder.total(ProbeUpload); got != 4*probeChunk {
		t.Fatalf("accounted %d stray bytes, want %d", got, 4*probeChunk)
	}
	if recorder.entries[0].user != "mallory" {
		t.Fatalf("accounted to %q", recorder.entries[0].user)
	}
}

// An upload beyond its grant closes the session, and what arrived is
// accounted.
func TestProbeUploadOverLimitClosesSession(t *testing.T) {
	checkLeaks(t)
	recorder := &accountRecorder{}
	server := NewProbeServer(ProbeConfig{Account: recorder.account})
	conn, session, frames := rawProbeServer(t, context.Background(), server, true)
	start := util.StringMap{"action": "start", "dir": "up", "bytes": "1"}
	if err := writeRawFrame(conn, cmdProbeRequest, 1, start.ToBytes()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if status := util.StringMapFromBytes((<-frames).data); status["status"] != "accepted" || status["bytes"] != "1" {
		t.Fatalf("status = %v", status)
	}
	_ = writeRawFrame(conn, cmdProbeData, 1, probeFiller)
	waitClosed(t, session, 3*time.Second)
	waitFor(t, "the upload to be accounted", func() bool { return recorder.total(ProbeUpload) == probeChunk })
}

// The cooldown follows the user across sessions.
func TestProbeCooldownFollowsUser(t *testing.T) {
	checkLeaks(t)
	server := NewProbeServer(ProbeConfig{MaxBytes: probeChunk})
	alice := auth.ContextWithUser(context.Background(), "alice")
	probeOn := func(ctx context.Context) util.StringMap {
		conn, _, frames := rawProbeServer(t, ctx, server, true)
		start := util.StringMap{"action": "start", "dir": "down"}
		if err := writeRawFrame(conn, cmdProbeRequest, 1, start.ToBytes()); err != nil {
			t.Fatalf("start: %v", err)
		}
		status := util.StringMapFromBytes((<-frames).data)
		if status["status"] == "accepted" {
			<-frames
		}
		return status
	}
	if status := probeOn(alice); status["status"] != "accepted" {
		t.Fatalf("first probe: %v", status)
	}
	if status := probeOn(alice); status["status"] != "refused" || status["reason"] != ProbeReasonCooldown {
		t.Fatalf("alice on a new session: %v", status)
	}
	if status := probeOn(auth.ContextWithUser(context.Background(), "bob")); status["status"] != "accepted" {
		t.Fatalf("bob: %v", status)
	}
}

// A server that never sends its settings, as version 1 servers do not, does
// not offer probes.
func TestProbeWithoutServerSettings(t *testing.T) {
	checkLeaks(t)
	defer func(timeout time.Duration) { probeSettingsTimeout = timeout }(probeSettingsTimeout)
	probeSettingsTimeout = 100 * time.Millisecond
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()
	client := NewClientSession(clientConn, testPadding(), logger.NOP(), 0, "")
	client.Run()
	defer client.Close()
	if _, err := client.probe(testContext(t), ProbeRequest{}); !errors.Is(err, ErrProbeUnsupported) {
		t.Fatalf("probe = %v", err)
	}
}
