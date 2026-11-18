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
	// The server ends the upload itself when the limit is reached, or on the
	// client's stop; either is correct.
	if result.Reason != ProbeReasonBytes && result.Reason != ProbeReasonStop {
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
