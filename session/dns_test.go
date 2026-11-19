package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/logger"

	"go.uber.org/goleak"
)

// checkLeaks fails the test if it leaves goroutines behind once it and its
// cleanups have finished. It must be the test's first call, so that its
// cleanup runs last.
func checkLeaks(t *testing.T) {
	t.Helper()
	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() {
		goleak.VerifyNone(t, ignore)
	})
}

// dnsServerSession starts a server session that echoes streams and answers DNS
// with handler, nil for a server that does not offer DNS.
func dnsServerSession(conn net.Conn, handler DNSHandler) *Session {
	server := NewServerSession(conn, func(stream *Stream) {
		_, _ = io.Copy(stream, stream)
	}, testPadding(), logger.NOP())
	server.SetDNSHandler(context.Background(), handler)
	go server.Run()
	return server
}

// dnsTestClient returns a client whose every dial reaches a new server session
// built by newServer, and the server sessions dialed so far.
func dnsTestClient(t *testing.T, handler DNSHandler) (*Client, func() []*Session) {
	t.Helper()
	var lock sync.Mutex
	var servers []*Session
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		server := dnsServerSession(serverConn, handler)
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
	return client, func() []*Session {
		lock.Lock()
		defer lock.Unlock()
		return append([]*Session(nil), servers...)
	}
}

func echoDNS(_ context.Context, request []byte) ([]byte, error) {
	return append([]byte("ok:"), request...), nil
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDNSRoundTrip(t *testing.T) {
	checkLeaks(t)
	client, _ := dnsTestClient(t, echoDNS)
	response, err := client.ExchangeDNS(testContext(t), []byte("query"))
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if string(response) != "ok:query" {
		t.Fatalf("response = %q", response)
	}
}

// Concurrent queries on one session must each get their own answer back.
func TestDNSConcurrentQueriesMatchAnswers(t *testing.T) {
	checkLeaks(t)
	client, servers := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		// Answer out of order.
		time.Sleep(time.Duration(request[0]%7) * time.Millisecond)
		return append([]byte("ok:"), request...), nil
	})
	// Open the session first so that every query shares it.
	if _, err := client.ExchangeDNS(testContext(t), []byte{0}); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := []byte(fmt.Sprintf("%c-%d", byte(i), i))
			response, err := client.ExchangeDNS(testContext(t), request)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(response, append([]byte("ok:"), request...)) {
				errs <- fmt.Errorf("query %d got %q", i, response)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := len(servers()); n != 1 {
		t.Fatalf("queries used %d sessions, want 1", n)
	}
}

// serverSettingsOf returns the settings a server answers a v2 client with.
func serverSettingsOf(t *testing.T, handler DNSHandler) util.StringMap {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	server := dnsServerSession(serverConn, handler)
	defer server.Close()
	settings := util.StringMap{"v": "2", "padding-md5": testPadding().Load().Md5}
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes()); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	for {
		frame, err := readRawFrame(clientConn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if frame.cmd == cmdServerSettings {
			return util.StringMapFromBytes(frame.data)
		}
	}
}

func TestServerOffersDNSOnlyWithHandler(t *testing.T) {
	checkLeaks(t)
	if settings := serverSettingsOf(t, echoDNS); settings["dns"] != "1" {
		t.Fatalf("server with a handler sent %v", settings)
	}
	settings := serverSettingsOf(t, nil)
	if _, present := settings["dns"]; present || len(settings) != 1 || settings["v"] != "2" {
		t.Fatalf("server without a handler sent %v, want only v=2", settings)
	}
}

// A client must not send a DNS frame to a server that did not offer DNS,
// since an upstream server would misparse its payload.
func TestDNSNotSentToServerWithoutOffer(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := newTestClient(clientConn, testPadding())
	defer client.Close()

	frames := make(chan byte, 16)
	go func() {
		for {
			frame, err := readRawFrame(serverConn)
			if err != nil {
				close(frames)
				return
			}
			frames <- frame.cmd
			if frame.cmd == cmdSettings {
				// Answer like an upstream v2 server.
				_ = writeRawFrame(serverConn, cmdServerSettings, 0, util.StringMap{"v": "2"}.ToBytes())
			}
		}
	}()

	_, err := client.ExchangeDNS(testContext(t), []byte("query"))
	if !errors.Is(err, ErrDNSUnsupported) {
		t.Fatalf("err = %v, want ErrDNSUnsupported", err)
	}
	_ = serverConn.Close()
	for cmd := range frames {
		if cmd == cmdDNSRequest {
			t.Fatal("client sent a DNS request to a server that did not offer DNS")
		}
	}
}

func TestDNSHandlerFailure(t *testing.T) {
	checkLeaks(t)
	for name, handler := range map[string]DNSHandler{
		"error": func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("boom")
		},
		"empty": func(context.Context, []byte) ([]byte, error) {
			return nil, nil
		},
		"oversize": func(context.Context, []byte) ([]byte, error) {
			return make([]byte, maxFrameDataLen+1), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := dnsTestClient(t, handler)
			_, err := client.ExchangeDNS(testContext(t), []byte("query"))
			if !errors.Is(err, ErrDNSServerFailed) {
				t.Fatalf("err = %v, want ErrDNSServerFailed", err)
			}
			// The session survives a failed query.
			if _, err = client.ExchangeDNS(testContext(t), []byte("again")); !errors.Is(err, ErrDNSServerFailed) {
				t.Fatalf("second query: %v", err)
			}
		})
	}
}

func TestDNSMaximumSizes(t *testing.T) {
	checkLeaks(t)
	client, _ := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		return bytes.Repeat([]byte{'a'}, maxFrameDataLen), nil
	})
	response, err := client.ExchangeDNS(testContext(t), bytes.Repeat([]byte{'q'}, maxFrameDataLen))
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if len(response) != maxFrameDataLen {
		t.Fatalf("response length = %d", len(response))
	}
}

func TestDNSRequestTooLargeIsNotSent(t *testing.T) {
	checkLeaks(t)
	var calls atomic.Int32
	client, servers := dnsTestClient(t, func(context.Context, []byte) ([]byte, error) {
		calls.Add(1)
		return []byte("x"), nil
	})
	_, err := client.ExchangeDNS(testContext(t), make([]byte, maxFrameDataLen+1))
	if !errors.Is(err, ErrDNSMessageTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 0 || len(servers()) != 0 {
		t.Fatal("an oversize request reached the server")
	}
}

func TestDNSCancelledQueryIsForgotten(t *testing.T) {
	checkLeaks(t)
	release := make(chan struct{})
	client, _ := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		if string(request) == "slow" {
			<-release
		}
		return request, nil
	})
	if _, err := client.ExchangeDNS(testContext(t), []byte("warm")); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.ExchangeDNS(ctx, []byte("slow"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	session := anySession(client)
	session.dnsClient.pendingLock.Lock()
	pending := len(session.dnsClient.pending)
	session.dnsClient.pendingLock.Unlock()
	if pending != 0 {
		t.Fatalf("%d requests still pending after the caller gave up", pending)
	}
	// The late answer is dropped and the session keeps working.
	close(release)
	if response, err := client.ExchangeDNS(testContext(t), []byte("next")); err != nil || string(response) != "next" {
		t.Fatalf("after late answer: %q, %v", response, err)
	}
}

// A session that closes mid-query fails the query at once, and the client
// tries again on a new session.
func TestDNSSessionClosedMidQueryRetries(t *testing.T) {
	checkLeaks(t)
	var first atomic.Bool
	first.Store(true)
	block := make(chan struct{})
	defer close(block)
	client, servers := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		if first.Swap(false) {
			<-block
		}
		return request, nil
	})
	go func() {
		// Wait for the first server session, then kill it mid-query.
		for len(servers()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		servers()[0].Close()
	}()
	start := time.Now()
	response, err := client.ExchangeDNS(testContext(t), []byte("query"))
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if string(response) != "query" {
		t.Fatalf("response = %q", response)
	}
	if n := len(servers()); n != 2 {
		t.Fatalf("used %d sessions, want a retry on a second one", n)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v; the closed session did not fail the query promptly", elapsed)
	}
}

func TestDNSPendingFailedOnClose(t *testing.T) {
	checkLeaks(t)
	block := make(chan struct{})
	defer close(block)
	client, _ := dnsTestClient(t, func(context.Context, []byte) ([]byte, error) {
		<-block
		return nil, nil
	})
	if _, err := client.dnsSessionForTest(t); err != nil {
		t.Fatal(err)
	}
	session := anySession(client)
	done := make(chan error, 1)
	go func() {
		_, err := session.exchangeDNS(context.Background(), []byte("query"))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	session.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("err = %v, want ErrClosedPipe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query still waiting after the session closed")
	}
}

func (c *Client) dnsSessionForTest(t *testing.T) (*Session, error) {
	t.Helper()
	session, err := c.dnsSession(testContext(t))
	return session, err
}

// A server answers past maxDNSInFlight at once rather than queueing, so that
// a client cannot pile up handlers.
func TestDNSInFlightLimit(t *testing.T) {
	checkLeaks(t)
	release := make(chan struct{})
	var running atomic.Int32
	client, _ := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		running.Add(1)
		<-release
		return request, nil
	})
	if _, err := client.dnsSessionForTest(t); err != nil {
		t.Fatal(err)
	}
	session := anySession(client)
	results := make(chan error, maxDNSInFlight)
	for i := 0; i < maxDNSInFlight; i++ {
		go func() {
			_, err := session.exchangeDNS(testContext(t), []byte("held"))
			results <- err
		}()
	}
	waitFor(t, "handlers to fill up", func() bool { return running.Load() == maxDNSInFlight })
	_, err := session.exchangeDNS(testContext(t), []byte("extra"))
	if !errors.Is(err, ErrDNSServerFailed) {
		t.Fatalf("query over the limit: %v, want ErrDNSServerFailed", err)
	}
	close(release)
	for i := 0; i < maxDNSInFlight; i++ {
		if err := <-results; err != nil {
			t.Fatalf("held query: %v", err)
		}
	}
}

// Stray DNS frames in the wrong direction are skipped with their payload.
func TestDNSFramesInWrongDirectionIgnored(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := newTestClient(clientConn, testPadding())
	defer client.Close()

	go func() {
		_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
		for {
			frame, err := readRawFrame(serverConn)
			if err != nil {
				return
			}
			if frame.cmd == cmdSYN {
				_ = writeRawFrame(serverConn, cmdDNSRequest, 1, []byte("\x02\x00\x00\x00\x01\x00\x05junk!"))
				_ = writeRawFrame(serverConn, cmdDNSResponse, 7, []byte("unsolicited"))
				_ = writeRawFrame(serverConn, cmdPSH, frame.sid, []byte("ok"))
				_, _ = io.Copy(io.Discard, serverConn)
				return
			}
		}
	}()
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	_, _ = stream.Write([]byte("x"))
	reply := make([]byte, 2)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(stream, reply); err != nil || string(reply) != "ok" {
		t.Fatalf("stream got %q, %v", reply, err)
	}
}

func TestDNSResponseIgnoredByServer(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	server := dnsServerSession(serverConn, echoDNS)
	defer server.Close()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()
	settings := util.StringMap{"v": "2", "padding-md5": testPadding().Load().Md5}
	_ = writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes())
	_ = writeRawFrame(clientConn, cmdDNSResponse, 1, []byte("\x01\x00\x00\x00\x09\x00\x00"))
	_ = writeRawFrame(clientConn, cmdHeartRequest, 5, nil)
	time.Sleep(50 * time.Millisecond)
	if server.IsClosed() {
		t.Fatal("server closed after a stray DNS response")
	}
}

// Streams and DNS share a session without disturbing each other.
func TestDNSDoesNotTakeSessionFromPool(t *testing.T) {
	checkLeaks(t)
	client, servers := dnsTestClient(t, echoDNS)
	roundTrip(t, client)
	if _, err := client.ExchangeDNS(testContext(t), []byte("q")); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	roundTrip(t, client)
	if n := len(servers()); n != 1 {
		t.Fatalf("used %d sessions, want streams and DNS to share one", n)
	}
}

// A DNS query sent while a stream write is stalled by backpressure must honour
// its own deadline and must not put a deadline on the connection that fails
// the stalled stream.
func TestDNSRequestDoesNotBreakBackpressure(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	pad := testPadding()
	release := make(chan struct{})
	received := make(chan int64, 1)
	server := NewServerSession(serverConn, func(stream *Stream) {
		<-release
		n, _ := io.Copy(io.Discard, stream)
		received <- n
	}, pad, logger.NOP())
	server.SetDNSHandler(context.Background(), echoDNS)
	go server.Run()
	defer server.Close()

	client := newTestClient(clientConn, pad)
	defer client.Close()
	if _, err := client.ExchangeDNS(testContext(t), []byte("warm")); err != nil {
		t.Fatalf("warm-up query: %v", err)
	}
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	const total = 4 << 20
	uploaded := make(chan error, 1)
	go func() {
		_, err := stream.Write(make([]byte, total))
		stream.Close()
		uploaded <- err
	}()
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = client.ExchangeDNS(ctx, []byte("stalled"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("query behind a stalled stream: %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("query took %v, past its own deadline", elapsed)
	}

	// Stall past the 5 second control frame deadline.
	time.Sleep(6 * time.Second)
	close(release)
	if err := <-uploaded; err != nil {
		t.Fatalf("stalled upload failed: %v", err)
	}
	if n := <-received; n != total {
		t.Fatalf("server received %d of %d bytes", n, total)
	}
	if response, err := client.ExchangeDNS(testContext(t), []byte("after")); err != nil || string(response) != "ok:after" {
		t.Fatalf("query after the stall: %q, %v", response, err)
	}
}

// A client that floods requests and stops reading cannot make the server
// start a goroutine per request.
func TestDNSFloodIsBounded(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	block := make(chan struct{})
	defer close(block)
	server := dnsServerSession(serverConn, func(context.Context, []byte) ([]byte, error) {
		<-block
		return nil, nil
	})
	defer server.Close()

	settings := util.StringMap{"v": "2", "padding-md5": testPadding().Load().Md5}
	if err := writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes()); err != nil {
		t.Fatal(err)
	}
	// Read the server's settings, then stop reading for good.
	for {
		frame, err := readRawFrame(clientConn)
		if err != nil {
			t.Fatal(err)
		}
		if frame.cmd == cmdServerSettings {
			break
		}
	}
	before := runtime.NumGoroutine()
	for i := 1; i <= 2000; i++ {
		if err := writeRawFrame(clientConn, cmdDNSRequest, uint32(i), []byte("q")); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if grown := runtime.NumGoroutine() - before; grown > maxDNSInFlight+16 {
		t.Fatalf("2000 requests started %d goroutines", grown)
	}
	if server.IsClosed() {
		t.Fatal("server closed under a flood")
	}
}

// Once a server is known not to offer DNS, queries fail without dialing a new
// session each time.
func TestDNSUnsupportedServerDialedOnce(t *testing.T) {
	checkLeaks(t)
	client, servers := dnsTestClient(t, nil)
	for i := 0; i < 5; i++ {
		_, err := client.ExchangeDNS(testContext(t), []byte("q"))
		if !errors.Is(err, ErrDNSUnsupported) {
			t.Fatalf("query %d: %v, want ErrDNSUnsupported", i, err)
		}
	}
	if n := len(servers()); n != 1 {
		t.Fatalf("dialed %d sessions, want 1", n)
	}
}

// brokenConn fails every write once broken, as a real connection whose peer
// reset it would.
type brokenConn struct {
	net.Conn
	broken atomic.Bool
}

func (c *brokenConn) Write(b []byte) (int, error) {
	if c.broken.Load() {
		return 0, errors.New("write: connection reset by peer")
	}
	return c.Conn.Write(b)
}

// A query whose write fails on a broken connection is retried on a new
// session, whatever error the connection returned.
func TestDNSWriteErrorRetries(t *testing.T) {
	checkLeaks(t)
	var lock sync.Mutex
	var conns []*brokenConn
	var servers []*Session
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		lock.Lock()
		defer lock.Unlock()
		servers = append(servers, dnsServerSession(serverConn, echoDNS))
		conn := &brokenConn{Conn: clientConn}
		conns = append(conns, conn)
		return conn, nil
	}, testPadding(), 0, 0, 0, 0, 0, 0, 0, 0, 0, false, nil, "")
	defer func() {
		client.Close()
		lock.Lock()
		defer lock.Unlock()
		for _, server := range servers {
			server.Close()
		}
	}()
	if _, err := client.ExchangeDNS(testContext(t), []byte("warm")); err != nil {
		t.Fatalf("warm-up query: %v", err)
	}
	lock.Lock()
	conns[0].broken.Store(true)
	lock.Unlock()
	response, err := client.ExchangeDNS(testContext(t), []byte("again"))
	if err != nil || string(response) != "ok:again" {
		t.Fatalf("query on a broken session: %q, %v", response, err)
	}
	lock.Lock()
	defer lock.Unlock()
	if len(conns) != 2 {
		t.Fatalf("dialed %d sessions, want a retry on a second one", len(conns))
	}
}

// Pool maintenance does not close a session while a DNS query waits on it.
func TestDNSBusySessionNotClosedAsIdle(t *testing.T) {
	checkLeaks(t)
	release := make(chan struct{})
	client, _ := dnsTestClient(t, func(_ context.Context, request []byte) ([]byte, error) {
		<-release
		return request, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := client.ExchangeDNS(testContext(t), []byte("held"))
		done <- err
	}()
	waitFor(t, "the query to be pending", func() bool {
		session := anySession(client)
		return session != nil && session.dnsBusy()
	})
	session := anySession(client)
	client.idleCleanupExpTime(time.Now().Add(time.Hour))
	client.closeAfterIdle = time.Nanosecond
	client.retireCleanup()
	if session.IsClosed() {
		t.Fatal("pool maintenance closed a session with a DNS query in flight")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("held query: %v", err)
	}
	client.idleCleanupExpTime(time.Now().Add(time.Hour))
	if !session.IsClosed() {
		t.Fatal("idle session not closed once its query finished")
	}
}

func TestDNSHandlerCancelledOnClose(t *testing.T) {
	checkLeaks(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	started := make(chan struct{})
	finished := make(chan struct{})
	server := dnsServerSession(serverConn, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	})
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()
	settings := util.StringMap{"v": "2", "padding-md5": testPadding().Load().Md5}
	_ = writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes())
	_ = writeRawFrame(clientConn, cmdDNSRequest, 1, []byte("q"))
	<-started
	server.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("handler context not cancelled when the session closed")
	}
}

// A query prefers a session without streams, whose receive loop a stream that
// is not read cannot hold up.
func TestDNSPrefersSessionWithoutStreams(t *testing.T) {
	checkLeaks(t)
	client, _ := dnsTestClient(t, echoDNS)
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	defer stream.Close()
	idle, err := client.createSession(context.Background())
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	waitFor(t, "settings", idle.serverSettingsReceived)
	waitFor(t, "settings", func() bool {
		for _, session := range []*Session{anySessionExcept(client, idle)} {
			if session == nil || !session.serverSettingsReceived() {
				return false
			}
		}
		return true
	})
	for i := 0; i < 20; i++ {
		session, err := client.dnsSession(testContext(t))
		if err != nil {
			t.Fatal(err)
		}
		if session != idle {
			t.Fatal("query placed on the session carrying a stream")
		}
	}
}

func anySessionExcept(c *Client, except *Session) *Session {
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	for _, session := range c.sessions {
		if session != except {
			return session
		}
	}
	return nil
}

// slowDialClient returns a client whose dials wait for release, or fail with
// dialErr when it is set, and counts them. Its sessions answer DNS with
// echoDNS. reuse=false builds it with disableReuse.
func slowDialClient(t *testing.T, reuse bool, dialErr error) (*Client, chan struct{}, *atomic.Int32) {
	t.Helper()
	return slowDialClientWith(t, reuse, dialErr, echoDNS)
}

// slowDialClientWith is slowDialClient with sessions answering with handler.
func slowDialClientWith(t *testing.T, reuse bool, dialErr error, handler DNSHandler) (*Client, chan struct{}, *atomic.Int32) {
	t.Helper()
	release := make(chan struct{})
	var dials atomic.Int32
	var lock sync.Mutex
	var servers []*Session
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if dialErr != nil {
			return nil, dialErr
		}
		clientConn, serverConn := net.Pipe()
		server := dnsServerSession(serverConn, handler)
		lock.Lock()
		servers = append(servers, server)
		lock.Unlock()
		return clientConn, nil
	}, testPadding(), 0, 0, 0, 0, 0, 0, 0, 0, 0, !reuse, nil, "")
	t.Cleanup(func() {
		client.Close()
		lock.Lock()
		defer lock.Unlock()
		for _, server := range servers {
			server.Close()
		}
	})
	return client, release, &dials
}

// waitWaiters waits until n queries wait for the running dial.
func waitWaiters(t *testing.T, client *Client, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.dnsDialLock.Lock()
		waiters := 0
		if client.dnsDialing != nil {
			waiters = client.dnsDialing.waiters
		}
		client.dnsDialLock.Unlock()
		if waiters >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d queries wait for the dial, want %d", waiters, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitDials waits until n dials have started.
func waitDials(t *testing.T, dials *atomic.Int32, n int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for dials.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d dials started, want %d", dials.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// A burst of queries that finds no session must open one connection, not one
// per query, and every query must be answered on it.
func TestDNSColdBurstDialsOnce(t *testing.T) {
	for _, reuse := range []bool{true, false} {
		t.Run(fmt.Sprintf("reuse=%v", reuse), func(t *testing.T) {
			checkLeaks(t)
			client, release, dials := slowDialClient(t, reuse, nil)
			const queries = 50
			var wg sync.WaitGroup
			errs := make(chan error, queries)
			for i := 0; i < queries; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					request := []byte(fmt.Sprintf("q%d", i))
					response, err := client.ExchangeDNS(testContext(t), request)
					if err != nil {
						errs <- err
						return
					}
					if !bytes.Equal(response, append([]byte("ok:"), request...)) {
						errs <- fmt.Errorf("query %d got %q", i, response)
					}
				}(i)
			}
			waitDials(t, dials, 1)
			waitWaiters(t, client, queries-1)
			close(release)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if n := dials.Load(); n != 1 {
				t.Fatalf("dialed %d sessions, want 1", n)
			}
		})
	}
}

// The queries waiting for a dial that fails get its error rather than each
// dialing again.
func TestDNSFailedDialShared(t *testing.T) {
	checkLeaks(t)
	dialErr := errors.New("dial refused")
	client, release, dials := slowDialClient(t, true, dialErr)
	const queries = 10
	errs := make(chan error, queries)
	for i := 0; i < queries; i++ {
		go func() {
			_, err := client.ExchangeDNS(testContext(t), []byte("q"))
			errs <- err
		}()
	}
	waitDials(t, dials, 1)
	waitWaiters(t, client, queries-1)
	close(release)
	for i := 0; i < queries; i++ {
		if err := <-errs; !errors.Is(err, dialErr) {
			t.Errorf("err = %v, want %v", err, dialErr)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d times, want 1", n)
	}
}

// When the query that started a dial gives up, a waiting query with time left
// dials itself instead of failing with it.
func TestDNSAbandonedDialRetried(t *testing.T) {
	checkLeaks(t)
	client, release, dials := slowDialClient(t, true, nil)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := client.ExchangeDNS(leaderCtx, []byte("leader"))
		leaderDone <- err
	}()
	waitDials(t, dials, 1)
	followerDone := make(chan error, 1)
	go func() {
		response, err := client.ExchangeDNS(testContext(t), []byte("follower"))
		if err == nil && string(response) != "ok:follower" {
			err = fmt.Errorf("response = %q", response)
		}
		followerDone <- err
	}()
	waitWaiters(t, client, 1)
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v, want context.Canceled", err)
	}
	waitDials(t, dials, 2)
	close(release)
	if err := <-followerDone; err != nil {
		t.Fatalf("follower: %v", err)
	}
}

// Without reuse, a session dialed for DNS is closed once its last query is
// answered.
func TestDNSNoReuseSessionClosedWhenIdle(t *testing.T) {
	checkLeaks(t)
	client, release, _ := slowDialClient(t, false, nil)
	close(release)
	if _, err := client.ExchangeDNS(testContext(t), []byte("q")); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.sessionsLock.Lock()
		n := len(client.sessions)
		client.sessionsLock.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions still open", n)
		}
		time.Sleep(time.Millisecond)
	}
}

// A session carries at most maxDNSPerSession queries, about as many as a server
// answers at once, so a larger burst spreads over as few more sessions as it
// needs instead of being refused by the server.
func TestDNSBurstBeyondInFlightLimitDialsMore(t *testing.T) {
	checkLeaks(t)
	answer := make(chan struct{})
	var answering atomic.Int32
	client, release, dials := slowDialClientWith(t, true, nil, func(ctx context.Context, request []byte) ([]byte, error) {
		answering.Add(1)
		select {
		case <-answer:
		case <-ctx.Done():
		}
		return append([]byte("ok:"), request...), nil
	})
	const queries = maxDNSPerSession + maxDNSPerSession/2
	var wg sync.WaitGroup
	errs := make(chan error, queries)
	for i := 0; i < queries; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := []byte(fmt.Sprintf("q%d", i))
			response, err := client.ExchangeDNS(testContext(t), request)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(response, append([]byte("ok:"), request...)) {
				errs <- fmt.Errorf("query %d got %q", i, response)
			}
		}(i)
	}
	waitDials(t, dials, 1)
	waitWaiters(t, client, queries-1)
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for answering.Load() < queries {
		if time.Now().After(deadline) {
			t.Fatalf("%d queries reached a handler, want %d", answering.Load(), queries)
		}
		time.Sleep(time.Millisecond)
	}
	if client.HasIdleDNSSession() != (dials.Load()*maxDNSPerSession > queries) {
		t.Errorf("HasIdleDNSSession = %v with %d sessions for %d queries",
			client.HasIdleDNSSession(), dials.Load(), queries)
	}
	close(answer)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialed %d sessions, want 2", n)
	}
}

// A session whose every DNS slot is taken is not reported idle.
func TestDNSFullSessionNotIdle(t *testing.T) {
	checkLeaks(t)
	client, _ := dnsTestClient(t, echoDNS)
	session, err := client.dnsSessionForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	session.dnsUsers.Add(-1)
	deadline := time.Now().Add(2 * time.Second)
	for !client.HasIdleDNSSession() {
		if time.Now().After(deadline) {
			t.Fatal("no idle session after dialing one")
		}
		time.Sleep(time.Millisecond)
	}
	session.dnsUsers.Store(maxDNSPerSession)
	if client.HasIdleDNSSession() {
		t.Fatal("full session reported idle")
	}
	session.dnsUsers.Store(0)
}

// A dial error that wraps a context error, from the dialer's own timeout, is
// still shared by the waiting queries while the one that dialed has time left.
func TestDNSDialTimeoutShared(t *testing.T) {
	checkLeaks(t)
	dialErr := fmt.Errorf("dial: %w", context.DeadlineExceeded)
	client, release, dials := slowDialClient(t, true, dialErr)
	const queries = 5
	errs := make(chan error, queries)
	for i := 0; i < queries; i++ {
		go func() {
			_, err := client.ExchangeDNS(testContext(t), []byte("q"))
			errs <- err
		}()
	}
	waitDials(t, dials, 1)
	waitWaiters(t, client, queries-1)
	close(release)
	for i := 0; i < queries; i++ {
		if err := <-errs; !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want DeadlineExceeded", err)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d times, want 1", n)
	}
}

// A query that gives up keeps its slot until the server answers it, since the
// server still counts it against its in-flight limit.
func TestDNSAbandonedQueryHoldsSlotUntilAnswered(t *testing.T) {
	checkLeaks(t)
	answer := make(chan struct{})
	client, _ := dnsTestClient(t, func(ctx context.Context, request []byte) ([]byte, error) {
		if string(request) == "slow" {
			select {
			case <-answer:
			case <-ctx.Done():
			}
		}
		return request, nil
	})
	if _, err := client.ExchangeDNS(testContext(t), []byte("warm")); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	session := anySession(client)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.ExchangeDNS(ctx, []byte("slow")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if n := session.dnsUsers.Load(); n != 1 {
		t.Fatalf("%d slots taken while the server still answers, want 1", n)
	}
	close(answer)
	deadline := time.Now().Add(2 * time.Second)
	for session.dnsUsers.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d slots taken after the answer arrived", session.dnsUsers.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

// A query waiting for a dial because every session was full uses a slot that
// frees up meanwhile instead of waiting for the dial.
func TestDNSWaiterUsesFreedSlot(t *testing.T) {
	checkLeaks(t)
	answer := make(chan struct{})
	client, release, dials := slowDialClientWith(t, true, nil, func(ctx context.Context, request []byte) ([]byte, error) {
		if string(request) == "hold" {
			select {
			case <-answer:
			case <-ctx.Done():
			}
		}
		return request, nil
	})
	defer close(answer)
	close(release)
	if _, err := client.ExchangeDNS(testContext(t), []byte("warm")); err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	session := anySession(client)
	// Take every slot but one with held queries, and the last one by hand.
	held := make(chan error, maxDNSPerSession)
	for i := 0; i < maxDNSPerSession-1; i++ {
		go func() {
			_, err := client.ExchangeDNS(testContext(t), []byte("hold"))
			held <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for session.dnsUsers.Load() != maxDNSPerSession-1 {
		if time.Now().After(deadline) {
			t.Fatalf("%d slots taken, want %d", session.dnsUsers.Load(), maxDNSPerSession-1)
		}
		time.Sleep(time.Millisecond)
	}
	if !session.acquireDNS() {
		t.Fatal("last slot not free")
	}
	// Block the overflow dial so that the waiter can only get the freed slot.
	client.dnsDialLock.Lock()
	dial := &dnsDial{done: make(chan struct{}), kick: make(chan struct{})}
	client.dnsDialing = dial
	client.dnsDialActive.Store(true)
	client.dnsDialLock.Unlock()
	defer func() {
		client.dnsDialLock.Lock()
		client.dnsDialing = nil
		client.dnsDialActive.Store(false)
		client.dnsDialLock.Unlock()
		close(dial.done)
	}()

	done := make(chan error, 1)
	go func() {
		_, err := client.ExchangeDNS(testContext(t), []byte("waiter"))
		done <- err
	}()
	deadline = time.Now().Add(2 * time.Second)
	for {
		client.dnsDialLock.Lock()
		waiters := dial.waiters
		client.dnsDialLock.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("query did not wait for the dial")
		}
		time.Sleep(time.Millisecond)
	}
	client.releaseDNS(session)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waiter: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not use the freed slot")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d sessions, want 1", n)
	}
}
