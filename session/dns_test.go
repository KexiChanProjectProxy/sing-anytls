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
)

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
	session, _, err := c.dnsSession(testContext(t))
	return session, err
}

// A server answers past maxDNSInFlight at once rather than queueing, so that
// a client cannot pile up handlers.
func TestDNSInFlightLimit(t *testing.T) {
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
		session, _, err := client.dnsSession(testContext(t))
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
