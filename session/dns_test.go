package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
