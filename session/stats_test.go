package session

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	singAtomic "github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	// Report quickly so that the tests do not wait for the production interval.
	statsInterval = 20 * time.Millisecond
}

func testPadding() *singAtomic.TypedValue[*padding.PaddingFactory] {
	var pad singAtomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	return &pad
}

func newTestClient(conn net.Conn, pad *singAtomic.TypedValue[*padding.PaddingFactory]) *Client {
	return NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return conn, nil
	}, pad, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, nil)
}

// echoServer starts a server session that answers every stream by echoing it.
func echoServer(t *testing.T, conn net.Conn, pad *singAtomic.TypedValue[*padding.PaddingFactory], provider StatsProvider) *Session {
	t.Helper()
	server := NewServerSession(conn, func(stream *Stream) {
		_, _ = io.Copy(stream, stream)
	}, pad, logger.NOP())
	server.SetStatsProvider(provider)
	go server.Run()
	return server
}

// roundTrip opens a stream and exchanges one message, which is what makes the
// client flush its buffered settings frame.
func roundTrip(t *testing.T, client *Client) {
	t.Helper()
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply := make([]byte, 4)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(stream, reply); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(reply) != "ping" {
		t.Fatalf("echo got %q", reply)
	}
}

func TestStatsDeliveredWhenNegotiated(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	pad := testPadding()
	server := echoServer(t, serverConn, pad, func(net.Conn) util.StringMap {
		return util.StringMap{"rtt_us": "1234"}
	})
	defer server.Close()

	client := newTestClient(clientConn, pad)
	defer client.Close()
	received := make(chan util.StringMap, 16)
	client.SetStatsHandler(func(seq uint64, stats util.StringMap) {
		select {
		case received <- stats:
		default:
		}
	})
	roundTrip(t, client)

	select {
	case stats := <-received:
		if stats["rtt_us"] != "1234" {
			t.Fatalf("stats = %v", stats)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no statistics frame arrived")
	}
}

// A client that never asked must never receive the new frame, which is what
// keeps old clients safe: they would misparse it.
func TestStatsNotSentWithoutRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	pad := testPadding()
	var calls atomic.Int32
	server := echoServer(t, serverConn, pad, func(net.Conn) util.StringMap {
		calls.Add(1)
		return util.StringMap{"rtt_us": "1"}
	})
	defer server.Close()

	client := newTestClient(clientConn, pad)
	defer client.Close()
	roundTrip(t, client)
	time.Sleep(10 * statsInterval)
	roundTrip(t, client)
	if calls.Load() != 0 {
		t.Fatalf("server produced statistics %d times for a client that did not ask", calls.Load())
	}
}

// A server that does not report, including one that predates this extension,
// just ignores the request; traffic is unaffected.
func TestStatsRequestIgnoredByServerWithoutProvider(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	pad := testPadding()
	server := echoServer(t, serverConn, pad, nil)
	defer server.Close()

	client := newTestClient(clientConn, pad)
	defer client.Close()
	var calls atomic.Int32
	client.SetStatsHandler(func(uint64, util.StringMap) { calls.Add(1) })
	roundTrip(t, client)
	time.Sleep(10 * statsInterval)
	roundTrip(t, client)
	if calls.Load() != 0 {
		t.Fatalf("handler called %d times without a reporting server", calls.Load())
	}
}

type rawFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

func readRawFrame(r io.Reader) (rawFrame, error) {
	var header rawHeader
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return rawFrame{}, err
	}
	data := make([]byte, header.Length())
	if _, err := io.ReadFull(r, data); err != nil {
		return rawFrame{}, err
	}
	return rawFrame{cmd: header.Cmd(), sid: header.StreamID(), data: data}, nil
}

func writeRawFrame(w io.Writer, cmd byte, sid uint32, data []byte) error {
	buffer := make([]byte, headerOverHeadSize+len(data))
	buffer[0] = cmd
	binary.BigEndian.PutUint32(buffer[1:], sid)
	binary.BigEndian.PutUint16(buffer[5:], uint16(len(data)))
	copy(buffer[headerOverHeadSize:], data)
	_, err := w.Write(buffer)
	return err
}

// clientSettings returns the settings a client sends, read off the wire by a
// bare peer.
func clientSettings(t *testing.T, handler StatsHandler) util.StringMap {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := newTestClient(clientConn, testPadding())
	defer client.Close()
	if handler != nil {
		client.SetStatsHandler(handler)
	}
	go func() {
		stream, err := client.CreateStream(context.Background())
		if err == nil {
			_, _ = stream.Write([]byte("x"))
		}
	}()
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

// Without a handler the settings a client sends are exactly what they were
// before this extension.
func TestClientSettingsUnchangedWithoutStats(t *testing.T) {
	settings := clientSettings(t, nil)
	if _, present := settings["stats"]; present {
		t.Fatalf("settings carry stats without a handler: %v", settings)
	}
	for _, key := range []string{"v", "client", "padding-md5"} {
		if _, present := settings[key]; !present {
			t.Fatalf("settings lost %q: %v", key, settings)
		}
	}
	if len(settings) != 3 {
		t.Fatalf("settings gained keys: %v", settings)
	}
}

func TestClientSettingsCarryStatsRequest(t *testing.T) {
	settings := clientSettings(t, func(uint64, util.StringMap) {})
	if settings["stats"] != "1" {
		t.Fatalf("settings = %v", settings)
	}
}

// A frame with an unknown command must be skipped with its payload. Before the
// fix the payload was parsed as the next header and corrupted the stream.
func TestUnknownCommandPayloadSkipped(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := newTestClient(clientConn, testPadding())
	defer client.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
		for {
			frame, err := readRawFrame(serverConn)
			if err != nil {
				return
			}
			if frame.cmd == cmdSYN {
				// A frame from some future version, then real data.
				_ = writeRawFrame(serverConn, 99, 0, []byte("\x02\x00\x00\x00\x01\x00\x05junk!"))
				_ = writeRawFrame(serverConn, cmdPSH, frame.sid, []byte("ok"))
				// Keep reading: net.Pipe is synchronous, so the client's
				// remaining writes would otherwise block.
				_, _ = io.Copy(io.Discard, serverConn)
				return
			}
		}
	}()

	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if _, err = stream.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply := make([]byte, 2)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(stream, reply); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("stream got %q, want the data after the unknown frame", reply)
	}
	_ = serverConn.Close()
	wg.Wait()
}

// A server must not report to a v1 client even if it sets the key, since only
// v2 clients have the settings exchange this relies on.
func TestStatsNotSentToVersionOneClient(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	var calls atomic.Int32
	server := echoServer(t, serverConn, testPadding(), func(net.Conn) util.StringMap {
		calls.Add(1)
		return util.StringMap{"rtt_us": "1"}
	})
	defer server.Close()
	settings := util.StringMap{"v": "1", "stats": "1", "padding-md5": testPadding().Load().Md5}
	_ = writeRawFrame(clientConn, cmdSettings, 0, settings.ToBytes())
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()
	time.Sleep(10 * statsInterval)
	if calls.Load() != 0 {
		t.Fatalf("server reported %d times to a v1 client", calls.Load())
	}
}

// Closing a client must stop its maintenance goroutine at once, not after the
// next check interval.
func TestClientCloseStopsMaintenanceLoop(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	}, testPadding(), time.Hour, 0, 0, 0, 0, 0, 0, 0, 0, false, nil)
	if !goroutineRunning("session.NewClient.func") {
		t.Fatal("maintenance goroutine did not start")
	}
	client.Close()
	deadline := time.Now().Add(time.Second)
	for goroutineRunning("session.NewClient.func") {
		if time.Now().After(deadline) {
			t.Fatal("maintenance goroutine outlived the client")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func goroutineRunning(function string) bool {
	buffer := make([]byte, 1<<20)
	return strings.Contains(string(buffer[:runtime.Stack(buffer, true)]), function)
}
