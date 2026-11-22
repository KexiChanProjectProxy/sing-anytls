package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// newStreamPair returns a client stream and the matching server stream over
// a loopback TCP connection, with the default padding scheme active so the
// first packets of the session go through the padding path. TCP rather than
// net.Pipe: the stream's pipe is synchronous, and with an unbuffered
// connection as well the padding writes and the stream hand-off block each
// other.
func newStreamPair(t *testing.T) (*Stream, *Stream) {
	t.Helper()
	cli, srv := tcpPair(t)
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	client := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return cli, nil
	}, &pad, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, nil, "")
	accepted := make(chan *Stream, 1)
	server := NewServerSession(srv, func(stream *Stream) { accepted <- stream }, &pad, logger.NOP())
	go server.Run()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		cli.Close()
		srv.Close()
	})
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	// The server only learns of the stream once data arrives.
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case peer := <-accepted:
		one := make([]byte, 1)
		if _, err := io.ReadFull(peer, one); err != nil {
			t.Fatalf("read first byte: %v", err)
		}
		return stream.(*Stream), peer
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept the stream")
	}
	return nil, nil
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	srv := <-accepted
	if srv == nil {
		t.Fatal("Accept failed")
	}
	return cli, srv
}

func pattern(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + seed)
	}
	return b
}

func headroomBuffer(payload []byte, headroom int) *buf.Buffer {
	b := buf.NewSize(headroom + len(payload))
	b.Resize(headroom, 0)
	copy(b.Extend(len(payload)), payload)
	return b
}

func readAll(t *testing.T, peer *Stream, n int) []byte {
	t.Helper()
	got := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(peer, got)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading from peer")
	}
	return got
}

func TestStreamFrontHeadroom(t *testing.T) {
	stream, _ := newStreamPair(t)
	if got := N.CalculateFrontHeadroom(stream); got != headerOverHeadSize {
		t.Fatalf("CalculateFrontHeadroom = %d, want %d", got, headerOverHeadSize)
	}
}

// TestStreamWriteBuffer covers the in-place path, the no-headroom fallback,
// payloads larger than one frame, and empty buffers, interleaved with plain
// Write calls so frame order is checked as well.
func TestStreamWriteBuffer(t *testing.T) {
	stream, peer := newStreamPair(t)
	cases := []struct {
		name     string
		size     int
		headroom int
		plain    bool
	}{
		{"in place", 1000, headerOverHeadSize, false},
		{"in place, extra headroom", 32 * 1024, 64, false},
		{"plain write between", 5000, 0, true},
		{"no headroom", 4096, 0, false},
		{"short headroom", 4096, headerOverHeadSize - 1, false},
		{"exactly one frame", maxFrameDataLen, headerOverHeadSize, false},
		{"larger than one frame", 3*maxFrameDataLen + 17, headerOverHeadSize, false},
		{"empty", 0, headerOverHeadSize, false},
		{"after empty", 777, headerOverHeadSize, false},
	}
	var want bytes.Buffer
	for i, c := range cases {
		payload := pattern(c.size, i)
		want.Write(payload)
		var err error
		if c.plain {
			_, err = stream.Write(payload)
		} else {
			err = stream.WriteBuffer(headroomBuffer(payload, c.headroom))
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	got := readAll(t, peer, want.Len())
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("peer received different bytes (%d bytes)", len(got))
	}
}

// TestStreamBufioCopy copies through sing's bufio.Copy, which takes the
// headroom from the stream and writes with WriteBuffer, and checks the data
// arrives intact.
func TestStreamBufioCopy(t *testing.T) {
	stream, peer := newStreamPair(t)
	const size = 4<<20 + 123
	payload := pattern(size, 3)
	srcR, srcW := tcpPair(t)
	defer srcR.Close()
	go func() {
		srcW.Write(payload)
		srcW.Close()
	}()
	copyDone := make(chan error, 1)
	go func() {
		_, err := bufio.Copy(stream, srcR)
		copyDone <- err
	}()
	got := readAll(t, peer, size)
	if !bytes.Equal(got, payload) {
		t.Fatal("peer received different bytes")
	}
	select {
	case err := <-copyDone:
		if err != nil {
			t.Fatalf("bufio.Copy: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bufio.Copy did not return")
	}
}

func TestStreamWriteBufferAfterClose(t *testing.T) {
	stream, _ := newStreamPair(t)
	stream.Close()
	err := stream.WriteBuffer(headroomBuffer(pattern(100, 1), headerOverHeadSize))
	if err == nil {
		t.Fatal("WriteBuffer after Close returned nil")
	}
	if _, werr := stream.Write([]byte{1}); werr == nil || !errors.Is(err, werr) && err.Error() != werr.Error() {
		t.Fatalf("WriteBuffer error %v differs from Write error %v", err, werr)
	}
}

func TestStreamWriteBufferDeadline(t *testing.T) {
	stream, _ := newStreamPair(t)
	stream.SetWriteDeadline(time.Now().Add(-time.Second))
	err := stream.WriteBuffer(headroomBuffer(pattern(100, 1), headerOverHeadSize))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteBuffer past deadline = %v, want os.ErrDeadlineExceeded", err)
	}
}
