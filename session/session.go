package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq         uint64
	createdAt   time.Time
	maxLifetime time.Duration
	idleSince   time.Time
	padding     *atomic.TypedValue[*padding.PaddingFactory]
	logger      logger.Logger

	peerVersion byte

	// client
	isClient    bool
	sendPadding bool
	pktCounter  atomic.Uint32
	heartbeat   time.Duration
	// clientMetadata is sent as the "client" setting verbatim.
	clientMetadata string
	// Latency measurement. Each timestamp is written by one goroutine and
	// consumed by recvLoop; the results are read by the pool. Timestamps are
	// monoNow values, zero when nothing is outstanding.
	settingsSentAt  atomic.Int64
	heartbeatSentAt atomic.Int64
	latencySmoothed atomic.Int64
	latencyLast     atomic.Int64
	latencySamples  atomic.Uint32
	// statsHandler receives the server's statistics frames. The client only
	// asks the server for them when it is set.
	statsHandler StatsHandler

	// server
	onNewStream func(stream *Stream)
	// statsProvider reports the server's view of the connection, and is nil
	// when the server does not report statistics.
	statsProvider StatsProvider
}

// StatsHandler receives a statistics frame for the client session numbered
// seq. It is called from the session's receive loop and must not block.
type StatsHandler func(seq uint64, stats util.StringMap)

// StatsProvider reports the server's view of conn, or nil when it has nothing
// to report. It is called periodically from a session's own goroutine.
type StatsProvider func(conn net.Conn) util.StringMap

// StatsInterval is how often a server reports statistics to a client that
// asked for them.
const StatsInterval = 10 * time.Second

// statsInterval is StatsInterval, as a variable so that tests can shorten it.
var statsInterval = StatsInterval

// SetStatsProvider makes a server session report statistics to a client that
// asks for them. It must be called before Run.
func (s *Session) SetStatsProvider(provider StatsProvider) {
	s.statsProvider = provider
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger, heartbeat time.Duration, clientMetadata string) *Session {
	s := &Session{
		conn:           conn,
		isClient:       true,
		sendPadding:    true,
		padding:        _padding,
		logger:         logger,
		heartbeat:      heartbeat,
		clientMetadata: clientMetadata,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
		logger:      logger,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      s.clientMetadata,
		"padding-md5": s.padding.Load().Md5,
	}
	if s.statsHandler != nil {
		// Servers that do not know this key ignore it, like any other.
		settings["stats"] = "1"
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	// The receive loop starts first, so that the server's answer is read
	// even while the settings write is still in progress.
	go s.recvLoop()

	// The settings frame goes out at once rather than with the first stream,
	// so that the server's answer measures the session's latency before it is
	// used, and so that heartbeats of an idle session really reach the server.
	// A failed write closes the session, which stops the receive loop.
	s.settingsSentAt.Store(monoNow())
	if _, err := s.writeControlFrame(f); err != nil {
		return
	}

	// Start heartbeat goroutine if enabled
	if s.heartbeat > 0 {
		go s.heartbeatLoop()
	}
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		_ = s.conn.SetDeadline(time.Now())
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)

	if sid >= 2 && s.peerVersion >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	// Register the stream before announcing it, so that a reply the server
	// sends straight after the SYN finds it.
	s.streamLock.Lock()
	select {
	case <-s.die:
		s.streamLock.Unlock()
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
	}
	s.streamLock.Unlock()

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		s.streamLock.Lock()
		delete(s.streams, sid)
		s.streamLock.Unlock()
		return nil, err
	}
	return stream, nil
}

func (s *Session) recvLoop() error {
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		logrus.Errorln("[BUG]", r, string(debug.Stack()))
	// 	}
	// }()
	defer s.Close()

	var receivedSettingsFromClient bool
	var statsStarted bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err == nil {
			sid := hdr.StreamID()
			switch hdr.Cmd() {
			case cmdPSH:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err == nil {
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok {
							stream.pipeW.Write(buffer)
						}
						buf.Put(buffer)
					} else {
						buf.Put(buffer)
						return err
					}
				}
			case cmdSYN: // should be server only
				if !s.isClient && !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeControlFrame(f)
					return nil
				}
				s.streamLock.Lock()
				if _, ok := s.streams[sid]; !ok {
					stream := newStream(sid, s)
					s.streams[sid] = stream
					go func() {
						if s.onNewStream != nil {
							s.onNewStream(stream)
						} else {
							stream.Close()
						}
					}()
				}
				s.streamLock.Unlock()
			case cmdSYNACK: // should be client only
				s.synDoneLock.Lock()
				if s.synDone != nil {
					s.synDone()
					s.synDone = nil
				}
				s.synDoneLock.Unlock()
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					// report error
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
					}
					buf.Put(buffer)
				}
			case cmdFIN:
				s.streamLock.Lock()
				stream, ok := s.streams[sid]
				delete(s.streams, sid)
				s.streamLock.Unlock()
				if ok {
					stream.closeLocally()
				}
			case cmdWaste:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
			case cmdSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if !s.isClient {
						receivedSettingsFromClient = true
						m := util.StringMapFromBytes(buffer)
						paddingF := s.padding.Load()
						if m["padding-md5"] != paddingF.Md5 {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
						// check client's version
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion = byte(v)
							// send cmdServerSettings
							f := newFrame(cmdServerSettings, 0)
							f.data = util.StringMap{
								"v": "2",
							}.ToBytes()
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
							// Statistics are only sent to a client that asked,
							// and only once the client is known to be v2.
							if m["stats"] == "1" && s.statsProvider != nil && !statsStarted {
								statsStarted = true
								go s.statsLoop()
							}
						}
					}
					buf.Put(buffer)
				}
			case cmdAlert:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						s.logger.Error("[Alert from server]", string(buffer))
					}
					buf.Put(buffer)
					return nil
				}
			case cmdUpdatePaddingScheme:
				if hdr.Length() > 0 {
					// `rawScheme` Do not use buffer to prevent subsequent misuse
					rawScheme := make([]byte, int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
						return err
					}
					if s.isClient {
						if padding.UpdatePaddingScheme(rawScheme, s.padding) {
							s.logger.Debug(fmt.Sprintf("[Update padding succeed] %x\n", md5.Sum(rawScheme)))
						} else {
							s.logger.Warn(fmt.Sprintf("[Update padding failed] %x\n", md5.Sum(rawScheme)))
						}
					}
				}
			case cmdHeartRequest:
				// Server side: respond to heartbeat silently (too verbose for debug)
				if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			case cmdHeartResponse:
				if s.isClient {
					if sent := s.heartbeatSentAt.Swap(0); sent != 0 {
						s.recordLatency(time.Duration(monoNow()-sent), "heartbeat")
					}
				}
			case cmdServerSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						if sent := s.settingsSentAt.Swap(0); sent != 0 {
							s.recordLatency(time.Duration(monoNow()-sent), "settings")
						}
						// check server's version
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion = byte(v)
						}
					}
					buf.Put(buffer)
				}
			case cmdStats:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient && s.statsHandler != nil {
						s.statsHandler(s.seq, util.StringMapFromBytes(buffer))
					}
					buf.Put(buffer)
				}
			default:
				// An unknown command is skipped along with its payload, so that
				// a newer peer's frame cannot desynchronise the stream.
				if hdr.Length() > 0 {
					if _, err := io.CopyN(io.Discard, s.conn, int64(hdr.Length())); err != nil {
						return err
					}
				}
			}
		} else {
			return err
		}
	}
}

func (s *Session) heartbeatLoop() {
	// Add jitter (0-20% of heartbeat interval) to prevent thundering herd
	// This ensures sessions don't all send heartbeats at exactly the same time
	import_time := time.Now().UnixNano()
	jitter := time.Duration(import_time % int64(s.heartbeat/5))

	s.logger.Trace(fmt.Sprintf("[Heartbeat][Session#%d] Starting heartbeat loop with %v interval (jitter: %v)", s.seq, s.heartbeat, jitter))

	// Wait for jitter before starting the ticker, returning at once if the
	// session closes meanwhile.
	jitterTimer := time.NewTimer(jitter)
	select {
	case <-jitterTimer.C:
	case <-s.die:
		jitterTimer.Stop()
		return
	}

	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()

	heartbeatCount := 0
	for {
		select {
		case <-ticker.C:
			if s.IsClosed() {
				return
			}
			heartbeatCount++
			// Log at trace level
			s.logger.Trace(fmt.Sprintf("[Heartbeat][Session#%d] Sending heartbeat #%d", s.seq, heartbeatCount))
			if err := s.sendHeartbeat(); err != nil {
				s.logger.Warn(fmt.Sprintf("[Heartbeat][Session#%d] Failed to send heartbeat #%d: %v", s.seq, heartbeatCount, err))
				s.Close()
				return
			}
		case <-s.die:
			s.logger.Trace(fmt.Sprintf("[Heartbeat][Session#%d] Stopped after %d heartbeats", s.seq, heartbeatCount))
			return
		}
	}
}

// sendHeartbeat writes a heartbeat request and times it. While an earlier
// request is still unanswered its timestamp is kept, because the next response
// belongs to it: the server answers requests in the order they arrive.
func (s *Session) sendHeartbeat() error {
	s.heartbeatSentAt.CompareAndSwap(0, monoNow())
	_, err := s.writeControlFrame(newFrame(cmdHeartRequest, 0))
	return err
}

// epoch anchors monoNow, so that timestamps kept in atomics stay monotonic.
var epoch = time.Now()

func monoNow() int64 {
	return int64(time.Since(epoch))
}

// Latency is a client session's end-to-end round trip time, measured from the
// settings exchange when the session opens and from every heartbeat after.
// Both are answered by the server itself, apart from any proxied destination,
// so any version 2 server can be measured.
type Latency struct {
	// Smoothed is an exponentially weighted moving average of the samples,
	// weighted like TCP's smoothed RTT.
	Smoothed time.Duration
	// Last is the most recent sample.
	Last time.Duration
	// Samples counts the samples taken; Smoothed and Last are meaningless
	// while it is zero.
	Samples uint32
}

// Latency returns what is known of the session's latency.
func (s *Session) Latency() Latency {
	return Latency{
		Smoothed: time.Duration(s.latencySmoothed.Load()),
		Last:     time.Duration(s.latencyLast.Load()),
		Samples:  s.latencySamples.Load(),
	}
}

// recordLatency adds a sample. It is only called from recvLoop, so updates do
// not race with each other; a reader may see the count and the average one
// update apart, which is harmless.
func (s *Session) recordLatency(sample time.Duration, source string) {
	if sample < 0 {
		sample = 0
	}
	s.latencyLast.Store(int64(sample))
	if s.latencySamples.Load() == 0 {
		s.latencySmoothed.Store(int64(sample))
		s.latencySamples.Add(1)
		s.logger.Debug(fmt.Sprintf("[Latency][Session#%d] first sample %v (%s)", s.seq, sample, source))
		return
	}
	smoothed := time.Duration(s.latencySmoothed.Load())
	smoothed += (sample - smoothed) / 8
	s.latencySmoothed.Store(int64(smoothed))
	s.latencySamples.Add(1)
	s.logger.Trace(fmt.Sprintf("[Latency][Session#%d] sample %v (%s), srtt=%v", s.seq, sample, source, smoothed))
}

// statsLoop reports the server's view of the connection until the session
// closes. A write only fails when the connection itself has, which closes the
// session as any other failed write does.
func (s *Session) statsLoop() {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.die:
			return
		case <-ticker.C:
			stats := s.statsProvider(s.conn)
			if len(stats) == 0 {
				continue
			}
			if err := s.writeStatsFrame(stats.ToBytes()); err != nil {
				s.Close()
				return
			}
		}
	}
}

// writeStatsFrame sends a statistics frame without a write deadline.
//
// writeControlFrame puts a deadline on the whole connection, which would also
// apply to a data write already blocked behind a client that stopped reading,
// and so turn ordinary backpressure into a failed session. A report instead
// waits its turn like a data frame; closing the session releases it.
func (s *Session) writeStatsFrame(data []byte) error {
	buffer := buf.NewSize(len(data) + headerOverHeadSize)
	defer buffer.Release()
	buffer.WriteByte(cmdStats)
	binary.BigEndian.PutUint32(buffer.Extend(4), 0)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(len(data)))
	buffer.Write(data)
	_, err := s.writeConn(buffer.Bytes())
	return err
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

// maxFrameDataLen is the maximum payload bytes per data frame. The wire
// format encodes payload length as a uint16, so a single frame cannot
// carry more than 65535 bytes. writeDataFrame splits larger writes into
// multiple frames and sends the whole frame sequence in one writeConn call.
// That keeps one Stream.Write contiguous relative to other stream/control
// frame writes.
const maxFrameDataLen = 0xFFFF

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return 0, nil
	}
	if dataLen <= maxFrameDataLen {
		buffer := buf.NewSize(dataLen + headerOverHeadSize)
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
		buffer.Write(data)
		_, err := s.writeConn(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return 0, err
		}
		return dataLen, nil
	}

	frameCount := (dataLen + maxFrameDataLen - 1) / maxFrameDataLen
	buffer := buf.NewSize(dataLen + frameCount*headerOverHeadSize)
	defer buffer.Release()

	for written := 0; written < dataLen; {
		chunk := dataLen - written
		if chunk > maxFrameDataLen {
			chunk = maxFrameDataLen
		}
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(chunk))
		buffer.Write(data[written : written+chunk])
		written += chunk
	}

	if _, err := s.writeConn(buffer.Bytes()); err != nil {
		return 0, err
	}
	return dataLen, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	s.conn.SetWriteDeadline(time.Time{})

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}
