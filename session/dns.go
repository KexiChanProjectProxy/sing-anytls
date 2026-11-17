package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// DNSHandler answers one DNS message received from a client. request is the
// message exactly as the client sent it, and the returned bytes are sent back
// verbatim. ctx carries the context given to SetDNSHandler and is cancelled
// when the session closes. It is called on its own goroutine.
type DNSHandler func(ctx context.Context, request []byte) ([]byte, error)

var (
	// ErrDNSUnsupported is returned when the server did not offer DNS.
	ErrDNSUnsupported = errors.New("anytls: server does not answer DNS")
	// ErrDNSServerFailed is returned when the server could not answer.
	ErrDNSServerFailed = errors.New("anytls: server could not answer DNS query")
	// ErrDNSMessageTooLarge is returned for a request that cannot fit a frame.
	ErrDNSMessageTooLarge = errors.New("anytls: DNS message exceeds 65535 bytes")
)

// maxDNSInFlight bounds the DNS requests a server session answers at once.
const maxDNSInFlight = 64

// maxDNSRejectQueue bounds the requests beyond maxDNSInFlight waiting to be
// answered with a failure. Requests beyond both are dropped, so that a client
// that floods the server, or stops reading, cannot pile up goroutines on it.
const maxDNSRejectQueue = 256

type dnsResult struct {
	data []byte
	err  error
}

// dnsClientState is the client half of in-session DNS.
type dnsClientState struct {
	// supported is set when the server's settings offered DNS. It is written
	// before ready is closed, so a reader that saw ready closed sees it.
	supported atomic.Bool
	ready     chan struct{}
	readyOnce sync.Once
	requestId atomic.Uint32

	pendingLock sync.Mutex
	pending     map[uint32]chan dnsResult
}

// dnsServerState is the server half of in-session DNS.
type dnsServerState struct {
	handler  DNSHandler
	ctx      context.Context
	cancel   context.CancelFunc
	inFlight chan struct{}
	rejects  chan uint32
}

// SetDNSHandler makes a server session offer DNS to clients and answer their
// queries with handler. It must be called before Run.
func (s *Session) SetDNSHandler(ctx context.Context, handler DNSHandler) {
	if handler == nil || s.isClient {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.dnsServer = &dnsServerState{
		handler:  handler,
		ctx:      ctx,
		cancel:   cancel,
		inFlight: make(chan struct{}, maxDNSInFlight),
		rejects:  make(chan uint32, maxDNSRejectQueue),
	}
	go s.rejectDNSLoop()
}

// DNSSupported reports whether the server offered DNS. It is false until the
// server's settings arrive.
func (s *Session) DNSSupported() bool {
	return s.dnsClient != nil && s.dnsClient.supported.Load()
}

// serverSettingsReceived reports whether the server's settings have arrived,
// which is when DNSSupported becomes final.
func (s *Session) serverSettingsReceived() bool {
	if s.dnsClient == nil {
		return false
	}
	select {
	case <-s.dnsClient.ready:
		return true
	default:
		return false
	}
}

// markServerSettings records the server's settings. It is called once from
// recvLoop when they arrive, and again harmlessly by Close.
func (s *Session) markServerSettings(dnsOffered bool) {
	if s.dnsClient == nil {
		return
	}
	if dnsOffered {
		s.dnsClient.supported.Store(true)
	}
	s.dnsClient.readyOnce.Do(func() {
		close(s.dnsClient.ready)
	})
}

// dnsBusy reports whether the client has DNS requests waiting for an answer
// on the session, which keeps pool maintenance from closing it.
func (s *Session) dnsBusy() bool {
	if s.dnsClient == nil {
		return false
	}
	s.dnsClient.pendingLock.Lock()
	defer s.dnsClient.pendingLock.Unlock()
	return len(s.dnsClient.pending) > 0
}

// closeDNS fails every request still waiting for an answer and cancels the
// handlers still running. It is called when the session closes.
func (s *Session) closeDNS() {
	if s.dnsServer != nil {
		s.dnsServer.cancel()
	}
	if s.dnsClient == nil {
		return
	}
	s.markServerSettings(false)
	s.dnsClient.pendingLock.Lock()
	pending := s.dnsClient.pending
	s.dnsClient.pending = make(map[uint32]chan dnsResult)
	s.dnsClient.pendingLock.Unlock()
	for _, ch := range pending {
		ch <- dnsResult{err: io.ErrClosedPipe}
	}
}

// exchangeDNS sends request to the server and waits for its answer. It
// returns io.ErrClosedPipe whenever the session closes before the answer, so
// that the caller can try another session.
func (s *Session) exchangeDNS(ctx context.Context, request []byte) ([]byte, error) {
	if s.dnsClient == nil {
		return nil, ErrDNSUnsupported
	}
	if len(request) == 0 {
		return nil, ErrDNSServerFailed
	}
	if len(request) > maxFrameDataLen {
		return nil, ErrDNSMessageTooLarge
	}
	select {
	case <-s.dnsClient.ready:
	case <-s.die:
		return nil, io.ErrClosedPipe
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	if !s.dnsClient.supported.Load() {
		return nil, ErrDNSUnsupported
	}

	ch := make(chan dnsResult, 1)
	s.dnsClient.pendingLock.Lock()
	select {
	case <-s.die:
		s.dnsClient.pendingLock.Unlock()
		return nil, io.ErrClosedPipe
	default:
	}
	var id uint32
	for {
		id = s.dnsClient.requestId.Add(1)
		if _, used := s.dnsClient.pending[id]; id != 0 && !used {
			break
		}
	}
	s.dnsClient.pending[id] = ch
	s.dnsClient.pendingLock.Unlock()

	unregister := func() {
		s.dnsClient.pendingLock.Lock()
		delete(s.dnsClient.pending, id)
		s.dnsClient.pendingLock.Unlock()
	}

	// The request waits its turn behind data frames rather than putting a
	// deadline on the whole connection as writeControlFrame does, which would
	// also fail a stream write blocked by ordinary backpressure. It is written
	// on its own goroutine so that the caller's deadline still applies.
	written := make(chan error, 1)
	go func() {
		written <- s.writeAsyncFrame(cmdDNSRequest, id, request)
	}()
	for {
		select {
		case err := <-written:
			if err != nil {
				// The connection is broken; nothing else can use it.
				s.Close()
				unregister()
				return nil, io.ErrClosedPipe
			}
			written = nil
		case result := <-ch:
			return result.data, result.err
		case <-ctx.Done():
			unregister()
			return nil, ctx.Err()
		case <-s.die:
			// Close fails pending requests; prefer an answer that raced it.
			select {
			case result := <-ch:
				if result.err == nil {
					return result.data, nil
				}
			default:
			}
			unregister()
			return nil, io.ErrClosedPipe
		}
	}
}

// handleDNSRequest takes a request read by recvLoop. It never blocks.
func (s *Session) handleDNSRequest(id uint32, request []byte) {
	if s.isClient || s.dnsServer == nil {
		return
	}
	if len(request) == 0 {
		s.rejectDNS(id)
		return
	}
	select {
	case s.dnsServer.inFlight <- struct{}{}:
		go s.serveDNS(id, request)
	default:
		s.rejectDNS(id)
	}
}

// rejectDNS queues a failure answer for a request the server will not handle,
// or drops the request when the queue is full.
func (s *Session) rejectDNS(id uint32) {
	select {
	case s.dnsServer.rejects <- id:
	default:
	}
}

// rejectDNSLoop answers rejected requests one at a time until the session
// closes, so that rejecting costs no goroutine per request.
func (s *Session) rejectDNSLoop() {
	for {
		select {
		case <-s.die:
			return
		case id := <-s.dnsServer.rejects:
			s.writeDNSResponse(id, nil)
		}
	}
}

func (s *Session) serveDNS(id uint32, request []byte) {
	defer func() { <-s.dnsServer.inFlight }()
	response, err := s.dnsServer.handler(s.dnsServer.ctx, request)
	if err != nil || len(response) > maxFrameDataLen {
		response = nil
	}
	s.writeDNSResponse(id, response)
}

func (s *Session) writeDNSResponse(id uint32, response []byte) {
	if s.IsClosed() {
		return
	}
	if err := s.writeAsyncFrame(cmdDNSResponse, id, response); err != nil {
		s.Close()
	}
}

// handleDNSResponse takes a response read by recvLoop. It never blocks.
func (s *Session) handleDNSResponse(id uint32, response []byte) {
	if !s.isClient || s.dnsClient == nil {
		return
	}
	s.dnsClient.pendingLock.Lock()
	ch, loaded := s.dnsClient.pending[id]
	delete(s.dnsClient.pending, id)
	s.dnsClient.pendingLock.Unlock()
	if !loaded {
		// The caller gave up before the answer arrived.
		return
	}
	if len(response) == 0 {
		ch <- dnsResult{err: ErrDNSServerFailed}
	} else {
		ch <- dnsResult{data: response}
	}
}

// ExchangeDNS sends a DNS message to the server over a session and returns
// the server's answer. It prefers an open session without streams, whose
// receive loop no stream can hold up, then the lowest latency; it waits for a
// session whose settings have not arrived yet, and dials one when there is
// none. A session that closes mid-query is retried once on another.
func (c *Client) ExchangeDNS(ctx context.Context, request []byte) ([]byte, error) {
	if len(request) > maxFrameDataLen {
		return nil, ErrDNSMessageTooLarge
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case <-c.die.Done():
			return nil, io.ErrClosedPipe
		default:
		}
		session, created, err := c.dnsSession(ctx)
		if err != nil {
			return nil, err
		}
		response, err := session.exchangeDNS(ctx, request)
		if created && c.disableReuse {
			session.Close()
		}
		if err == nil || !errors.Is(err, io.ErrClosedPipe) || ctx.Err() != nil {
			return response, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// dnsSession picks the session a DNS query goes on. It does not take the
// session out of the idle pool, so it never disturbs where streams go, but it
// marks the session used so that the idle timeout does not close it.
func (c *Client) dnsSession(ctx context.Context) (*Session, bool, error) {
	now := time.Now()
	var (
		best, pendingSettings *Session
		bestStreams           int
		unsupported           bool
	)
	c.sessionsLock.Lock()
	for _, session := range c.sessions {
		if session.IsClosed() || session.retired(now) {
			continue
		}
		if !session.serverSettingsReceived() {
			if pendingSettings == nil || session.seq > pendingSettings.seq {
				pendingSettings = session
			}
			continue
		}
		if !session.DNSSupported() {
			unsupported = true
			continue
		}
		streams := session.streamCount()
		if best == nil || (streams == 0) != (bestStreams == 0) && streams == 0 ||
			(streams == 0) == (bestStreams == 0) && preferred(session, best) {
			best, bestStreams = session, streams
		}
	}
	c.sessionsLock.Unlock()
	if best != nil {
		c.markDNSUse(best)
		return best, false, nil
	}
	if unsupported {
		// Every session goes to the same server, so a new one would not
		// offer DNS either.
		return nil, false, ErrDNSUnsupported
	}
	if pendingSettings != nil {
		c.markDNSUse(pendingSettings)
		return pendingSettings, false, nil
	}
	session, err := c.createSession(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create session: %w", err)
	}
	if c.metricsCallback != nil {
		c.metricsCallback.SessionCreated("dns")
	}
	if !c.disableReuse {
		// Pool it like a session made for ensure_idle_session, so that the
		// idle timeout closes it when nothing uses it. A session that already
		// closed has run its dieHook and must not enter the pool.
		c.idleSessionLock.Lock()
		if !session.IsClosed() {
			session.idleSince = time.Now()
			c.idleSession.Insert(math.MaxUint64-session.seq, session)
		}
		c.idleSessionLock.Unlock()
		c.updatePoolMetrics()
	}
	return session, true, nil
}

// markDNSUse restarts the idle time of a session a DNS query uses. The pool
// only reads idleSince under idleSessionLock.
func (c *Client) markDNSUse(session *Session) {
	c.idleSessionLock.Lock()
	session.idleSince = time.Now()
	c.idleSessionLock.Unlock()
}

func (s *Session) streamCount() int {
	s.streamLock.RLock()
	defer s.streamLock.RUnlock()
	return len(s.streams)
}
