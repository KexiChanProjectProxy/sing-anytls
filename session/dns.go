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
// verbatim. ctx carries the connection's context and is cancelled when the
// session closes. It is called on its own goroutine.
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
// A request beyond it is answered with an empty response straight away, so
// that a client cannot pile up goroutines on the server.
const maxDNSInFlight = 64

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
	inFlight chan struct{}
}

// SetDNSHandler makes a server session offer DNS to clients and answer their
// queries with handler. It must be called before Run.
func (s *Session) SetDNSHandler(ctx context.Context, handler DNSHandler) {
	if handler == nil {
		return
	}
	s.dnsServer = &dnsServerState{
		handler:  handler,
		ctx:      ctx,
		inFlight: make(chan struct{}, maxDNSInFlight),
	}
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

// failPendingDNS fails every request still waiting for an answer. It is
// called when the session closes.
func (s *Session) failPendingDNS() {
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

// exchangeDNS sends request to the server and waits for its answer.
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
	if !s.dnsClient.supported.Load() {
		if s.IsClosed() {
			return nil, io.ErrClosedPipe
		}
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

	f := newFrame(cmdDNSRequest, id)
	f.data = request
	if _, err := s.writeControlFrame(f); err != nil {
		unregister()
		return nil, err
	}

	select {
	case result := <-ch:
		return result.data, result.err
	case <-ctx.Done():
		unregister()
		return nil, ctx.Err()
	case <-s.die:
		// Close fails pending requests; prefer an answer that raced it.
		select {
		case result := <-ch:
			return result.data, result.err
		default:
		}
		unregister()
		return nil, io.ErrClosedPipe
	}
}

// handleDNSRequest takes a request read by recvLoop. It never blocks.
func (s *Session) handleDNSRequest(id uint32, request []byte) {
	if s.isClient || s.dnsServer == nil || len(request) == 0 {
		return
	}
	select {
	case s.dnsServer.inFlight <- struct{}{}:
		go s.serveDNS(id, request)
	default:
		go s.writeDNSResponse(id, nil)
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
// the server's answer. It uses the open session with the lowest latency that
// offered DNS, waits for a session whose settings have not arrived yet, and
// dials one when there is none. A session that closes mid-query is retried
// once on another.
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
// session out of the idle pool, so it never disturbs where streams go.
func (c *Client) dnsSession(ctx context.Context) (*Session, bool, error) {
	now := time.Now()
	var best, pendingSettings *Session
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
			continue
		}
		if best == nil || preferred(session, best) {
			best = session
		}
	}
	c.sessionsLock.Unlock()
	if best != nil {
		return best, false, nil
	}
	if pendingSettings != nil {
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
		// idle timeout closes it when nothing uses it.
		c.idleSessionLock.Lock()
		session.idleSince = time.Now()
		c.idleSession.Insert(math.MaxUint64-session.seq, session)
		c.idleSessionLock.Unlock()
		c.updatePoolMetrics()
	}
	return session, true, nil
}
