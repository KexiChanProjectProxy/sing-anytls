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

// maxDNSPerSession bounds the DNS queries a client puts on one session. It
// stays below maxDNSInFlight, since a server frees a request's place only
// once it has written the answer, a little after the client received it.
const maxDNSPerSession = maxDNSInFlight - 8

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
	// abandoned holds the requests whose caller gave up before the answer,
	// with the function that gives the caller's DNS slot back once the server
	// is done with the request: when its answer arrives or the session
	// closes. It is protected by pendingLock.
	abandoned map[uint32]func()
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
	abandoned := s.dnsClient.abandoned
	s.dnsClient.abandoned = nil
	s.dnsClient.pendingLock.Unlock()
	for _, ch := range pending {
		ch <- dnsResult{err: io.ErrClosedPipe}
	}
	for _, release := range abandoned {
		release()
	}
}

// exchangeDNS sends request to the server and waits for its answer. It
// returns io.ErrClosedPipe whenever the session closes before the answer, so
// that the caller can try another session.
func (s *Session) exchangeDNS(ctx context.Context, request []byte) ([]byte, error) {
	return s.exchangeDNSSlot(ctx, request, nil, nil)
}

// exchangeDNSSlot is exchangeDNS for a query holding a DNS slot on the
// session, which release, when not nil, gives back exactly once. It is called
// on return, unless the caller gives up after the request was registered:
// the server still answers it then, so the slot is given back only when that
// answer arrives or the session closes, and a later query is not admitted
// beyond what the server answers at once. onPark, when not nil, is called
// under pendingLock when that happens, before release can run.
func (s *Session) exchangeDNSSlot(ctx context.Context, request []byte, release, onPark func()) (_ []byte, err error) {
	held := false
	defer func() {
		if !held && release != nil {
			release()
		}
	}()
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
	if err := ctx.Err(); err != nil {
		// Don't send a query whose caller already gave up.
		return nil, err
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
		_, used := s.dnsClient.pending[id]
		_, waiting := s.dnsClient.abandoned[id]
		if id != 0 && !used && !waiting {
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
		err := s.writeAsyncFrame(cmdDNSRequest, id, request)
		if err != nil {
			// The connection is broken; nothing else can use it. Closing it
			// here too gives back the slot of a caller that already gave up.
			s.Close()
		}
		written <- err
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
			s.dnsClient.pendingLock.Lock()
			if _, ok := s.dnsClient.pending[id]; ok {
				delete(s.dnsClient.pending, id)
				if release != nil && s.dnsClient.abandoned != nil {
					if onPark != nil {
						onPark()
					}
					s.dnsClient.abandoned[id] = release
					held = true
				}
			}
			s.dnsClient.pendingLock.Unlock()
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
	release := s.dnsClient.abandoned[id]
	delete(s.dnsClient.abandoned, id)
	s.dnsClient.pendingLock.Unlock()
	if !loaded {
		// The caller gave up before the answer arrived.
		if release != nil {
			release()
		}
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
// none or every session already carries as many queries as a server answers
// at once. Concurrent queries that need a new session share a single dial. A
// session that closes mid-query is retried once on another.
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
		session, err := c.dnsSession(ctx)
		if err != nil {
			return nil, err
		}
		var parked atomic.Bool
		response, err := session.exchangeDNSSlot(ctx, request, func() {
			if parked.Load() {
				session.dnsParked.Add(-1)
			}
			c.releaseDNS(session)
		}, func() {
			parked.Store(true)
			session.dnsParked.Add(1)
		})
		if parked.Load() {
			c.closeIfOnlyParked(session)
		}
		if err == nil || !errors.Is(err, io.ErrClosedPipe) || ctx.Err() != nil {
			return response, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// dnsSlotsClosing is stored in Session.dnsUsers when the last query on a
// session dialed for DNS closes it, so that no query can take a slot on it.
const dnsSlotsClosing = math.MinInt32

// dnsSlotFree reports whether the session has a DNS slot free.
func (s *Session) dnsSlotFree() bool {
	n := s.dnsUsers.Load()
	return n >= 0 && n < maxDNSPerSession
}

// acquireDNS takes one of the session's DNS slots for a query, and reports
// false when the session already carries maxDNSPerSession queries, about as
// many as the server answers at once, or is closing. The query gives the slot back
// with Client.releaseDNS.
func (s *Session) acquireDNS() bool {
	for {
		n := s.dnsUsers.Load()
		if n < 0 || n >= maxDNSPerSession {
			return false
		}
		if s.dnsUsers.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// releaseDNS gives back a DNS slot taken on session.
//
// Without reuse no pool maintenance runs, so a session dialed for DNS is
// shared by the queries that overlap it and closed by the last of them, which
// first marks it closing so that no other query takes a slot on it.
func (c *Client) releaseDNS(session *Session) {
	session.dnsUsers.Add(-1)
	if c.closeIfOnlyParked(session) {
		return
	}
	if c.dnsDialActive.Load() && !session.IsClosed() {
		// Queries waiting for a dial because every session was full can use
		// the slot now.
		c.dnsDialLock.Lock()
		if dial := c.dnsDialing; dial != nil && dial.waiters > 0 {
			close(dial.kick)
			dial.kick = make(chan struct{})
		}
		c.dnsDialLock.Unlock()
	}
}

// closeIfOnlyParked closes a session dialed for DNS without reuse once only
// queries whose callers gave up hold slots on it, which also stops the
// server's work on them, so that a server that never answers cannot keep the
// connection open. It reports whether it closed the session.
func (c *Client) closeIfOnlyParked(session *Session) bool {
	if !c.disableReuse || !session.dnsDialed.Load() {
		return false
	}
	for {
		n := session.dnsUsers.Load()
		if n < 0 || n != session.dnsParked.Load() {
			return false
		}
		if session.dnsUsers.CompareAndSwap(n, dnsSlotsClosing) {
			session.Close()
			return true
		}
	}
}

// HasIdleDNSSession reports whether a DNS query would go on an established
// session without dialing or waiting for one: an open session that isn't
// retired, whose settings have arrived with DNS offered, that carries no
// stream and has a DNS slot free. Queries already in flight on the session
// don't otherwise count against it, since DNS queries share a session, each
// under its own request id. It is a best-effort hint and doesn't change any
// state.
func (c *Client) HasIdleDNSSession() bool {
	now := time.Now()
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	for _, session := range c.sessions {
		if session.IsClosed() || session.retired(now) || session.probing.Load() ||
			!session.serverSettingsReceived() || !session.DNSSupported() {
			continue
		}
		if session.streamCount() == 0 && session.dnsSlotFree() {
			return true
		}
	}
	return false
}

// dnsDial is a session dial that DNS queries wait for. Its fields other than
// done are protected by Client.dnsDialLock.
type dnsDial struct {
	// done is closed when the dial has finished.
	done chan struct{}
	// kick is closed, and replaced, when a DNS slot frees up on a session
	// while queries wait, so that they look for a session again.
	kick chan struct{}
	// waiters counts the queries waiting for the dial.
	waiters int
	// finished is set when the dial has finished, together with the fields
	// below.
	finished bool
	// session is the dialed session and err the dial error.
	session *Session
	err     error
	// reserved counts the slots on session taken for waiting queries and not
	// yet claimed by one.
	reserved int
	// abandoned is set when the dial failed because the query that started
	// it gave up, so that a waiting query with time left dials again instead
	// of failing with it.
	abandoned bool
}

// dnsSession picks the session a DNS query goes on, dialing one when there is
// none with a free DNS slot, and takes a slot on it, see acquireDNS. It does
// not take the session out of the idle pool, so it never disturbs where
// streams go, but it marks the session used so that the idle timeout does not
// close it.
//
// Only one dial runs at a time: queries that need a session while one is
// running wait for it and then use the session it made, so that a burst of
// queries opens a single connection rather than one each.
func (c *Client) dnsSession(ctx context.Context) (*Session, error) {
	for {
		select {
		case <-c.die.Done():
			return nil, io.ErrClosedPipe
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		session, err := c.pickDNSSession()
		if session != nil || err != nil {
			return session, err
		}

		c.dnsDialLock.Lock()
		dial := c.dnsDialing
		if dial == nil {
			// Look again under the lock: a dial may have finished since.
			session, err = c.pickDNSSession()
			if session != nil || err != nil {
				c.dnsDialLock.Unlock()
				return session, err
			}
			dial = &dnsDial{done: make(chan struct{}), kick: make(chan struct{})}
			c.dnsDialing = dial
			c.dnsDialActive.Store(true)
			c.dnsDialLock.Unlock()
			session, err = c.dialDNSSession(ctx, dial)
			if err != nil {
				return nil, c.dialError(err)
			}
			return session, nil
		}
		// Look again under the lock: a slot may have freed up since, and a
		// slot freed from now on wakes this query through kick.
		session, err = c.pickDNSSession()
		if session != nil || err != nil {
			c.dnsDialLock.Unlock()
			return session, err
		}
		dial.waiters++
		kick := dial.kick
		c.dnsDialLock.Unlock()

		select {
		case <-kick:
			c.leaveDNSDial(dial)
			continue
		case <-dial.done:
		case <-ctx.Done():
			c.leaveDNSDial(dial)
			return nil, ctx.Err()
		case <-c.die.Done():
			c.leaveDNSDial(dial)
			return nil, io.ErrClosedPipe
		}

		c.dnsDialLock.Lock()
		if dial.reserved > 0 {
			dial.reserved--
			session = dial.session
			c.dnsDialLock.Unlock()
			c.markDNSUse(session)
			return session, nil
		}
		c.dnsDialLock.Unlock()

		if dial.err == nil && dial.session != nil && dial.session.IsClosed() {
			// The new session died at once. Fail like a query that got it,
			// which ExchangeDNS retries once, rather than dialing again and
			// again until the deadline.
			session, err = c.pickDNSSession()
			if session != nil || err != nil {
				return session, err
			}
			return nil, io.ErrClosedPipe
		}
		if dial.err != nil && !dial.abandoned {
			// A session may have opened another way meanwhile, such as for a
			// stream.
			session, err = c.pickDNSSession()
			if session != nil || err != nil {
				return session, err
			}
			return nil, c.dialError(dial.err)
		}
		// The dial was abandoned, or its session closed or filled up: look
		// for a session again, and dial if there is still none.
	}
}

// dialError returns the error of a query whose session dial failed with err:
// io.ErrClosedPipe when the client closed, which stops the dial.
func (c *Client) dialError(err error) error {
	select {
	case <-c.die.Done():
		return io.ErrClosedPipe
	default:
		return fmt.Errorf("failed to create session: %w", err)
	}
}

// leaveDNSDial undoes a query's wait for dial when the query gives up, and
// gives back the slot reserved for it if the dial already finished.
func (c *Client) leaveDNSDial(dial *dnsDial) {
	c.dnsDialLock.Lock()
	if !dial.finished {
		dial.waiters--
		c.dnsDialLock.Unlock()
		return
	}
	if dial.reserved == 0 {
		c.dnsDialLock.Unlock()
		return
	}
	dial.reserved--
	session := dial.session
	c.dnsDialLock.Unlock()
	c.releaseDNS(session)
}

// dialDNSSession dials a session for DNS as the dial that other queries wait
// for, and returns it with a DNS slot taken. The queries waiting for it when
// it finishes get slots reserved on it, as many as it has.
func (c *Client) dialDNSSession(ctx context.Context, dial *dnsDial) (session *Session, err error) {
	defer func() {
		// Deferred, so that waiting queries are released even if the dial
		// panics.
		c.dnsDialLock.Lock()
		dial.finished = true
		dial.session, dial.err = session, err
		dial.abandoned = err != nil && ctx.Err() != nil
		if session != nil && !session.IsClosed() {
			for dial.reserved < dial.waiters && session.acquireDNS() {
				dial.reserved++
			}
		}
		c.dnsDialing = nil
		c.dnsDialActive.Store(false)
		c.dnsDialLock.Unlock()
		close(dial.done)
	}()

	// Stop the dial when the client closes too: the queries waiting for it
	// cannot dial themselves meanwhile.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.die, cancel)
	defer stop()

	session, err = c.createSessionWith(dialCtx, func(session *Session) {
		// Take the slot before other queries can find the session.
		session.dnsDialed.Store(true)
		session.dnsUsers.Store(1)
	})
	if err != nil {
		return nil, err
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
	return session, nil
}

// pickDNSSession returns the open session a DNS query should use with a DNS
// slot taken on it, nil when there is none with a free slot, or
// ErrDNSUnsupported when the server does not answer DNS.
func (c *Client) pickDNSSession() (*Session, error) {
	for {
		session, err := c.bestDNSSession()
		if session == nil || err != nil {
			return nil, err
		}
		if session.acquireDNS() {
			c.markDNSUse(session)
			return session, nil
		}
		// Another query took the last slot since: look again.
	}
}

// bestDNSSession returns the open session with a free DNS slot that a query
// should use, nil when there is none, or ErrDNSUnsupported when the server
// does not answer DNS.
func (c *Client) bestDNSSession() (*Session, error) {
	now := time.Now()
	var (
		best, pendingSettings  *Session
		bestStreams            int
		unsupported, supported bool
	)
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	for _, session := range c.sessions {
		if session.IsClosed() || session.retired(now) || session.probing.Load() {
			// A probing session is full of filler a query would wait behind.
			continue
		}
		if !session.serverSettingsReceived() {
			if session.dnsSlotFree() &&
				(pendingSettings == nil || session.seq > pendingSettings.seq) {
				pendingSettings = session
			}
			continue
		}
		if !session.DNSSupported() {
			unsupported = true
			continue
		}
		supported = true
		if !session.dnsSlotFree() {
			continue
		}
		streams := session.streamCount()
		if best == nil || (streams == 0) != (bestStreams == 0) && streams == 0 ||
			(streams == 0) == (bestStreams == 0) && preferred(session, best) {
			best, bestStreams = session, streams
		}
	}
	if best != nil {
		return best, nil
	}
	if unsupported && !supported {
		// Every session goes to the same server, so a new one would not
		// offer DNS either.
		return nil, ErrDNSUnsupported
	}
	return pendingSettings, nil
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
