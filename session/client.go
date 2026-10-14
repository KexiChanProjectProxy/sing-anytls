package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/internal/skiplist"
	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]

	idleSessionTimeout          time.Duration
	maxConnectionLifetime       time.Duration
	connectionLifetimeJitter    time.Duration
	minIdleSession              int
	minIdleSessionForAge        int
	ensureIdleSession           int
	ensureIdleSessionCreateRate int
	heartbeat                   time.Duration
	disableReuse                bool
	clientMetadata              string
	// closeAfterIdle and closeAfterLifetime retire sessions regardless of the
	// pool's own limits and protections; zero disables each.
	closeAfterIdle     time.Duration
	closeAfterLifetime time.Duration

	logger          logger.Logger
	metricsCallback MetricsCallback

	statsHandler  atomic.TypedValue[StatsHandler]
	selectHandler atomic.TypedValue[SelectHandler]
}

// SelectHandler is told which session a new stream was placed on. It is
// called from CreateStream with the caller's context and must not block.
type SelectHandler func(ctx context.Context, info SessionInfo)

// SessionInfo describes the session a stream was placed on, as it was when
// the stream opened.
type SessionInfo struct {
	// Seq numbers the client's sessions from 1.
	Seq uint64
	// Reused is true when the session came from the idle pool, false when it
	// was dialed for this stream.
	Reused bool
	// IdleFor is how long a reused session sat in the pool.
	IdleFor time.Duration
	Latency Latency
	// Streams counts the streams opened on the session, this one included.
	Streams   uint64
	CreatedAt time.Time
	// MaxLifetime is the session's max_connection_lifetime with jitter, and
	// ExpiresAt the time it is reached; both are zero without a limit. An
	// expired session is still used until age cleanup finds it idle.
	MaxLifetime time.Duration
	ExpiresAt   time.Time
	// RetireAt is when the session stops being reused under
	// close_after_lifetime, or zero without that limit.
	RetireAt time.Time
	// IdleSessions and TotalSessions describe the pool after the pick.
	IdleSessions  int
	TotalSessions int
}

// Age is how long the session has existed at now.
func (i SessionInfo) Age(now time.Time) time.Duration {
	return now.Sub(i.CreatedAt)
}

// LifetimeLeft is the time until ExpiresAt, negative once it has passed, and
// false without a lifetime limit.
func (i SessionInfo) LifetimeLeft(now time.Time) (time.Duration, bool) {
	if i.ExpiresAt.IsZero() {
		return 0, false
	}
	return i.ExpiresAt.Sub(now), true
}

// SetSessionRetirement sets two limits applied to every session regardless
// of min_idle_session, ensure_idle_session and min_idle_session_for_age:
// a session idle for longer than closeAfterIdle is closed, and a session older
// than closeAfterLifetime, less up to a tenth of it at random, is no longer
// handed out and closes once it is idle. Retirement never interrupts a stream.
// Zero disables a limit. It must be called before the first stream.
func (c *Client) SetSessionRetirement(closeAfterIdle, closeAfterLifetime time.Duration) {
	c.closeAfterIdle = closeAfterIdle
	c.closeAfterLifetime = closeAfterLifetime
}

// SetSelectHandler reports every stream's session to handler from now on.
func (c *Client) SetSelectHandler(handler SelectHandler) {
	c.selectHandler.Store(handler)
}

// SetStatsHandler makes sessions opened from now on ask the server for its
// statistics and deliver them to handler. Sessions already open are not
// affected.
func (c *Client) SetStatsHandler(handler StatsHandler) {
	c.statsHandler.Store(handler)
}

func NewClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout, maxConnectionLifetime, connectionLifetimeJitter time.Duration, minIdleSession, minIdleSessionForAge, ensureIdleSession, ensureIdleSessionCreateRate int, heartbeat time.Duration, disableReuse bool, metricsCallback MetricsCallback, clientMetadata string,
) *Client {
	c := &Client{
		sessions:                    make(map[uint64]*Session),
		dialOut:                     dialOut,
		padding:                     _padding,
		idleSessionTimeout:          idleSessionTimeout,
		maxConnectionLifetime:       maxConnectionLifetime,
		connectionLifetimeJitter:    connectionLifetimeJitter,
		minIdleSession:              minIdleSession,
		minIdleSessionForAge:        minIdleSessionForAge,
		ensureIdleSession:           ensureIdleSession,
		ensureIdleSessionCreateRate: ensureIdleSessionCreateRate,
		heartbeat:                   heartbeat,
		disableReuse:                disableReuse,
		clientMetadata:              clientMetadata,
		logger:                      logger,
		metricsCallback:             metricsCallback,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	if !c.disableReuse {
		go func() {
			// Wait on the ticker and on close together, so that closing the
			// client stops this goroutine at once rather than after the next
			// check interval.
			ticker := time.NewTicker(idleSessionCheckInterval)
			defer ticker.Stop()
			for {
				select {
				case <-c.die.Done():
					return
				case <-ticker.C:
				}
				c.retireCleanup()
				c.idleCleanup()
				c.ageCleanup()
				c.ensureIdleSessionPool()
			}
		}()
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	sessionCreated := false
	var idleFor time.Duration
	if !c.disableReuse {
		session = c.getIdleSession()
		if session != nil {
			idleFor = time.Since(session.idleSince)
		}
	}
	if session == nil {
		session, err = c.createSession(ctx)
		sessionCreated = true
	}
	if session == nil {
		if c.metricsCallback != nil {
			c.metricsCallback.StreamError()
		}
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Report session creation for on-demand sessions
	if sessionCreated && c.metricsCallback != nil {
		c.metricsCallback.SessionCreated("demand")
		c.updatePoolMetrics()
	}

	stream, err = session.OpenStream()
	if err != nil {
		session.Close()
		if c.metricsCallback != nil {
			c.metricsCallback.StreamError()
		}
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	streams := session.streamsOpened.Add(1)

	// Report stream opened
	if c.metricsCallback != nil {
		c.metricsCallback.StreamOpened()
	}
	if handler := c.selectHandler.Load(); handler != nil {
		handler(ctx, c.sessionInfo(session, !sessionCreated, idleFor, streams))
	}

	stream.dieHook = func() {
		// Report stream closed
		if c.metricsCallback != nil {
			c.metricsCallback.StreamClosed()
		}

		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			if c.disableReuse {
				session.Close()
				return
			}
			if session.retired(time.Now()) {
				// Its stream was the only thing keeping a retired session open.
				c.closeRetired(session, retireReasonLifetime, "its stream ended")
				return
			}

			select {
			case <-c.die.Done():
				// Now client has been closed
				session.Close()
			default:
				c.idleSessionLock.Lock()
				session.idleSince = time.Now()
				c.idleSession.Insert(math.MaxUint64-session.seq, session)
				c.idleSessionLock.Unlock()

				// Update pool metrics when session becomes idle
				c.updatePoolMetrics()
			}
		}
	}

	return stream, nil
}

// IdleLatency returns the smoothed latency of the session the next stream
// would be placed on: the lowest among measured idle sessions. It returns false
// when no idle session has been measured, in which case the next stream would
// take an unmeasured session or dial a new one.
func (c *Client) IdleLatency() (time.Duration, bool) {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	var best time.Duration
	found := false
	now := time.Now()
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		session := it.Value()
		if session.IsClosed() || session.retired(now) {
			continue
		}
		latency := session.Latency()
		if latency.Samples == 0 {
			continue
		}
		if !found || latency.Smoothed < best {
			best, found = latency.Smoothed, true
		}
	}
	return best, found
}

// getIdleSession takes the preferred idle session out of the pool: the one
// with the lowest measured latency, or the newest when none is measured.
func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	var idleKey uint64
	var retired []*Session
	now := time.Now()
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		session := it.Value()
		// A closed session is removed by its dieHook shortly; never hand it out.
		if session.IsClosed() {
			continue
		}
		if session.retired(now) {
			retired = append(retired, session)
			continue
		}
		if idle == nil || preferred(session, idle) {
			idle, idleKey = session, it.Key()
		}
	}
	if idle != nil {
		c.idleSession.Remove(idleKey)
	}
	for _, session := range retired {
		c.idleSession.Remove(math.MaxUint64 - session.seq)
	}
	idleCount := c.idleSession.Len()
	c.idleSessionLock.Unlock()
	for _, session := range retired {
		c.closeRetired(session, retireReasonLifetime, "idle "+now.Sub(session.idleSince).String())
	}
	if idle != nil {
		latency := idle.Latency()
		c.logger.Trace(fmt.Sprintf("[Pool] Picked session seq=%d (srtt=%v, samples=%d, idle left=%d)",
			idle.seq, latency.Smoothed, latency.Samples, idleCount))
	}
	return
}

// preferred reports whether a should be handed out before b. A measured
// session comes before an unmeasured one, then the lower smoothed latency, and
// between equals the newer session, which is the order without measurements.
func preferred(a, b *Session) bool {
	return comparePreference(a.seq, a.Latency(), b.seq, b.Latency()) < 0
}

// comparePreference orders sessions from most to least preferred.
func comparePreference(aSeq uint64, a Latency, bSeq uint64, b Latency) int {
	aMeasured, bMeasured := a.Samples > 0, b.Samples > 0
	switch {
	case aMeasured != bMeasured:
		if aMeasured {
			return -1
		}
		return 1
	case aMeasured && a.Smoothed != b.Smoothed:
		if a.Smoothed < b.Smoothed {
			return -1
		}
		return 1
	case aSeq > bSeq:
		return -1
	case aSeq < bSeq:
		return 1
	default:
		return 0
	}
}

func (c *Client) sessionInfo(session *Session, reused bool, idleFor time.Duration, streams uint64) SessionInfo {
	info := SessionInfo{
		Seq:         session.seq,
		Reused:      reused,
		IdleFor:     idleFor,
		Latency:     session.Latency(),
		Streams:     streams,
		CreatedAt:   session.createdAt,
		MaxLifetime: session.maxLifetime,
		RetireAt:    session.retireAt,
	}
	if session.maxLifetime > 0 {
		info.ExpiresAt = session.createdAt.Add(session.maxLifetime)
	}
	c.idleSessionLock.Lock()
	info.IdleSessions = c.idleSession.Len()
	c.idleSessionLock.Unlock()
	c.sessionsLock.Lock()
	info.TotalSessions = len(c.sessions)
	c.sessionsLock.Unlock()
	return info
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.logger, c.heartbeat, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	session.statsHandler = c.statsHandler.Load()
	session.createdAt = time.Now()
	if c.closeAfterLifetime > 0 {
		session.retireAt = session.createdAt.Add(retirementLifetime(c.closeAfterLifetime))
	}

	if c.maxConnectionLifetime > 0 {
		session.maxLifetime = jitteredLifetime(c.maxConnectionLifetime, c.connectionLifetimeJitter)
	}

	session.dieHook = func() {
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	select {
	case <-c.die.Done():
		// The client closed while this session was being dialed, after Close
		// took its snapshot of sessions, so nothing else would close it.
		c.sessionsLock.Unlock()
		session.Close()
		return nil, io.ErrClosedPipe
	default:
	}
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

// updatePoolMetrics reports current pool status to metrics callback
func (c *Client) updatePoolMetrics() {
	if c.metricsCallback == nil {
		return
	}

	c.idleSessionLock.Lock()
	idleCount := c.idleSession.Len()
	c.idleSessionLock.Unlock()

	c.sessionsLock.Lock()
	totalCount := len(c.sessions)
	c.sessionsLock.Unlock()

	activeCount := totalCount - idleCount
	c.metricsCallback.SessionPoolUpdate(idleCount, activeCount, totalCount)
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	now := time.Now()

	type sessionInfo struct {
		session  *Session
		key      uint64
		idleTime time.Duration
		latency  Latency
	}
	var expired []sessionInfo
	activeCount := 0

	c.idleSessionLock.Lock()
	currentIdleCount := c.idleSession.Len()
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		session := it.Value()
		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}
		expired = append(expired, sessionInfo{
			session:  session,
			key:      it.Key(),
			idleTime: now.Sub(session.idleSince),
			latency:  session.Latency(),
		})
	}

	// min_idle_session keeps the preferred expired sessions: the lowest
	// latency ones, which are also the ones streams are placed on.
	slices.SortFunc(expired, func(a, b sessionInfo) int {
		return comparePreference(a.session.seq, a.latency, b.session.seq, b.latency)
	})
	protectedCount := min(max(c.minIdleSession-activeCount, 0), len(expired))
	for _, s := range expired[:protectedCount] {
		s.session.idleSince = now
	}
	sessionToClose := expired[protectedCount:]
	for _, s := range sessionToClose {
		c.idleSession.Remove(s.key)
	}
	c.idleSessionLock.Unlock()

	// Log cleanup activity if there are sessions to close or sessions were protected
	if len(sessionToClose) > 0 || protectedCount > 0 {
		if protectedCount > 0 {
			c.logger.Debug(fmt.Sprintf("[IdleCleanup] Found %d expired sessions (timeout=%v), closing %d (keeping %d lowest-latency to maintain min_idle_session=%d, current=%d)",
				len(expired), c.idleSessionTimeout, len(sessionToClose), protectedCount, c.minIdleSession, currentIdleCount))
		} else {
			c.logger.Debug(fmt.Sprintf("[IdleCleanup] Found %d expired sessions (timeout=%v), closing all (current=%d)",
				len(sessionToClose), c.idleSessionTimeout, currentIdleCount))
		}
	}

	for i, s := range sessionToClose {
		c.logger.Debug(fmt.Sprintf("[IdleCleanup] Closing session #%d (seq=%d, idle=%v, idleSince=%v, latency=%v, samples=%d)",
			i+1, s.session.seq, s.idleTime, s.session.idleSince, s.latency.Smoothed, s.latency.Samples))

		// Report session closure metrics
		if c.metricsCallback != nil {
			age := now.Sub(s.session.createdAt).Seconds()
			c.metricsCallback.SessionClosed("idle_timeout", age)
		}

		s.session.Close()
	}

	// Update pool metrics after cleanup
	if len(sessionToClose) > 0 {
		c.updatePoolMetrics()
	}
}

// ensureIdleSessionPool ensures that at least ensureIdleSession idle sessions exist in the pool.
// If the current count is below the target, it creates new sessions asynchronously.
func (c *Client) ensureIdleSessionPool() {
	// Feature disabled if ensureIdleSession is 0
	if c.ensureIdleSession <= 0 {
		return
	}

	// Check if client is closing
	select {
	case <-c.die.Done():
		return
	default:
	}

	// Count current idle sessions
	c.idleSessionLock.Lock()
	currentIdleCount := c.idleSession.Len()
	c.idleSessionLock.Unlock()

	// Calculate how many sessions we need to create
	deficit := c.ensureIdleSession - currentIdleCount
	if deficit <= 0 {
		return
	}

	// Report deficit metrics
	if c.metricsCallback != nil {
		c.metricsCallback.EnsureIdleDeficit(deficit)
	}

	// Apply rate limiting if configured
	toCreate := deficit
	if c.ensureIdleSessionCreateRate > 0 && deficit > c.ensureIdleSessionCreateRate {
		toCreate = c.ensureIdleSessionCreateRate
		c.logger.Trace(fmt.Sprintf("[EnsureIdleSession] Current idle sessions: %d, target: %d, deficit=%d, rate-limited to creating %d sessions (will create %d more in next cycle)",
			currentIdleCount, c.ensureIdleSession, deficit, toCreate, deficit-toCreate))
	} else {
		c.logger.Trace(fmt.Sprintf("[EnsureIdleSession] Current idle sessions: %d, target: %d, creating %d new sessions",
			currentIdleCount, c.ensureIdleSession, toCreate))
	}

	// Report how many we're creating this cycle
	if c.metricsCallback != nil {
		c.metricsCallback.EnsureIdleCreatedCycle(toCreate)
	}

	// Create sessions asynchronously to not block the periodic check
	for i := 0; i < toCreate; i++ {
		go func(index int) {
			// Check if client is closing before creating
			select {
			case <-c.die.Done():
				return
			default:
			}

			// Create session with background context (not tied to any specific stream request)
			session, err := c.createSession(context.Background())
			if err != nil {
				c.logger.Trace(fmt.Sprintf("[EnsureIdleSession] Failed to create session #%d: %v", index+1, err))
				return
			}

			// Immediately add to idle pool
			c.idleSessionLock.Lock()
			session.idleSince = time.Now()
			c.idleSession.Insert(math.MaxUint64-session.seq, session)
			c.idleSessionLock.Unlock()

			// Report session creation for ensure_idle
			if c.metricsCallback != nil {
				c.metricsCallback.SessionCreated("ensure_idle")
				c.updatePoolMetrics()
			}

			c.logger.Trace(fmt.Sprintf("[EnsureIdleSession] Successfully created and pooled session #%d (seq=%d)",
				index+1, session.seq))
		}(i)
	}
}

// ageCleanup closes idle sessions that have exceeded their maximum lifetime.
// The highest-latency ones are closed first, unmeasured ones before them and
// the oldest between equals, while respecting min_idle_session_for_age.
func (c *Client) ageCleanup() {
	// Feature disabled if maxConnectionLifetime is 0
	if c.maxConnectionLifetime <= 0 {
		return
	}

	now := time.Now()

	type sessionToClose struct {
		session   *Session
		key       uint64
		createdAt time.Time
		age       time.Duration
		maxLife   time.Duration
		latency   Latency
	}

	var expiredSessions []sessionToClose
	var keptCount int

	// Collect all idle sessions that have exceeded their individual max lifetime
	c.idleSessionLock.Lock()
	currentIdleCount := c.idleSession.Len()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		// Check if session has exceeded its individual max lifetime
		if session.maxLifetime > 0 {
			age := now.Sub(session.createdAt)
			if age >= session.maxLifetime {
				expiredSessions = append(expiredSessions, sessionToClose{
					session:   session,
					key:       key,
					createdAt: session.createdAt,
					age:       age,
					maxLife:   session.maxLifetime,
					latency:   session.Latency(),
				})
			}
		}
	}
	c.idleSessionLock.Unlock()

	// If no expired sessions, nothing to do
	if len(expiredSessions) == 0 {
		return
	}

	// Order by retirement: unmeasured first, then the highest latency, then
	// the oldest. The sessions kept are the ones streams are placed on.
	slices.SortFunc(expiredSessions, func(a, b sessionToClose) int {
		return compareRetirement(a.latency, a.createdAt, b.latency, b.createdAt)
	})

	// Calculate how many sessions we can safely close while respecting min_idle_session_for_age
	maxCanClose := currentIdleCount - c.minIdleSessionForAge
	if maxCanClose <= 0 {
		c.logger.Debug(fmt.Sprintf("[AgeCleanup] Found %d expired sessions, but skipping cleanup to maintain min_idle_session_for_age=%d (current=%d)",
			len(expiredSessions), c.minIdleSessionForAge, currentIdleCount))
		return
	}

	// Limit to closing only what we can afford
	sessionsToClose := expiredSessions
	if len(expiredSessions) > maxCanClose {
		sessionsToClose = expiredSessions[:maxCanClose]
		keptCount = len(expiredSessions) - maxCanClose
	}

	c.logger.Debug(fmt.Sprintf("[AgeCleanup] Found %d expired sessions, closing %d highest-latency (keeping %d to maintain min_idle_session_for_age=%d)",
		len(expiredSessions), len(sessionsToClose), keptCount, c.minIdleSessionForAge))

	// Close sessions starting from oldest
	c.idleSessionLock.Lock()
	closed := 0
	for i, s := range sessionsToClose {
		// The lock was released after collecting, so a session may have been
		// handed to a new stream since. Only close it if it is still idle.
		if !c.idleSession.Remove(s.key) {
			continue
		}
		closed++
		c.logger.Debug(fmt.Sprintf("[AgeCleanup] Closing session #%d (seq=%d, age=%v, maxLife=%v, created=%v, latency=%v, samples=%d)",
			i+1, s.session.seq, s.age, s.maxLife, s.session.createdAt, s.latency.Smoothed, s.latency.Samples))

		// Report session closure metrics
		if c.metricsCallback != nil {
			c.metricsCallback.SessionClosed("max_age", s.age.Seconds())
		}

		// Close outside the lock to avoid blocking
		go s.session.Close()
	}
	c.idleSessionLock.Unlock()

	// Update pool metrics after cleanup
	if closed > 0 {
		c.updatePoolMetrics()
	}
}

// compareRetirement orders sessions from first to last to close: unmeasured
// before measured, then higher smoothed latency first, then older first.
func compareRetirement(a Latency, aCreated time.Time, b Latency, bCreated time.Time) int {
	aMeasured, bMeasured := a.Samples > 0, b.Samples > 0
	switch {
	case aMeasured != bMeasured:
		if !aMeasured {
			return -1
		}
		return 1
	case aMeasured && a.Smoothed != b.Smoothed:
		if a.Smoothed > b.Smoothed {
			return -1
		}
		return 1
	default:
		return aCreated.Compare(bCreated)
	}
}

// Reasons a session is retired, as reported to logs and metrics.
const (
	retireReasonIdle     = "close_after_idle"
	retireReasonLifetime = "close_after_lifetime"
)

// retirementLifetime draws a session's lifetime under close_after_lifetime
// uniformly from [0.9, 1] of it, so that sessions created together, such as an
// ensure_idle_session batch, do not all retire at once.
func retirementLifetime(lifetime time.Duration) time.Duration {
	jitter := lifetime / 10
	if jitter <= 0 {
		return lifetime
	}
	return lifetime - rand.N(jitter+1)
}

// retired reports whether the session has reached its close_after_lifetime
// deadline and must no longer be handed out.
func (s *Session) retired(now time.Time) bool {
	return !s.retireAt.IsZero() && !now.Before(s.retireAt)
}

// closeRetired closes a session that is not in the idle pool and logs why;
// state says whether it was idle and for how long, or that its stream ended.
func (c *Client) closeRetired(session *Session, reason string, state string) {
	age := time.Since(session.createdAt)
	latency := session.Latency()
	c.logger.Debug(fmt.Sprintf("[RetireCleanup] Closing session seq=%d (reason=%s, age=%v, %s, latency=%v, samples=%d)",
		session.seq, reason, age, state, latency.Smoothed, latency.Samples))
	if c.metricsCallback != nil {
		c.metricsCallback.SessionClosed(reason, age.Seconds())
	}
	session.Close()
	c.updatePoolMetrics()
}

// retireCleanup closes idle sessions past close_after_lifetime or idle for
// longer than close_after_idle, ignoring every pool protection. It runs before
// the other maintenance so that ensure_idle_session refills in the same pass.
func (c *Client) retireCleanup() {
	if c.closeAfterIdle <= 0 && c.closeAfterLifetime <= 0 {
		return
	}
	type retiring struct {
		session *Session
		reason  string
	}
	var closing []retiring
	now := time.Now()
	c.idleSessionLock.Lock()
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		session := it.Value()
		switch {
		case session.retired(now):
			closing = append(closing, retiring{session, retireReasonLifetime})
		case c.closeAfterIdle > 0 && now.Sub(session.idleSince) > c.closeAfterIdle:
			closing = append(closing, retiring{session, retireReasonIdle})
		}
	}
	for _, s := range closing {
		c.idleSession.Remove(math.MaxUint64 - s.session.seq)
	}
	c.idleSessionLock.Unlock()
	for _, s := range closing {
		c.closeRetired(s.session, s.reason, "idle "+now.Sub(s.session.idleSince).String())
	}
}

// jitteredLifetime draws a session's max_connection_lifetime uniformly from
// [lifetime-jitter, lifetime+jitter], and never below one second.
//
// It used to offset by seq*31337 nanoseconds modulo the jitter, less half of
// it. For any realistic seq that product is a few microseconds, far below a
// jitter in seconds, so every session got lifetime-jitter/2 and sessions
// created together still expired together.
func jitteredLifetime(lifetime, jitter time.Duration) time.Duration {
	if jitter > 0 {
		lifetime += rand.N(2*jitter+1) - jitter
	}
	if lifetime < time.Second {
		lifetime = time.Second
	}
	return lifetime
}
