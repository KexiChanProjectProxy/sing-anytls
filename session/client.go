package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/skiplist"
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

	logger          logger.Logger
	metricsCallback MetricsCallback
}

func NewClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout, maxConnectionLifetime, connectionLifetimeJitter time.Duration, minIdleSession, minIdleSessionForAge, ensureIdleSession, ensureIdleSessionCreateRate int, heartbeat time.Duration, metricsCallback MetricsCallback,
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
	go func() {
		for {
			time.Sleep(idleSessionCheckInterval)
			c.idleCleanup()
			c.ageCleanup()
			c.ensureIdleSessionPool()
			select {
			case <-c.die.Done():
				return
			default:
			}
		}
	}()
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

	session = c.getIdleSession()
	sessionCreated := false
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

	// Report stream opened
	if c.metricsCallback != nil {
		c.metricsCallback.StreamOpened()
	}

	stream.dieHook = func() {
		// Report stream closed
		if c.metricsCallback != nil {
			c.metricsCallback.StreamClosed()
		}

		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			select {
			case <-c.die.Done():
				// Now client has been closed
				go session.Close()
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

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	if !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		idle = it.Value()
		c.idleSession.Remove(it.Key())
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.logger, c.heartbeat)
	session.seq = c.sessionCounter.Add(1)
	session.createdAt = time.Now()

	// Assign randomized lifetime if configured
	if c.maxConnectionLifetime > 0 {
		if c.connectionLifetimeJitter > 0 {
			// Calculate random lifetime: base ± jitter
			// Use session.seq as seed for deterministic but varied randomness
			jitterNanos := c.connectionLifetimeJitter.Nanoseconds()
			// Random value in range [-jitter, +jitter]
			randomJitter := time.Duration((int64(session.seq)*31337)%jitterNanos - jitterNanos/2)
			session.maxLifetime = c.maxConnectionLifetime + randomJitter
			// Ensure lifetime is positive
			if session.maxLifetime < time.Second {
				session.maxLifetime = time.Second
			}
		} else {
			session.maxLifetime = c.maxConnectionLifetime
		}
	}

	session.dieHook = func() {
		c.idleSessionLock.Lock()
		c.idleSession.Remove(math.MaxUint64 - session.seq)
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
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
	activeCount := 0
	protectedCount := 0
	now := time.Now()

	type sessionInfo struct {
		session   *Session
		key       uint64
		idleTime  time.Duration
	}
	var sessionToClose []sessionInfo

	c.idleSessionLock.Lock()
	currentIdleCount := c.idleSession.Len()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			protectedCount++
			continue
		}

		sessionToClose = append(sessionToClose, sessionInfo{
			session:  session,
			key:      key,
			idleTime: now.Sub(session.idleSince),
		})
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	// Log cleanup activity if there are sessions to close or sessions were protected
	if len(sessionToClose) > 0 || protectedCount > 0 {
		if protectedCount > 0 {
			c.logger.Debug(fmt.Sprintf("[IdleCleanup] Found %d expired sessions (timeout=%v), closing %d (keeping %d to maintain min_idle_session=%d, current=%d)",
				len(sessionToClose)+protectedCount, c.idleSessionTimeout, len(sessionToClose), protectedCount, c.minIdleSession, currentIdleCount))
		} else {
			c.logger.Debug(fmt.Sprintf("[IdleCleanup] Found %d expired sessions (timeout=%v), closing all (current=%d)",
				len(sessionToClose), c.idleSessionTimeout, currentIdleCount))
		}
	}

	for i, s := range sessionToClose {
		c.logger.Debug(fmt.Sprintf("[IdleCleanup] Closing session #%d (seq=%d, idle=%v, idleSince=%v)",
			i+1, s.session.seq, s.idleTime, s.session.idleSince))

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
		c.logger.Debug(fmt.Sprintf("[EnsureIdleSession] Current idle sessions: %d, target: %d, deficit=%d, rate-limited to creating %d sessions (will create %d more in next cycle)",
			currentIdleCount, c.ensureIdleSession, deficit, toCreate, deficit-toCreate))
	} else {
		c.logger.Debug(fmt.Sprintf("[EnsureIdleSession] Current idle sessions: %d, target: %d, creating %d new sessions",
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
				c.logger.Debug(fmt.Sprintf("[EnsureIdleSession] Failed to create session #%d: %v", index+1, err))
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

			c.logger.Debug(fmt.Sprintf("[EnsureIdleSession] Successfully created and pooled session #%d (seq=%d)",
				index+1, session.seq))
		}(i)
	}
}

// ageCleanup closes idle sessions that have exceeded their maximum lifetime.
// Older connections are prioritized for closure, while respecting min_idle_session.
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
				})
			}
		}
	}
	c.idleSessionLock.Unlock()

	// If no expired sessions, nothing to do
	if len(expiredSessions) == 0 {
		return
	}

	// Sort by creation time (oldest first)
	// Since we want to close older connections first, sort in ascending order by createdAt
	for i := 0; i < len(expiredSessions)-1; i++ {
		for j := i + 1; j < len(expiredSessions); j++ {
			if expiredSessions[i].createdAt.After(expiredSessions[j].createdAt) {
				expiredSessions[i], expiredSessions[j] = expiredSessions[j], expiredSessions[i]
			}
		}
	}

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

	c.logger.Debug(fmt.Sprintf("[AgeCleanup] Found %d expired sessions, closing %d oldest (keeping %d to maintain min_idle_session_for_age=%d)",
		len(expiredSessions), len(sessionsToClose), keptCount, c.minIdleSessionForAge))

	// Close sessions starting from oldest
	c.idleSessionLock.Lock()
	for i, s := range sessionsToClose {
		c.idleSession.Remove(s.key)
		c.logger.Debug(fmt.Sprintf("[AgeCleanup] Closing session #%d (seq=%d, age=%v, maxLife=%v, created=%v)",
			i+1, s.session.seq, s.age, s.maxLife, s.session.createdAt))

		// Report session closure metrics
		if c.metricsCallback != nil {
			c.metricsCallback.SessionClosed("max_age", s.age.Seconds())
		}

		// Close outside the lock to avoid blocking
		go s.session.Close()
	}
	c.idleSessionLock.Unlock()

	// Update pool metrics after cleanup
	if len(sessionsToClose) > 0 {
		c.updatePoolMetrics()
	}
}
