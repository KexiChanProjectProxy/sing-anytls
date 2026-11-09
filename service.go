package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	users           atomic.TypedValue[map[[32]byte]string]
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
	statsProvider   session.StatsProvider
	drainTimeout    time.Duration

	// sessionLock also orders user updates against session registration, so
	// that a session authenticated just before an update cannot escape it.
	sessionLock sync.Mutex
	sessions    map[*session.Session]sessionAuth
	draining    bool
	drainTimer  *time.Timer
}

// sessionAuth is what a session authenticated with.
type sessionAuth struct {
	passwordSha256 [32]byte
	user           string
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
	// StatsProvider, when set, reports the server's view of a connection to
	// clients that ask for it.
	StatsProvider session.StatsProvider
	// DrainTimeout limits how long Drain waits for streams before closing the
	// sessions that still have some. Zero means no limit.
	DrainTimeout time.Duration
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		statsProvider:   config.StatsProvider,
		drainTimeout:    config.DrainTimeout,
		sessions:        make(map[*session.Session]sessionAuth),
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.users.Store(newUserMap(config.Users))

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func newUserMap(users []User) map[[32]byte]string {
	u := make(map[[32]byte]string, len(users))
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	return u
}

// UpdateUsers replaces the user set and closes the sessions it no longer
// allows: those of a removed user, or authenticated with a password that is
// gone or now belongs to someone else. Other sessions are left alone.
func (s *Service) UpdateUsers(users []User) {
	u := newUserMap(users)

	var revoked []*session.Session
	s.sessionLock.Lock()
	s.users.Store(u)
	for sess, sessAuth := range s.sessions {
		if user, ok := u[sessAuth.passwordSha256]; !ok || user != sessAuth.user {
			revoked = append(revoked, sess)
		}
	}
	s.sessionLock.Unlock()

	for _, sess := range revoked {
		sess.Close()
	}
}

// Drain stops the service accepting sessions and makes the current ones close:
// idle sessions at once, the others when their last stream ends or when
// DrainTimeout runs out. It does not wait for them.
func (s *Service) Drain() {
	s.sessionLock.Lock()
	s.draining = true
	sessions := s.sessionsLocked()
	if s.drainTimeout > 0 && s.drainTimer == nil && len(sessions) > 0 {
		s.drainTimer = time.AfterFunc(s.drainTimeout, func() {
			s.Close()
		})
	}
	s.sessionLock.Unlock()

	for _, sess := range sessions {
		sess.Drain()
	}
}

// Close stops the service accepting sessions and closes the current ones,
// interrupting their streams.
func (s *Service) Close() error {
	s.sessionLock.Lock()
	s.draining = true
	s.stopDrainTimerLocked()
	sessions := s.sessionsLocked()
	s.sessionLock.Unlock()

	for _, sess := range sessions {
		sess.Close()
	}
	return nil
}

func (s *Service) sessionsLocked() []*session.Session {
	sessions := make([]*session.Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	return sessions
}

func (s *Service) stopDrainTimerLocked() {
	if s.drainTimer != nil {
		s.drainTimer.Stop()
	}
}

// registerSession tracks sess, unless the service is draining or the user was
// updated away since sess authenticated.
func (s *Service) registerSession(sess *session.Session, sessAuth sessionAuth) bool {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	if s.draining {
		return false
	}
	if user, ok := s.users.Load()[sessAuth.passwordSha256]; !ok || user != sessAuth.user {
		return false
	}
	s.sessions[sess] = sessAuth
	return true
}

func (s *Service) unregisterSession(sess *session.Session) {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	delete(s.sessions, sess)
	// The timer keeps the service reachable, so let it go with the last session.
	if s.draining && len(s.sessions) == 0 {
		s.stopDrainTimerLocked()
	}
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	user, ok := s.users.Load()[passwordSha256]
	if ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	sess := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	sess.SetStatsProvider(s.statsProvider)
	sess.SetCloseHook(func() {
		s.unregisterSession(sess)
	})
	if s.registerSession(sess, sessionAuth{passwordSha256: passwordSha256, user: user}) {
		sess.Run()
	}
	sess.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
