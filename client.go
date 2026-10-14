package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// MetricsCallback provides hooks for reporting metrics
type MetricsCallback interface {
	// Session pool metrics
	SessionPoolUpdate(idle, active, total int)
	SessionCreated(reason string)
	SessionClosed(reason string, ageSeconds float64)
	SessionOldest(ageSeconds float64)

	// Ensure idle session metrics
	EnsureIdleDeficit(deficit int)
	EnsureIdleCreatedCycle(count int)

	// Stream metrics
	StreamOpened()
	StreamClosed()
	StreamError()
}

type ClientConfig struct {
	Password                    string
	IdleSessionCheckInterval    time.Duration
	IdleSessionTimeout          time.Duration
	MaxConnectionLifetime       time.Duration
	ConnectionLifetimeJitter    time.Duration
	MinIdleSession              int
	MinIdleSessionForAge        int
	EnsureIdleSession           int
	EnsureIdleSessionCreateRate int
	Heartbeat                   time.Duration
	DisableReuse                bool
	// ClientMetadata is sent to the server as the "client" setting verbatim.
	// It is empty unless set.
	ClientMetadata  string
	DialOut         util.DialOutFunc
	Logger          logger.ContextLogger
	MetricsCallback MetricsCallback
}

type Client struct {
	passwordSha256 []byte
	dialOut        util.DialOutFunc
	sessionClient  *session.Client
	padding        atomic.TypedValue[*padding.PaddingFactory]
}

func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordSha256: pw[:],
		dialOut:        config.DialOut,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, config.Logger, c.createOutboundConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MaxConnectionLifetime, config.ConnectionLifetimeJitter, config.MinIdleSession, config.MinIdleSessionForAge, config.EnsureIdleSession, config.EnsureIdleSessionCreateRate, config.Heartbeat, config.DisableReuse, config.MetricsCallback, config.ClientMetadata)
	return c, nil
}

// SetStatsHandler makes sessions opened from now on ask the server for its view
// of the connection, and delivers each report to handler with the number of
// the session it describes. It is harmless against a server that does not
// report: the request is ignored and handler is never called.
func (c *Client) SetStatsHandler(handler session.StatsHandler) {
	c.sessionClient.SetStatsHandler(handler)
}

// SetSelectHandler reports the session each new stream is placed on.
func (c *Client) SetSelectHandler(handler session.SelectHandler) {
	c.sessionClient.SetSelectHandler(handler)
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	_, err = b.WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
