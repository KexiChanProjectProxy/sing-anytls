package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/auth"
)

// A probe fills one session with filler for a few seconds, so that the sender
// becomes limited by the path rather than by the application and the path's
// capacity can be observed. The client asks for it; the server decides how
// much it allows. On the wire:
//
//	client: cmdProbeRequest {action=start, dir, bytes, ms}
//	server: cmdProbeStatus  {status=accepted, bytes, ms} or {status=refused, reason}
//	sender: cmdProbeData ... (server for dir=down, client for dir=up)
//	client: cmdProbeRequest {action=stop}   (to end early, or after an upload)
//	server: cmdProbeStatus  {status=done, reason, bytes, ms, ...meter keys}
//
// The keys status, reason, bytes, ms and retry_ms of a status belong to this
// package; everything else in a done status comes from the server's meter.

// ProbeDirection says which end sends the filler.
type ProbeDirection uint8

const (
	// ProbeDownload has the server send, measuring server to client.
	ProbeDownload ProbeDirection = iota
	// ProbeUpload has the client send, measuring client to server.
	ProbeUpload
)

func (d ProbeDirection) String() string {
	if d == ProbeUpload {
		return "up"
	}
	return "down"
}

func parseProbeDirection(value string) (ProbeDirection, bool) {
	switch value {
	case "down":
		return ProbeDownload, true
	case "up":
		return ProbeUpload, true
	}
	return 0, false
}

// ProbeRun measures one probe on one end of the connection.
type ProbeRun interface {
	// Converged reports whether the sender has found the path's capacity, so
	// that the probe can stop before its limits. It is only called on the
	// sending end, after every data frame, and must be cheap.
	Converged() bool
	// Finish ends the measurement. bytes is the filler this end sent or
	// received. On the server the result is sent to the client verbatim,
	// except for the keys this package owns.
	Finish(bytes int64) util.StringMap
}

// ProbeMeter starts measuring a probe on conn, the connection under the
// session. ctx is the session's context. It may return nil to measure nothing.
type ProbeMeter func(ctx context.Context, conn net.Conn, direction ProbeDirection) ProbeRun

// ProbeAccount is told of filler a session moved, so that it can be counted
// as the user's traffic. ctx is the session's context. It is called once at
// the end of each probe, even one cut short, and once more when the session
// closes for filler that arrived outside an upload.
type ProbeAccount func(ctx context.Context, direction ProbeDirection, bytes int64)

// Default probe limits, used for a zero field of ProbeConfig.
const (
	DefaultProbeMaxBytes      = 32 << 20
	DefaultProbeMaxDuration   = 5 * time.Second
	DefaultProbeCooldown      = 60 * time.Second
	DefaultProbeMaxConcurrent = 4
)

// ProbeConfig is how much probing a server allows.
type ProbeConfig struct {
	// MaxBytes and MaxDuration bound one probe; a client asking for more, or
	// for nothing in particular, gets these.
	MaxBytes    int64
	MaxDuration time.Duration
	// Cooldown is how long a user, or a session without one, waits between
	// two probes in the same direction; a negative value disables it.
	Cooldown time.Duration
	// MaxConcurrent bounds the probes running at once across the server.
	MaxConcurrent int
	// Meter measures each probe; it may be nil.
	Meter ProbeMeter
	// Account counts the filler; it may be nil.
	Account ProbeAccount
}

// ProbeServer is the probe state a server shares between its sessions.
type ProbeServer struct {
	config  ProbeConfig
	running chan struct{}

	cooldownAccess sync.Mutex
	lastEnd        map[probeOwner]time.Time
}

// probeOwner is whose probes share a cooldown: the authenticated user, or the
// session when there is none.
type probeOwner struct {
	owner     any
	direction ProbeDirection
}

// NewProbeServer returns the shared state for config, with defaults filled in.
func NewProbeServer(config ProbeConfig) *ProbeServer {
	if config.MaxBytes <= 0 {
		config.MaxBytes = DefaultProbeMaxBytes
	}
	if config.MaxDuration <= 0 {
		config.MaxDuration = DefaultProbeMaxDuration
	}
	if config.Cooldown < 0 {
		config.Cooldown = 0
	} else if config.Cooldown == 0 {
		config.Cooldown = DefaultProbeCooldown
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = DefaultProbeMaxConcurrent
	}
	return &ProbeServer{
		config:  config,
		running: make(chan struct{}, config.MaxConcurrent),
		lastEnd: make(map[probeOwner]time.Time),
	}
}

// cooldownLeft is how long owner must still wait.
func (p *ProbeServer) cooldownLeft(owner probeOwner, now time.Time) time.Duration {
	p.cooldownAccess.Lock()
	defer p.cooldownAccess.Unlock()
	last, loaded := p.lastEnd[owner]
	if !loaded {
		return 0
	}
	return p.config.Cooldown - now.Sub(last)
}

// ended starts owner's cooldown, and forgets cooldowns that have run out.
func (p *ProbeServer) ended(owner probeOwner, now time.Time) {
	p.cooldownAccess.Lock()
	defer p.cooldownAccess.Unlock()
	for key, last := range p.lastEnd {
		if now.Sub(last) >= p.config.Cooldown {
			delete(p.lastEnd, key)
		}
	}
	if p.config.Cooldown > 0 {
		p.lastEnd[owner] = now
	}
}

const (
	probeKeyAction  = "action"
	probeKeyDir     = "dir"
	probeKeyBytes   = "bytes"
	probeKeyMs      = "ms"
	probeKeyStatus  = "status"
	probeKeyReason  = "reason"
	probeKeyRetryMs = "retry_ms"

	probeActionStart = "start"
	probeActionStop  = "stop"

	probeStatusAccepted = "accepted"
	probeStatusRefused  = "refused"
	probeStatusDone     = "done"

	// Reasons a probe ended.
	ProbeReasonBytes     = "bytes"
	ProbeReasonTime      = "time"
	ProbeReasonConverged = "converged"
	ProbeReasonStop      = "stop"
	// Reasons a probe was refused.
	ProbeReasonCooldown = "cooldown"
	ProbeReasonBusy     = "busy"
	ProbeReasonInvalid  = "invalid"
)

// probeChunk is the filler carried by one data frame.
const probeChunk = maxFrameDataLen

var probeFiller = make([]byte, probeChunk)

// probeUploadGrace is how long past the accepted duration the server waits
// for an upload to stop before ending it itself.
const probeUploadGrace = 2 * time.Second

// probeWatchdogGrace is how long past the accepted duration a probe may take
// before its session is closed. Writes have no deadline of their own, so a
// peer that stops reading would otherwise hold the probe, and its share of
// MaxConcurrent, for as long as the connection lives. It is a variable so
// that tests can shorten it.
var probeWatchdogGrace = 10 * time.Second

// probeRequestQueue bounds the requests waiting for a server session's probe
// goroutine; more are dropped, so that a flood cannot pile up on the server.
const probeRequestQueue = 8

type probeRequest struct {
	id   uint32
	data util.StringMap
}

// probeServerState is the server half of probing for one session.
type probeServerState struct {
	server    *ProbeServer
	ctx       context.Context
	owner     any
	requests  chan probeRequest
	startOnce sync.Once
	// upload is the upload being received, read by recvLoop.
	upload atomic.Pointer[serverUpload]
	// stray counts filler received outside an upload, which is accounted
	// when the session closes.
	stray atomic.Int64
}

type serverUpload struct {
	id       uint32
	maxBytes int64
	received atomic.Int64
	first    atomic.Int64
	last     atomic.Int64
}

// SetProbeServer makes a server session offer probes to clients. ctx is passed
// to the meter and the accounting, and the user it carries shares a cooldown
// across sessions. It must be called before Run.
func (s *Session) SetProbeServer(ctx context.Context, server *ProbeServer) {
	if server == nil || s.isClient {
		return
	}
	var owner any = s
	if user, loaded := auth.UserFromContext[string](ctx); loaded && user != "" {
		owner = user
	}
	s.probeServer = &probeServerState{
		server:   server,
		ctx:      ctx,
		owner:    owner,
		requests: make(chan probeRequest, probeRequestQueue),
	}
}

// handleProbeRequest takes a request read by recvLoop. It never blocks.
func (s *Session) handleProbeRequest(id uint32, data []byte) {
	state := s.probeServer
	if s.isClient || state == nil || id == 0 {
		return
	}
	state.startOnce.Do(func() {
		go s.probeLoop()
	})
	select {
	case state.requests <- probeRequest{id: id, data: util.StringMapFromBytes(data)}:
	default:
	}
}

// handleProbeData counts filler read by recvLoop. A server closes a session
// that sends more than an upload allows, or more than one upload's worth
// outside any.
func (s *Session) handleProbeData(id uint32, n int) {
	if s.isClient {
		if probe := s.probeClient.active.Load(); probe != nil && probe.id == id {
			probe.count(n)
		}
		return
	}
	state := s.probeServer
	if state == nil {
		return
	}
	upload := state.upload.Load()
	if upload == nil || upload.id != id {
		// The tail of an upload the server ended, or filler nobody asked for.
		if state.stray.Add(int64(n)) > state.server.config.MaxBytes {
			s.Close()
		}
		return
	}
	now := monoNow()
	upload.first.CompareAndSwap(0, now)
	upload.last.Store(now)
	if upload.received.Add(int64(n)) > upload.maxBytes {
		s.Close()
	}
}

// accountStray accounts the filler received outside an upload so far.
func (s *Session) accountStray() {
	state := s.probeServer
	if state == nil || state.server.config.Account == nil {
		return
	}
	if stray := state.stray.Swap(0); stray > 0 {
		state.server.config.Account(state.ctx, ProbeUpload, stray)
	}
}

// probeLoop serves one session's probes, one at a time, until it closes.
func (s *Session) probeLoop() {
	state := s.probeServer
	for {
		select {
		case <-s.die:
			return
		case request := <-state.requests:
			if request.data[probeKeyAction] != probeActionStart {
				// A stop for a probe that already ended.
				continue
			}
			if !s.serveProbe(request) {
				return
			}
		}
	}
}

// serveProbe answers one start request and runs the probe if it is allowed.
// It returns false when the session is gone.
func (s *Session) serveProbe(request probeRequest) bool {
	state := s.probeServer
	config := state.server.config
	direction, valid := parseProbeDirection(request.data[probeKeyDir])
	if !valid {
		return s.writeProbeStatus(request.id, util.StringMap{probeKeyStatus: probeStatusRefused, probeKeyReason: ProbeReasonInvalid})
	}
	owner := probeOwner{owner: state.owner, direction: direction}
	if wait := state.server.cooldownLeft(owner, time.Now()); wait > 0 {
		return s.writeProbeStatus(request.id, util.StringMap{
			probeKeyStatus:  probeStatusRefused,
			probeKeyReason:  ProbeReasonCooldown,
			probeKeyRetryMs: strconv.FormatInt(wait.Milliseconds()+1, 10),
		})
	}
	select {
	case state.server.running <- struct{}{}:
	default:
		return s.writeProbeStatus(request.id, util.StringMap{probeKeyStatus: probeStatusRefused, probeKeyReason: ProbeReasonBusy})
	}
	defer func() { <-state.server.running }()

	maxBytes := config.MaxBytes
	if requested, err := strconv.ParseInt(request.data[probeKeyBytes], 10, 64); err == nil && requested > 0 && requested < maxBytes {
		maxBytes = requested
	}
	maxDuration := config.MaxDuration
	if requested, err := strconv.ParseInt(request.data[probeKeyMs], 10, 64); err == nil && requested > 0 && time.Duration(requested)*time.Millisecond < maxDuration {
		maxDuration = time.Duration(requested) * time.Millisecond
	}
	watchdog := time.AfterFunc(maxDuration+probeWatchdogGrace, func() { s.Close() })
	defer watchdog.Stop()

	// The meter and the upload start before the client learns it may send,
	// so that they see all of the filler.
	var run ProbeRun
	if config.Meter != nil {
		run = config.Meter(state.ctx, s.conn, direction)
	}
	var upload *serverUpload
	if direction == ProbeUpload {
		upload = &serverUpload{id: request.id, maxBytes: maxBytes}
		state.upload.Store(upload)
	}
	var (
		reason string
		bytes  int64
		took   time.Duration
		alive  = s.writeProbeStatus(request.id, util.StringMap{
			probeKeyStatus: probeStatusAccepted,
			probeKeyBytes:  strconv.FormatInt(maxBytes, 10),
			probeKeyMs:     strconv.FormatInt(maxDuration.Milliseconds(), 10),
		})
	)
	if alive {
		if direction == ProbeDownload {
			reason, bytes, took, alive = s.sendProbe(request.id, maxBytes, maxDuration, run)
		} else {
			reason, took, alive = s.receiveProbe(upload, maxDuration)
		}
	}
	if upload != nil {
		state.upload.Store(nil)
		bytes = upload.received.Load()
	}
	state.server.ended(owner, time.Now())
	if config.Account != nil && bytes > 0 {
		config.Account(state.ctx, direction, bytes)
	}
	s.accountStray()
	result := util.StringMap{}
	if run != nil {
		for key, value := range run.Finish(bytes) {
			result[key] = value
		}
	}
	if !alive {
		return false
	}
	result[probeKeyStatus] = probeStatusDone
	result[probeKeyReason] = reason
	result[probeKeyBytes] = strconv.FormatInt(bytes, 10)
	result[probeKeyMs] = strconv.FormatInt(took.Milliseconds(), 10)
	return s.writeProbeStatus(request.id, result)
}

// sendProbe sends download filler until a limit, convergence or a stop.
func (s *Session) sendProbe(id uint32, maxBytes int64, maxDuration time.Duration, run ProbeRun) (reason string, sent int64, took time.Duration, alive bool) {
	start := time.Now()
	deadline := start.Add(maxDuration)
	for {
		if sent >= maxBytes {
			reason = ProbeReasonBytes
			break
		}
		if !time.Now().Before(deadline) {
			reason = ProbeReasonTime
			break
		}
		if stop, alive := s.pollProbeRequests(id); !alive {
			return "", sent, time.Since(start), false
		} else if stop {
			reason = ProbeReasonStop
			break
		}
		n := int64(probeChunk)
		if remaining := maxBytes - sent; remaining < n {
			n = remaining
		}
		if err := s.writeAsyncFrame(cmdProbeData, id, probeFiller[:n]); err != nil {
			s.Close()
			return "", sent, time.Since(start), false
		}
		sent += n
		if run != nil && run.Converged() {
			reason = ProbeReasonConverged
			break
		}
	}
	return reason, sent, time.Since(start), true
}

// pollProbeRequests handles the requests that arrived while a download runs:
// a stop for it ends it, and a start for another probe is refused.
func (s *Session) pollProbeRequests(id uint32) (stop bool, alive bool) {
	for {
		select {
		case <-s.die:
			return false, false
		case request := <-s.probeServer.requests:
			switch {
			case request.data[probeKeyAction] == probeActionStop && request.id == id:
				stop = true
			case request.data[probeKeyAction] == probeActionStart:
				if !s.writeProbeStatus(request.id, util.StringMap{probeKeyStatus: probeStatusRefused, probeKeyReason: ProbeReasonBusy}) {
					return false, false
				}
			}
		default:
			return stop, true
		}
	}
}

// receiveProbe waits for an upload to end, which is when the client stops it
// after its last filler, or when it runs past its duration. A client sending
// more than allowed has its session closed by handleProbeData.
func (s *Session) receiveProbe(upload *serverUpload, maxDuration time.Duration) (reason string, took time.Duration, alive bool) {
	timer := time.NewTimer(maxDuration + probeUploadGrace)
	defer timer.Stop()
	alive = true
wait:
	for {
		select {
		case <-s.die:
			alive = false
			break wait
		case <-timer.C:
			reason = ProbeReasonTime
			break wait
		case request := <-s.probeServer.requests:
			switch {
			case request.data[probeKeyAction] == probeActionStop && request.id == upload.id:
				// The receive loop counted every filler frame before the stop.
				reason = ProbeReasonStop
				break wait
			case request.data[probeKeyAction] == probeActionStart:
				if !s.writeProbeStatus(request.id, util.StringMap{probeKeyStatus: probeStatusRefused, probeKeyReason: ProbeReasonBusy}) {
					alive = false
					break wait
				}
			}
		}
	}
	if first, last := upload.first.Load(), upload.last.Load(); first != 0 {
		took = time.Duration(last - first)
	}
	return reason, took, alive
}

func (s *Session) writeProbeStatus(id uint32, status util.StringMap) bool {
	if s.IsClosed() {
		return false
	}
	if err := s.writeAsyncFrame(cmdProbeStatus, id, status.ToBytes()); err != nil {
		s.Close()
		return false
	}
	return true
}

// Client side.

var (
	// ErrProbeUnsupported is returned when the server did not offer probes.
	ErrProbeUnsupported = errors.New("anytls: server does not offer probes")
	// ErrProbeSessionUnavailable is returned when the session asked for is
	// not idle in the pool.
	ErrProbeSessionUnavailable = errors.New("anytls: session to probe is not idle")
	// ErrProbeTimeout is returned when the server stops answering a probe;
	// the session is closed, since its state is unknown.
	ErrProbeTimeout = errors.New("anytls: probe timed out")
)

// ProbeRefusedError is returned when the server refuses a probe.
type ProbeRefusedError struct {
	// Reason is ProbeReasonCooldown, ProbeReasonBusy or ProbeReasonInvalid.
	Reason string
	// RetryAfter is how long the cooldown has left, zero otherwise.
	RetryAfter time.Duration
}

func (e *ProbeRefusedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("anytls: probe refused: %s, retry after %v", e.Reason, e.RetryAfter)
	}
	return "anytls: probe refused: " + e.Reason
}

// ProbeRequest describes a probe a client asks for.
type ProbeRequest struct {
	Direction ProbeDirection
	// MaxBytes and MaxDuration ask for less than the server allows; zero
	// takes the server's limit.
	MaxBytes    int64
	MaxDuration time.Duration
	// Seq is the session to probe, which must be idle in the pool; zero
	// probes the session the next stream would use, dialing one if none is
	// idle.
	Seq uint64
	// Meter measures the probe on this end; it may be nil. For an upload,
	// its convergence ends the probe early.
	Meter ProbeMeter
}

// ProbeResult is what a probe found.
type ProbeResult struct {
	Seq       uint64
	Direction ProbeDirection
	// MaxBytes and MaxDuration are the limits the server accepted.
	MaxBytes    int64
	MaxDuration time.Duration
	// Bytes is the filler this end counted: received for a download, sent
	// for an upload. Duration runs from the server's acceptance to the last
	// filler received for a download, and over the writes for an upload,
	// which the socket buffer makes optimistic; the server's own count is in
	// Server.
	Bytes    int64
	Duration time.Duration
	// Reason is why the server ended the probe.
	Reason string
	// Server is the server's final status, with its meter's keys.
	Server util.StringMap
	// Local is this end's meter result, nil without a meter.
	Local util.StringMap
}

// probeClientState is the client half of probing for one session.
type probeClientState struct {
	// offered is written before the server settings are marked received.
	offered atomic.Bool
	nextID  atomic.Uint32
	active  atomic.Pointer[clientProbe]
}

type clientProbe struct {
	id     uint32
	status chan util.StringMap
	// firstStatus is when the first status arrived, which for an accepted
	// download is when the server starts sending.
	firstStatus atomic.Int64
	received    atomic.Int64
	last        atomic.Int64
}

func (p *clientProbe) count(n int) {
	p.received.Add(int64(n))
	p.last.Store(monoNow())
}

// handleProbeStatus takes a status read by recvLoop. It never blocks.
func (s *Session) handleProbeStatus(id uint32, data []byte) {
	if !s.isClient {
		return
	}
	probe := s.probeClient.active.Load()
	if probe == nil || probe.id != id {
		return
	}
	probe.firstStatus.CompareAndSwap(0, monoNow())
	select {
	case probe.status <- util.StringMapFromBytes(data):
	default:
	}
}

// ProbeSupported reports whether the server offered probes. It is false until
// the server's settings arrive.
func (s *Session) ProbeSupported() bool {
	return s.probeClient.offered.Load()
}

// probeStatusTimeout bounds the wait for each status the server owes beyond
// the probe's own duration.
const probeStatusTimeout = 10 * time.Second

// probeSettingsTimeout bounds the wait for the server's settings, which a
// version 1 server never sends. It is a variable so that tests can shorten it.
var probeSettingsTimeout = 10 * time.Second

// probeCancelGrace is how long a probe whose ctx ended may take to stop
// before its session is closed.
const probeCancelGrace = 3 * time.Second

// probe runs one probe on a session that this client holds exclusively.
func (s *Session) probe(ctx context.Context, request ProbeRequest) (ProbeResult, error) {
	result := ProbeResult{Seq: s.seq, Direction: request.Direction}
	if s.dnsClient == nil {
		return result, ErrProbeUnsupported
	}
	// A version 1 server never sends its settings, and does not offer probes.
	settingsTimer := time.NewTimer(probeSettingsTimeout)
	defer settingsTimer.Stop()
	select {
	case <-s.dnsClient.ready:
	case <-s.die:
		return result, io.ErrClosedPipe
	case <-ctx.Done():
		return result, ctx.Err()
	case <-settingsTimer.C:
		return result, ErrProbeUnsupported
	}
	if s.IsClosed() {
		return result, io.ErrClosedPipe
	}
	if !s.ProbeSupported() {
		return result, ErrProbeUnsupported
	}

	id := s.probeClient.nextID.Add(1)
	if id == 0 {
		id = s.probeClient.nextID.Add(1)
	}
	probe := &clientProbe{id: id, status: make(chan util.StringMap, 4)}
	s.probeClient.active.Store(probe)
	defer s.probeClient.active.Store(nil)
	// The filler would delay heartbeats, which would then read as latency of
	// the path; they are not sent, and no latency is sampled, while it runs.
	s.probing.Store(true)
	defer s.probing.Store(false)

	start := util.StringMap{
		probeKeyAction: probeActionStart,
		probeKeyDir:    request.Direction.String(),
	}
	if request.MaxBytes > 0 {
		start[probeKeyBytes] = strconv.FormatInt(request.MaxBytes, 10)
	}
	if request.MaxDuration > 0 {
		start[probeKeyMs] = strconv.FormatInt(max(request.MaxDuration.Milliseconds(), 1), 10)
	}
	// The meter starts before the request, so that it sees all the filler.
	var run ProbeRun
	if request.Meter != nil {
		run = request.Meter(ctx, s.conn, request.Direction)
	}
	finish := func(bytes int64) {
		if run != nil {
			result.Local = run.Finish(bytes)
			run = nil
		}
	}
	defer finish(0)
	if err := s.writeAsyncFrame(cmdProbeRequest, id, start.ToBytes()); err != nil {
		s.Close()
		return result, io.ErrClosedPipe
	}
	status, err := s.waitProbeStatus(ctx, probe, probeStatusTimeout)
	if err != nil {
		return result, err
	}
	switch status[probeKeyStatus] {
	case probeStatusAccepted:
	case probeStatusRefused:
		refused := &ProbeRefusedError{Reason: status[probeKeyReason]}
		if retry, err := strconv.ParseInt(status[probeKeyRetryMs], 10, 64); err == nil && retry > 0 {
			refused.RetryAfter = time.Duration(retry) * time.Millisecond
		}
		return result, refused
	default:
		s.Close()
		return result, fmt.Errorf("anytls: unexpected probe status %q", status[probeKeyStatus])
	}
	acceptedAt := probe.firstStatus.Load()
	result.MaxBytes, _ = strconv.ParseInt(status[probeKeyBytes], 10, 64)
	if ms, err := strconv.ParseInt(status[probeKeyMs], 10, 64); err == nil {
		result.MaxDuration = time.Duration(ms) * time.Millisecond
	}
	if result.MaxBytes <= 0 || result.MaxDuration <= 0 {
		s.Close()
		return result, errors.New("anytls: invalid probe limits from server")
	}

	// Writes have no deadline, so a server that stops reading, or a ctx that
	// ends while a write is blocked, would otherwise hold the caller for as
	// long as the connection lives.
	finished := make(chan struct{})
	defer close(finished)
	watchdog := time.AfterFunc(result.MaxDuration+probeWatchdogGrace+probeStatusTimeout, func() { s.Close() })
	defer watchdog.Stop()
	defer context.AfterFunc(ctx, func() {
		timer := time.NewTimer(probeCancelGrace)
		defer timer.Stop()
		select {
		case <-finished:
		case <-timer.C:
			s.Close()
		}
	})()

	var done util.StringMap
	if request.Direction == ProbeDownload {
		done, err = s.receiveDownload(ctx, probe, result.MaxDuration)
		result.Bytes = probe.received.Load()
		if last := probe.last.Load(); last != 0 {
			result.Duration = time.Duration(last - acceptedAt)
		}
	} else {
		var sent int64
		var took time.Duration
		done, sent, took, err = s.sendUpload(ctx, probe, result.MaxBytes, result.MaxDuration, run)
		result.Bytes, result.Duration = sent, took
	}
	finish(result.Bytes)
	if err != nil {
		return result, err
	}
	result.Server = done
	result.Reason = done[probeKeyReason]
	return result, nil
}

// receiveDownload waits for the server to finish sending, asking it to stop
// when ctx ends first.
func (s *Session) receiveDownload(ctx context.Context, probe *clientProbe, maxDuration time.Duration) (util.StringMap, error) {
	timer := time.NewTimer(maxDuration + probeStatusTimeout)
	defer timer.Stop()
	select {
	case status := <-probe.status:
		return s.checkDone(status)
	case <-s.die:
		return nil, io.ErrClosedPipe
	case <-timer.C:
		s.Close()
		return nil, ErrProbeTimeout
	case <-ctx.Done():
		return nil, s.stopProbe(probe, ctx.Err())
	}
}

// sendUpload sends filler until a limit, convergence, the server ending the
// probe, or ctx, then stops the upload and waits for the server's result.
// The server answers the stop after counting every filler frame before it.
func (s *Session) sendUpload(ctx context.Context, probe *clientProbe, maxBytes int64, maxDuration time.Duration, run ProbeRun) (util.StringMap, int64, time.Duration, error) {
	begin := time.Now()
	deadline := begin.Add(maxDuration)
	var sent int64
	for sent < maxBytes && time.Now().Before(deadline) {
		select {
		case status := <-probe.status:
			// The server ended it first.
			done, err := s.checkDone(status)
			return done, sent, time.Since(begin), err
		case <-s.die:
			return nil, sent, time.Since(begin), io.ErrClosedPipe
		case <-ctx.Done():
			return nil, sent, time.Since(begin), s.stopProbe(probe, ctx.Err())
		default:
		}
		n := int64(probeChunk)
		if remaining := maxBytes - sent; remaining < n {
			n = remaining
		}
		if err := s.writeAsyncFrame(cmdProbeData, probe.id, probeFiller[:n]); err != nil {
			s.Close()
			return nil, sent, time.Since(begin), io.ErrClosedPipe
		}
		sent += n
		if run != nil && run.Converged() {
			break
		}
	}
	took := time.Since(begin)
	if err := s.writeAsyncFrame(cmdProbeRequest, probe.id, util.StringMap{probeKeyAction: probeActionStop}.ToBytes()); err != nil {
		s.Close()
		return nil, sent, took, io.ErrClosedPipe
	}
	status, err := s.waitProbeStatus(context.Background(), probe, probeStatusTimeout+probeUploadGrace)
	if err != nil {
		return nil, sent, took, err
	}
	done, err := s.checkDone(status)
	return done, sent, took, err
}

// stopProbe asks the server to end a probe the caller gave up on, and waits a
// little for it to confirm so that the session can be used again. A session
// that does not confirm is closed.
func (s *Session) stopProbe(probe *clientProbe, cause error) error {
	if err := s.writeAsyncFrame(cmdProbeRequest, probe.id, util.StringMap{probeKeyAction: probeActionStop}.ToBytes()); err != nil {
		s.Close()
		return cause
	}
	if status, err := s.waitProbeStatus(context.Background(), probe, probeCancelGrace); err == nil {
		if _, err := s.checkDone(status); err != nil {
			s.Close()
		}
	}
	return cause
}

func (s *Session) checkDone(status util.StringMap) (util.StringMap, error) {
	if status[probeKeyStatus] != probeStatusDone {
		s.Close()
		return nil, fmt.Errorf("anytls: unexpected probe status %q", status[probeKeyStatus])
	}
	return status, nil
}

// waitProbeStatus waits for the server's next status. A server that does not
// answer in time leaves the session in an unknown state, so it is closed.
func (s *Session) waitProbeStatus(ctx context.Context, probe *clientProbe, timeout time.Duration) (util.StringMap, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case status := <-probe.status:
		return status, nil
	case <-s.die:
		return nil, io.ErrClosedPipe
	case <-timer.C:
		s.Close()
		return nil, ErrProbeTimeout
	case <-ctx.Done():
		// Only reached before the server accepted, when nothing was sent.
		s.Close()
		return nil, ctx.Err()
	}
}

// Probe fills a session with filler to measure the path's capacity in one
// direction. The session is taken out of the pool for the probe, as a stream
// would take it, and returned afterwards.
func (c *Client) Probe(ctx context.Context, request ProbeRequest) (ProbeResult, error) {
	select {
	case <-c.die.Done():
		return ProbeResult{}, io.ErrClosedPipe
	default:
	}
	var (
		session *Session
		created bool
		err     error
	)
	if request.Seq != 0 {
		session = c.takeIdleSession(request.Seq)
		if session == nil {
			return ProbeResult{Seq: request.Seq, Direction: request.Direction}, ErrProbeSessionUnavailable
		}
	} else {
		if !c.disableReuse {
			session = c.getIdleSession()
		}
		if session == nil {
			session, err = c.createSession(ctx)
			if err != nil {
				return ProbeResult{Direction: request.Direction}, fmt.Errorf("failed to create session: %w", err)
			}
			created = true
			if c.metricsCallback != nil {
				c.metricsCallback.SessionCreated("probe")
			}
		}
	}
	result, err := session.probe(ctx, request)
	c.releaseSession(session)
	if created {
		c.updatePoolMetrics()
	}
	return result, err
}

// takeIdleSession takes the session numbered seq out of the idle pool, or
// returns nil when it is not there.
func (c *Client) takeIdleSession(seq uint64) *Session {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	key := math.MaxUint64 - seq
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		if it.Key() != key {
			continue
		}
		session := it.Value()
		if session.IsClosed() || session.retired(time.Now()) {
			return nil
		}
		c.idleSession.Remove(key)
		return session
	}
	return nil
}

// IdleSessions describes the sessions in the idle pool, which are the ones a
// probe can name by Seq.
func (c *Client) IdleSessions() []SessionInfo {
	type idle struct {
		session *Session
		idleFor time.Duration
	}
	c.idleSessionLock.Lock()
	sessions := make([]idle, 0, c.idleSession.Len())
	now := time.Now()
	for it := c.idleSession.Iterate(); it.IsNotEnd(); it.MoveToNext() {
		if session := it.Value(); !session.IsClosed() && !session.retired(now) {
			sessions = append(sessions, idle{session, now.Sub(session.idleSince)})
		}
	}
	c.idleSessionLock.Unlock()
	infos := make([]SessionInfo, 0, len(sessions))
	for _, item := range sessions {
		infos = append(infos, c.sessionInfo(item.session, true, item.idleFor, item.session.streamsOpened.Load()))
	}
	return infos
}
