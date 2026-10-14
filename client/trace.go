package client

import (
	"log/slog"
	"runtime/debug"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ConnectPhase is where a connection attempt failed.
type ConnectPhase int

const (
	// ConnectPhaseOpen is opening the socket, or the address the resolver
	// returned failing validation.
	ConnectPhaseOpen ConnectPhase = iota
	// ConnectPhaseHandshake is the key exchange, from the first packet to the
	// shared secret, before HandshakeDone.
	ConnectPhaseHandshake
	// ConnectPhaseJoin is after HandshakeDone, waiting for the server to accept
	// the client. A wrong server password, a ban or an invalid nickname end
	// here.
	ConnectPhaseJoin
)

// String names the phase: "open", "handshake" or "join".
func (p ConnectPhase) String() string {
	switch p {
	case ConnectPhaseOpen:
		return "open"
	case ConnectPhaseHandshake:
		return "handshake"
	case ConnectPhaseJoin:
		return "join"
	default:
		return "unknown"
	}
}

// ResolveStartInfo describes the ResolveStart milestone.
type ResolveStartInfo struct {
	// Addr is the address as configured.
	Addr string
	// Attempt is the 1-based attempt number: 1 for the attempt Connect
	// starts, the retry number of the reconnect policy for a reconnection.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// ResolveDoneInfo describes the ResolveDone milestone.
type ResolveDoneInfo struct {
	// Err is the resolver's error when the client fell back to the address as
	// given; nil otherwise.
	Err error
	// Addr is the address as configured.
	Addr string
	// Target is the host:port that will be dialled.
	Target string
	// Source is where the resolver found the target, as it reports it, and
	// may be empty. The client names a fallback "Fallback".
	Source string
	// Duration is how long resolution took.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// ConnectStartInfo describes the ConnectStart milestone.
type ConnectStartInfo struct {
	// Target is the host:port that is about to be dialled.
	Target string
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// HandshakeDoneInfo describes the HandshakeDone milestone.
type HandshakeDoneInfo struct {
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// SessionStartInfo describes the SessionStart milestone.
type SessionStartInfo struct {
	// Capabilities is what the server reported about itself in initserver.
	Capabilities ServerCapabilities
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// ClientID is the id the server assigned to the client.
	ClientID teamspeak.ClientID
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// WelcomeDoneInfo describes the WelcomeDone milestone.
type WelcomeDoneInfo struct {
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// AttemptFailedInfo describes the AttemptFailed milestone.
type AttemptFailedInfo struct {
	// Err is why the attempt ended, as Connect returns it for a Connect, or
	// as the reconnect loop saw it.
	Err error
	// Phase is where the attempt failed.
	Phase ConnectPhase
	// Duration is the time since ResolveStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// ReconnectScheduledInfo describes the ReconnectScheduled milestone.
type ReconnectScheduledInfo struct {
	// Cause is the error that ended the previous connection or attempt.
	Cause error
	// Delay is how long the loop waits before the attempt.
	Delay time.Duration
	// Attempt is the number of the attempt that follows, the one the
	// reconnect policy sees.
	Attempt int
}

// ConnectTrace observes the milestones of every connection attempt, the one
// Connect makes and each one the reconnect loop makes, for timing, metrics,
// logs or a progress display. Set it with WithConnectTrace. Every hook is
// optional.
//
// For an attempt that succeeds the hooks are called in this order:
// ResolveStart, ResolveDone, ConnectStart, HandshakeDone, SessionStart and
// WelcomeDone. An attempt that does not reach SessionStart ends with
// AttemptFailed instead, whatever the reason, including a cancelled context or
// a Disconnect during the attempt: every attempt that began ends with exactly
// one of SessionStart and AttemptFailed. A connection that drops after
// SessionStart is not an AttemptFailed; the disconnected event reports it,
// and ReconnectScheduled follows when reconnecting. Nothing is reported for a
// Connect refused before an attempt begins, such as one on a client that is
// already connected or an address that is not valid.
//
// The rules for a hook:
//
//   - It is called synchronously, at the milestone, by the code that reaches
//     it, and the connection waits for it to return. Its return value does not
//     exist: a hook cannot change or stop the connection.
//   - It must be quick. Slow work belongs on a goroutine of the caller's own.
//   - It may be called from different goroutines: Connect's caller for the
//     resolution and the opening, the receive goroutine for the handshake
//     milestones, the reconnect goroutine for a reconnection. It must be safe
//     for that. The calls of one attempt are in milestone order.
//   - No client lock is held: a hook may call Status, ClientID and the other
//     readers without deadlocking. SessionStart runs before Connect returns
//     and before the connected event is queued.
//   - It must not call Connect or Disconnect. The handshake hooks run on the
//     receive path. Disconnect from one does not deadlock, but from
//     SessionStart or WelcomeDone it waits out its goodbye (a second) because
//     the acknowledgement can only be read by the receive path the hook is
//     holding, and Connect may then report a success for a session that is
//     already closed. To abandon an attempt, cancel the context given to
//     Connect; to leave once connected, call Disconnect from an OnConnected
//     handler.
//   - A hook that panics is recovered and logged at Error, with its name, the
//     panic value and the stack; the connection is not affected.
//
// The connected and disconnected events are separate from the trace and keep
// their ordering guarantees.
type ConnectTrace struct {
	// ResolveStart is called before the address is resolved.
	ResolveStart func(ResolveStartInfo)
	// ResolveDone is called after resolution, also when it fell back to the
	// address as given.
	ResolveDone func(ResolveDoneInfo)
	// ConnectStart is called right before the socket is opened, or the
	// PacketConn from WithPacketConn is used.
	ConnectStart func(ConnectStartInfo)
	// HandshakeDone is called when the encrypted session exists: the shared
	// secret is derived and clientinit is about to be sent.
	HandshakeDone func(HandshakeDoneInfo)
	// SessionStart is called when the server has accepted the client, before
	// Connect returns and before the connected event is queued.
	SessionStart func(SessionStartInfo)
	// WelcomeDone is called when the server's welcome sequence ends: the
	// channel list and the clients already there have arrived. At most once
	// per attempt, and only after SessionStart.
	WelcomeDone func(WelcomeDoneInfo)
	// AttemptFailed is called when an attempt ends without SessionStart.
	AttemptFailed func(AttemptFailedInfo)
	// ReconnectScheduled is called when the reconnect loop has decided to
	// retry and is about to wait.
	ReconnectScheduled func(ReconnectScheduledInfo)
}

// WithConnectTrace reports the milestones of every connection attempt to
// trace; see ConnectTrace for when each hook is called and what a hook may do.
//
// The client copies the struct: changing trace afterwards has no effect. A nil
// trace turns tracing off.
func WithConnectTrace(trace *ConnectTrace) Option {
	return optionFunc(func(c *Client) {
		if trace == nil {
			c.trace = ConnectTrace{}

			return
		}
		c.trace = *trace
	})
}

// callHook runs the hook fn named name with info, recovering a panic in it:
// logged at Error, as a panicking event handler is, and the connection goes
// on.
func callHook[I any](logger *slog.Logger, name string, fn func(I), info I) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		logger.Error("connect trace hook panicked",
			slog.String("hook", name),
			slog.Any("panic", r),
			slog.String("stack", string(debug.Stack())))
	}()
	fn(info)
}

// noReport is the report of an attempt end that has nothing to announce.
func noReport() {}

// attemptStamp is what the hooks of one attempt share, copied under the lock.
type attemptStamp struct {
	resolveStart time.Time
	connectStart time.Time
	number       int
	reconnect    bool
}

// stampLocked copies the attempt's identity, with ok false when the attempt
// never began, so the caller reports nothing. The caller holds c.mu.
func (c *Client) stampLocked() (attemptStamp, bool) {
	a := c.attempt

	return attemptStamp{
		number: a.number, reconnect: a.reconnect,
		resolveStart: a.resolveStart, connectStart: a.connectStart,
	}, a.traced
}

// traceResolveStart reports ResolveStart for the attempt that just began.
func (c *Client) traceResolveStart(a attemptStamp) {
	if c.trace.ResolveStart != nil {
		callHook(c.logger, "ResolveStart", c.trace.ResolveStart,
			ResolveStartInfo{Addr: c.addr, Attempt: a.number, Reconnect: a.reconnect})
	}
}

// traceResolveDone reports ResolveDone, unless the attempt has already ended.
func (c *Client) traceResolveDone(
	attempt *connectAttempt, a attemptStamp, target, source string, took time.Duration, err error,
) {
	if c.trace.ResolveDone == nil || attempt.finished() {
		return
	}
	callHook(c.logger, "ResolveDone", c.trace.ResolveDone, ResolveDoneInfo{
		Addr: c.addr, Target: target, Source: source, Err: err, Duration: took,
		Attempt: a.number, Reconnect: a.reconnect,
	})
}

// traceConnectStart marks the attempt's clock for the durations that count
// from ConnectStart and reports it, unless the attempt has already ended.
func (c *Client) traceConnectStart(attempt *connectAttempt, a attemptStamp, target string) {
	c.mu.Lock()
	attempt.connectStart = time.Now()
	c.mu.Unlock()
	if c.trace.ConnectStart == nil || attempt.finished() {
		return
	}
	callHook(c.logger, "ConnectStart", c.trace.ConnectStart,
		ConnectStartInfo{Target: target, Attempt: a.number, Reconnect: a.reconnect})
}

// traceHandshakeDone reports HandshakeDone for the connection h ran, once its
// shared secret exists and before clientinit is sent. It does nothing when h
// is no longer the current connection's handler or its attempt has ended.
func (c *Client) traceHandshakeDone(h *transport.PacketHandler) {
	c.mu.Lock()
	if c.handler != h || c.status != StatusConnecting || c.attempt.claimed || c.attempt.handshakeDone {
		c.mu.Unlock()

		return
	}
	c.attempt.handshakeDone = true
	a, ok := c.stampLocked()
	c.mu.Unlock()

	if !ok || c.trace.HandshakeDone == nil {
		return
	}
	callHook(c.logger, "HandshakeDone", c.trace.HandshakeDone, HandshakeDoneInfo{
		Duration: time.Since(a.connectStart), Attempt: a.number, Reconnect: a.reconnect,
	})
}

// traceWelcomeDone reports WelcomeDone, once, for the session h ran, if its
// SessionStart has been reported.
func (c *Client) traceWelcomeDone(h *transport.PacketHandler) {
	c.mu.Lock()
	if c.handler != h || c.status != StatusConnected || !c.attempt.sessionStarted || c.attempt.welcomeDone {
		c.mu.Unlock()

		return
	}
	c.attempt.welcomeDone = true
	a, ok := c.stampLocked()
	c.mu.Unlock()

	if !ok || c.trace.WelcomeDone == nil {
		return
	}
	callHook(c.logger, "WelcomeDone", c.trace.WelcomeDone, WelcomeDoneInfo{
		Duration: time.Since(a.connectStart), Attempt: a.number, Reconnect: a.reconnect,
	})
}

// endAttemptLocked decides that the current attempt failed with err and
// returns the report to run once the lock is released: AttemptFailed, then the
// release of whoever waits for the outcome. The report is a no-op when the
// outcome was already decided, so an attempt is reported once however many
// paths end it. The caller holds c.mu and must call the report.
func (c *Client) endAttemptLocked(err error) func() {
	a := c.attempt
	if !a.claim(err) {
		return noReport
	}
	stamp, traced := c.stampLocked()
	phase := a.phase()

	return func() {
		if traced && c.trace.AttemptFailed != nil {
			callHook(c.logger, "AttemptFailed", c.trace.AttemptFailed, AttemptFailedInfo{
				Phase: phase, Err: err, Duration: time.Since(stamp.resolveStart),
				Attempt: stamp.number, Reconnect: stamp.reconnect,
			})
		}
		a.complete()
	}
}

// startSessionLocked decides that the current attempt succeeded and returns
// the report to run once the lock is released: SessionStart, then the release
// of whoever waits for the outcome. The caller holds c.mu, has set the client
// ID and capabilities, and must call the report.
func (c *Client) startSessionLocked() func() {
	a := c.attempt
	if !a.claim(nil) {
		return noReport
	}
	a.sessionStarted = true
	stamp, traced := c.stampLocked()
	info := SessionStartInfo{
		ClientID: c.clid, Capabilities: c.capabilities,
		Attempt: stamp.number, Reconnect: stamp.reconnect,
	}

	return func() {
		if traced && c.trace.SessionStart != nil {
			info.Duration = time.Since(stamp.connectStart)
			callHook(c.logger, "SessionStart", c.trace.SessionStart, info)
		}
		a.complete()
	}
}

// traceReconnectScheduled reports ReconnectScheduled.
func (c *Client) traceReconnectScheduled(attempt int, delay time.Duration, cause error) {
	if c.trace.ReconnectScheduled == nil {
		return
	}
	callHook(c.logger, "ReconnectScheduled", c.trace.ReconnectScheduled,
		ReconnectScheduledInfo{Attempt: attempt, Delay: delay, Cause: cause})
}
