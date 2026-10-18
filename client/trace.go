package client

import (
	"log/slog"
	"maps"
	"runtime/debug"
	"strconv"
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
	// Target is the host:port that will be dialled, the first candidate.
	Target string
	// Source is where the resolver found the target, as it reports it, and
	// may be empty. The client names a fallback "Fallback".
	Source string
	// Candidates is every answer the resolver gave, in order; empty when
	// resolution fell back to the address as given.
	Candidates []ResolvedAddr
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

// ConnectDoneInfo describes the ConnectDone milestone.
type ConnectDoneInfo struct {
	// Target is the host:port that was dialled.
	Target string
	// LocalAddr is the host:port of the local socket, or "" when it is not
	// known.
	LocalAddr string
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// HandshakeDoneInfo describes the HandshakeDone milestone.
type HandshakeDoneInfo struct {
	// ServerPublicKey is the server's public key exactly as it sent it, in
	// base64, so that a caller can pin the identity of a server.
	ServerPublicKey string
	// PuzzleDuration is the time spent solving the RSA puzzle; 0 when the
	// server sent none.
	PuzzleDuration time.Duration
	// PuzzleLevel is the level of the RSA puzzle the server demanded; 0 when
	// it sent none.
	PuzzleLevel int
	// Resends is how many packets the client had to send again from
	// ConnectStart to HandshakeDone, handshake steps and handshake commands
	// alike.
	Resends int
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// SessionStartInfo describes the SessionStart milestone.
type SessionStartInfo struct {
	// InitServer is every parameter of initserver, unescaped, except the
	// ones that would carry a secret (client_server_password,
	// client_default_channel_password, client_default_token and
	// client_key_offset). It is the hook's own copy.
	InitServer teamspeak.Properties
	// Nickname is the nickname the server accepted, from acn. It differs from
	// the requested one when that was taken.
	Nickname string
	// Capabilities is what the server reported about itself in initserver.
	Capabilities ServerCapabilities
	// Duration is the time since ConnectStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// TalkPower is the client's talk power in its channel
	// (client_talk_power).
	TalkPower int32
	// ClientID is the id the server assigned to the client.
	ClientID teamspeak.ClientID
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// WelcomeDoneInfo describes the WelcomeDone milestone.
type WelcomeDoneInfo struct {
	// ChannelID is the channel the client is in at the end of the welcome:
	// where it landed, which is not the default channel it asked for when that
	// was refused. 0 when not known.
	ChannelID teamspeak.ChannelID
	// Channels is how many channel rows the welcome delivered.
	Channels int
	// Clients is how many clients are in view at the end of the welcome, this
	// client included.
	Clients int
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
	// Target is the host:port that was being dialled; "" when the attempt
	// failed before ResolveDone.
	Target string
	// WaitingFor is what the attempt was waiting for when it ended, in the
	// words a cancelled Connect's error uses, such as "the server's answer to
	// clientek".
	WaitingFor string
	// Phase is where the attempt failed.
	Phase ConnectPhase
	// Duration is the time since ResolveStart.
	Duration time.Duration
	// Attempt is the 1-based attempt number; see ResolveStartInfo.
	Attempt int
	// Reconnect is true for an attempt the reconnect loop made.
	Reconnect bool
}

// DisconnectStartInfo describes the DisconnectStart milestone. It has no
// fields yet.
type DisconnectStartInfo struct{}

// DisconnectDoneInfo describes the DisconnectDone milestone.
type DisconnectDoneInfo struct {
	// Acknowledged is true when the server acknowledged the goodbye before
	// the goodbye timeout.
	Acknowledged bool
	// Duration is how long the goodbye took.
	Duration time.Duration
}

// SessionEndInfo describes the SessionEnd milestone.
type SessionEndInfo struct {
	// Cause is nil after Disconnect; otherwise it is the cause the
	// disconnected event gets.
	Cause error
	// Duration is the time since SessionStart.
	Duration time.Duration
	// Attempt is the attempt number of the attempt that started the session.
	Attempt int
	// ClientID is the id the client had in the session.
	ClientID teamspeak.ClientID
	// Reconnect is true when the reconnect loop's attempt started the session.
	Reconnect bool
}

// ReconnectStoppedInfo describes the ReconnectStopped milestone.
type ReconnectStoppedInfo struct {
	// Cause is the error ShouldRetry declined, or the last attempt's error
	// once the attempts are used up; nil when Disconnect stopped the loop.
	Cause error
	// Attempts is how many reconnection attempts the loop made.
	Attempts int
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

// Trace observes a client's session, from the first connection attempt to its
// end, for timing, metrics, logs or a progress display. Set it with WithTrace.
// Every hook is optional.
//
// For an attempt that succeeds the hooks are called in this order:
// ResolveStart, ResolveDone, ConnectStart, ConnectDone, HandshakeDone,
// SessionStart and WelcomeDone. An attempt that does not reach SessionStart
// ends with AttemptFailed instead, whatever the reason, including a cancelled
// context or a Disconnect during the attempt: every attempt that began ends
// with exactly one of SessionStart and AttemptFailed. Nothing is reported for
// a Connect refused before an attempt begins, such as one on a client that is
// already connected or an address that is not valid.
//
// Every session that had a SessionStart ends with exactly one SessionEnd,
// before the disconnected event is queued. For an explicit Disconnect of a
// connected session the order is DisconnectStart, DisconnectDone, SessionEnd,
// then the disconnected event. For a drop with reconnecting enabled it is
// SessionEnd, ReconnectScheduled, and then the next attempt's hooks, until a
// SessionStart or a ReconnectStopped.
//
// The rules for a hook:
//
//   - It is called synchronously, at the milestone, by the code that reaches
//     it, and the connection waits for it to return. Its return value does not
//     exist: a hook cannot change or stop the connection.
//   - It must be quick. Slow work belongs on a goroutine of the caller's own.
//   - It may be called from different goroutines: Connect's caller for the
//     resolution and the opening, the receive goroutine for the handshake
//     milestones and a drop, Disconnect's caller for the goodbye, the
//     reconnect goroutine for a reconnection. It must be safe for that. The
//     calls of one attempt are in milestone order.
//   - No client lock is held: a hook may call Status, ClientID and the other
//     readers without deadlocking. SessionStart runs before Connect returns
//     and before the connected event is queued.
//   - It must not call Connect or Disconnect. The handshake hooks run on the
//     receive path, and the hooks of a session's end run while it is being
//     closed; calling either waits for the very code that is calling the hook.
//     To abandon an attempt, cancel the context given to Connect; to leave once
//     connected, call Disconnect from an OnConnected handler.
//   - A hook that panics is recovered and logged at Error, with its name, the
//     panic value and the stack; the connection is not affected.
//
// The connected and disconnected events are separate from the trace and keep
// their ordering guarantees.
type Trace struct {
	// ResolveStart is called before the address is resolved.
	ResolveStart func(ResolveStartInfo)
	// ResolveDone is called after resolution, also when it fell back to the
	// address as given.
	ResolveDone func(ResolveDoneInfo)
	// ConnectStart is called right before the socket is opened, or the
	// PacketConn from WithPacketConn is used.
	ConnectStart func(ConnectStartInfo)
	// ConnectDone is called once the socket is open, or the PacketConn is set
	// up, before the first handshake packet is sent. A socket that cannot be
	// opened is an AttemptFailed in phase open, with no ConnectDone.
	ConnectDone func(ConnectDoneInfo)
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
	// DisconnectStart is called when Disconnect begins saying goodbye to a
	// connected session. It is not called when there is no session.
	DisconnectStart func(DisconnectStartInfo)
	// DisconnectDone is called when the goodbye is over.
	DisconnectDone func(DisconnectDoneInfo)
	// SessionEnd is called once for every session that had a SessionStart,
	// however it ends, before the disconnected event is queued.
	SessionEnd func(SessionEndInfo)
	// ReconnectScheduled is called when the reconnect loop has decided to
	// retry and is about to wait.
	ReconnectScheduled func(ReconnectScheduledInfo)
	// ReconnectStopped is called when the reconnect loop ends without a
	// session: ShouldRetry declined, the attempts ran out, or Disconnect
	// stopped it.
	ReconnectStopped func(ReconnectStoppedInfo)
}

// WithTrace reports the milestones of the client's connection attempts and
// sessions to trace; see Trace for when each hook is called and what a hook may do.
//
// The client copies the struct: changing trace afterwards has no effect. A nil
// trace turns tracing off.
func WithTrace(trace *Trace) Option {
	return optionFunc(func(c *Client) {
		if trace == nil {
			c.trace = Trace{}

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
		logger.Error("trace hook panicked",
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
func (c *Client) traceResolveDone(attempt *connectAttempt, a attemptStamp, done ResolveDoneInfo) {
	c.mu.Lock()
	attempt.target = done.Target
	c.mu.Unlock()
	if c.trace.ResolveDone == nil || attempt.finished() {
		return
	}
	done.Addr, done.Attempt, done.Reconnect = c.addr, a.number, a.reconnect
	callHook(c.logger, "ResolveDone", c.trace.ResolveDone, done)
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

// traceConnectDone marks the attempt as opened, which makes a later failure a
// handshake failure, and reports ConnectDone, unless the attempt has already
// ended. It is called from the transport once the connection is attached,
// before the first handshake packet is sent.
func (c *Client) traceConnectDone(attempt *connectAttempt, a attemptStamp, target, localAddr string) {
	c.mu.Lock()
	attempt.opened = true
	connectStart := attempt.connectStart
	c.mu.Unlock()
	if c.trace.ConnectDone == nil || attempt.finished() {
		return
	}
	callHook(c.logger, "ConnectDone", c.trace.ConnectDone, ConnectDoneInfo{
		Target: target, LocalAddr: localAddr, Duration: time.Since(connectStart),
		Attempt: a.number, Reconnect: a.reconnect,
	})
}

// traceHandshakeDone reports HandshakeDone for the connection h ran, once its
// shared secret exists and before clientinit is sent. It does nothing when h
// is no longer the current connection's handler or its attempt has ended.
func (c *Client) traceHandshakeDone(h *transport.PacketHandler, serverPublicKey string) {
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
	puzzleLevel, puzzleDuration := h.TsCrypt.Puzzle()
	callHook(c.logger, "HandshakeDone", c.trace.HandshakeDone, HandshakeDoneInfo{
		Duration: time.Since(a.connectStart), Attempt: a.number, Reconnect: a.reconnect,
		PuzzleLevel: puzzleLevel, PuzzleDuration: puzzleDuration,
		Resends: h.Resends(), ServerPublicKey: serverPublicKey,
	})
}

// countWelcomeChannel counts a channel row of the welcome sequence, which the
// server sends as channellist before channellistfinished.
func (c *Client) countWelcomeChannel(h *transport.PacketHandler) {
	c.mu.Lock()
	if c.handler == h && !c.attempt.welcomeDone {
		c.attempt.channels++
	}
	c.mu.Unlock()
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
	channelID := c.clients[c.clid].ChannelID
	channels, clients := c.attempt.channels, len(c.clients)
	c.mu.Unlock()

	if !ok || c.trace.WelcomeDone == nil {
		return
	}
	callHook(c.logger, "WelcomeDone", c.trace.WelcomeDone, WelcomeDoneInfo{
		Duration: time.Since(a.connectStart), Attempt: a.number, Reconnect: a.reconnect,
		ChannelID: channelID, Channels: channels, Clients: clients,
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
	target := a.target
	waitingFor := a.waiting(c.handler != nil && c.handler.ClientEkPending())

	return func() {
		if traced && c.trace.AttemptFailed != nil {
			callHook(c.logger, "AttemptFailed", c.trace.AttemptFailed, AttemptFailedInfo{
				Phase: phase, Err: err, Target: target, WaitingFor: waitingFor, Duration: time.Since(stamp.resolveStart),
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
func (c *Client) startSessionLocked(initserver map[string]string) func() {
	a := c.attempt
	if !a.claim(nil) {
		return noReport
	}
	a.sessionStarted = true
	a.sessionStartedAt = time.Now()
	stamp, traced := c.stampLocked()
	info := SessionStartInfo{
		ClientID: c.clid, Capabilities: c.capabilities,
		Attempt: stamp.number, Reconnect: stamp.reconnect,
	}
	if traced && c.trace.SessionStart != nil {
		info.InitServer, info.Nickname, info.TalkPower = initServerInfo(initserver, c.nickname)
	}

	return func() {
		if traced && c.trace.SessionStart != nil {
			info.Duration = time.Since(stamp.connectStart)
			callHook(c.logger, "SessionStart", c.trace.SessionStart, info)
		}
		a.complete()
	}
}

// secretInitServerKeys are the initserver parameters that could carry a
// secret, left out of SessionStartInfo.InitServer.
var secretInitServerKeys = []string{
	"client_server_password", "client_default_channel_password", "client_default_token", "client_key_offset",
}

// initServerInfo reads from the parameters of initserver what SessionStart
// reports: a copy without the secret ones, the accepted nickname (requested
// when the server did not name one) and the talk power.
func initServerInfo(params map[string]string, requested string) (teamspeak.Properties, string, int32) {
	props := make(teamspeak.Properties, len(params))
	maps.Copy(props, params)
	for _, key := range secretInitServerKeys {
		delete(props, key)
	}
	nickname, ok := params["acn"]
	if !ok {
		nickname = requested
	}
	talkPower, err := strconv.ParseInt(params["client_talk_power"], 10, 32)
	if err != nil {
		talkPower = 0
	}

	return props, nickname, int32(talkPower)
}

// endSessionLocked decides that the session the current attempt started has
// ended with cause, nil for a Disconnect, and returns the report to run once
// the lock is released: SessionEnd. The report is a no-op when the session
// already ended or there was none, so a session is reported once however many
// paths end it; the report is nil when there is nothing to report. The caller
// holds c.mu and must call the report before the disconnected event is queued.
func (c *Client) endSessionLocked(cause error) func() {
	a := c.attempt
	if !a.sessionStarted || a.sessionEnded {
		return nil
	}
	a.sessionEnded = true
	stamp, traced := c.stampLocked()
	if !traced || c.trace.SessionEnd == nil {
		return nil
	}
	info := SessionEndInfo{
		ClientID: c.clid, Cause: cause, Attempt: stamp.number, Reconnect: stamp.reconnect,
	}
	started := a.sessionStartedAt

	return func() {
		info.Duration = time.Since(started)
		callHook(c.logger, "SessionEnd", c.trace.SessionEnd, info)
	}
}

// traceDisconnectStart reports DisconnectStart.
func (c *Client) traceDisconnectStart() {
	if c.trace.DisconnectStart != nil {
		callHook(c.logger, "DisconnectStart", c.trace.DisconnectStart, DisconnectStartInfo{})
	}
}

// traceDisconnectDone reports DisconnectDone.
func (c *Client) traceDisconnectDone(acknowledged bool, took time.Duration) {
	if c.trace.DisconnectDone != nil {
		callHook(c.logger, "DisconnectDone", c.trace.DisconnectDone,
			DisconnectDoneInfo{Acknowledged: acknowledged, Duration: took})
	}
}

// traceReconnectStopped reports ReconnectStopped.
func (c *Client) traceReconnectStopped(attempts int, cause error) {
	if c.trace.ReconnectStopped != nil {
		callHook(c.logger, "ReconnectStopped", c.trace.ReconnectStopped,
			ReconnectStoppedInfo{Attempts: attempts, Cause: cause})
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
