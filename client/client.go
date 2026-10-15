package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/discovery"
	"github.com/honeybbq/teamspeak-go/internal/identitykey"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/versions"
)

// ErrAlreadyConnected reports a Connect on a client that is already connected
// or connecting. It is teamspeak.ErrAlreadyConnected.
var ErrAlreadyConnected = teamspeak.ErrAlreadyConnected

var (
	errNoAddresses                 = errors.New("the host has no addresses")
	errClosedDuringHandshake       = errors.New("connection closed before the TeamSpeak handshake completed")
	errDisconnectedDuringHandshake = fmt.Errorf("%w: Disconnect was called before the handshake completed",
		teamspeak.ErrNotConnected)
)

// reconnectAttemptTimeout bounds each reconnection attempt.
const reconnectAttemptTimeout = 30 * time.Second

// resolveTimeout bounds address resolution, the default chain or a
// WithResolver one, which falls back to the address as given rather than
// failing, so a slow DNS or TSDNS server costs at most this much of a Connect.
const resolveTimeout = 10 * time.Second

// disconnectTimeout bounds the goodbye Disconnect sends, whatever deadline its
// context sets: the server's acknowledgement is a courtesy, and a connection
// that has already died would otherwise hold Disconnect for as long as the
// caller allowed.
const disconnectTimeout = time.Second

// ResolvedAddr is one endpoint a server address resolved to. Only Addr is
// required; Connect reads nothing else.
type ResolvedAddr struct {
	// Expiry is when the answer stops being valid; the zero time is unknown.
	Expiry time.Time
	// Addr is the endpoint, as host:port.
	Addr string
	// Source names how it was found, for logs: SRV, TSDNS, or the address as
	// given. It may be empty.
	Source string
}

// AddrResolver resolves a TeamSpeak server address to host:port endpoints.
// Implementations may replace the default chain (SRV, TSDNS, direct).
//
// Implementations must honour ctx. The client stops waiting for a resolution
// when its budget is spent, but cannot stop the resolver: one that ignores ctx
// keeps its goroutine, and whatever it holds, until it returns.
type AddrResolver interface {
	// Resolve returns the addresses to try for addr, in order.
	Resolve(ctx context.Context, addr string) ([]ResolvedAddr, error)
}

// defaultResolver is the SRV, TSDNS and direct chain.
type defaultResolver struct {
	resolver *discovery.Resolver
}

func (d defaultResolver) Resolve(ctx context.Context, addr string) ([]ResolvedAddr, error) {
	found, err := d.resolver.Resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	out := make([]ResolvedAddr, len(found))
	for i, f := range found {
		out[i] = ResolvedAddr(f)
	}

	return out, nil
}

// CommandMiddleware wraps the typed commands' executor. It sees each request —
// its name with Request.Command, never its parameters' secrets in a log line —
// and the caller's context, and returns the rows or an error: so it can
// observe a command, time it, retry it, or answer it itself without calling
// next.
//
// Exec and ExecNoWait, which send a raw line, and the commands the client
// sends on its own during the handshake and Disconnect do not pass through it.
type CommandMiddleware func(next teamspeak.Executor) teamspeak.Executor

// EventMiddleware wraps the delivery of server events. It may observe an
// event, pass on a different one in its place, or drop it by not calling next.
type EventMiddleware func(next func(Event)) func(Event)

// clientInitOptions are what clientinit sends besides the identity. The
// passwords are held only as the hashes the voice protocol sends,
// base64(sha1(password)), computed once when the option is applied: the
// plaintext is never kept.
type clientInitOptions struct {
	serverPasswordHash         string
	defaultChannel             string
	defaultChannelPasswordHash string
	// version is held by value, so changing the caller's copy afterwards has
	// no effect.
	version versions.ClientVersion
}

// String describes the options without the password hashes, which the
// server accepts as the passwords themselves.
func (o clientInitOptions) String() string {
	return fmt.Sprintf("{defaultChannel:%q serverPassword:%s defaultChannelPassword:%s}",
		o.defaultChannel, redacted(o.serverPasswordHash), redacted(o.defaultChannelPasswordHash))
}

// GoString is String, so %#v redacts too.
func (o clientInitOptions) GoString() string { return o.String() }

func redacted(secret string) string {
	if secret == "" {
		return "none"
	}

	return "redacted"
}

// typedCommands names teamspeak.Commands under an unexported name, so the
// embedded field promotes the typed commands as the client's methods but
// cannot be replaced from outside.
type typedCommands = teamspeak.Commands

// Client is a TeamSpeak client speaking the voice protocol, for TeamSpeak 3
// and TeamSpeak 6 servers.
//
// The typed commands of teamspeak.Commands — ListChannels, MoveClient and the
// rest — are its methods, running on Send.
type Client struct {
	*typedCommands

	resolver AddrResolver
	// lookupNicknames turns on the MyTeamSpeak nickname lookup in the
	// default resolver.
	lookupNicknames bool
	identity        *identity.Identity
	attempt         *connectAttempt
	// trace is the caller's Trace, copied by WithTrace.
	trace  Trace
	logger *slog.Logger
	// handler is the current connection's packet handler, which owns that
	// connection's crypto state. It is replaced, under mu, by every Connect;
	// read it with currentHandler.
	handler  *transport.PacketHandler
	cmdTrack *commandTracker
	throttle *commandThrottle
	clients  map[teamspeak.ClientID]teamspeak.ClientEntry
	// evtChain is the event middleware wrapped around dispatchEvent.
	evtChain func(Event)
	addr     string
	nickname string
	// uidAlgorithm is the hash the connected server uses for
	// client_unique_identifier, learned from virtualserver_version during
	// initserver: SHA-1 on TS3, SHA-256 on TS6.
	uidAlgorithm identity.UIDAlgorithm
	// capabilities is what the server reported about itself in initserver.
	capabilities ServerCapabilities
	// packetConn, when set, replaces the UDP socket the transport would
	// otherwise dial. It is the seam for proxies, tunnels and tests.
	packetConn net.PacketConn
	// clientInitOptions is behind a pointer so that even a Client value
	// printed field by field shows an address, not the password hashes.
	clientInitOptions *clientInitOptions
	// reconnectOptions is nil unless WithReconnect turned reconnection on.
	reconnectOptions *ReconnectOptions
	// reconnecting guards against competing retry loops after two failures in
	// quick succession.
	reconnecting bool
	// reconnectPending records a drop that arrived while a retry loop still
	// held the slot, with its cause, so endReconnect can start another loop
	// rather than lose it.
	reconnectPending        bool
	reconnectPendingErr     error
	reconnectPendingVerdict *retryVerdict
	// attemptVerdict is the verdict on the reconnect attempt that just failed,
	// left by failConnectionLocked for the loop to take.
	attemptVerdict *retryVerdict
	// background counts the goroutines the client starts on its own behalf
	// that nobody waits on, so a test can wait for them instead of sleeping.
	background sync.WaitGroup
	// stopped is set by an explicit Disconnect, which must never be undone by a
	// retry.
	stopped bool
	// stop is closed while stopped is set, so a wait can select on it instead
	// of polling; it is replaced by a fresh channel when Connect clears the
	// stop. Read it with stopChan; change it only through setStoppedLocked.
	stop chan struct{}
	// leaving is the Disconnect saying goodbye, nil when there is none.
	leaving *leaving
	// goodbye is closed when the server announces that this client left while
	// a Disconnect waits for its goodbye to be answered; nil otherwise.
	goodbye chan struct{}
	// disconnects counts Disconnect calls, so a Connect waiting for one to
	// finish can tell whether another arrived meanwhile.
	disconnects    uint64
	cmdMiddlewares []CommandMiddleware
	// executor is the command middleware wrapped around the client's own
	// executor; Send runs requests through it.
	executor teamspeak.Executor
	// wireHook, when set, sees every encoded line before it is sent and may
	// stop it with an error. A seam for tests.
	wireHook         func(line string) error
	eventMiddlewares []EventMiddleware
	events           eventQueue
	onTextMessage    subscribers[TextMessageEvent]
	onClientEnter    subscribers[ClientEnterEvent]
	onClientLeave    subscribers[ClientLeaveEvent]
	onClientMoved    subscribers[ClientMovedEvent]
	onConnected      subscribers[ConnectedEvent]
	onDisconnected   subscribers[DisconnectedEvent]
	onPoked          subscribers[PokeEvent]
	onKicked         subscribers[KickedEvent]
	onVoiceData      subscribers[VoiceDataEvent]
	onNotification   subscribers[NotificationEvent]
	status           Status
	mu               sync.Mutex
	clid             teamspeak.ClientID
}

// String describes the client by its address, nickname and status. It, and
// GoString and LogValue, never include the passwords, their hashes or the
// identity's private key, so a client that reaches a log or an error message
// leaks none of them.
func (c *Client) String() string {
	nickname, status := c.describe()

	return fmt.Sprintf("teamspeak client %q at %s (%s)", nickname, c.addr, status)
}

// GoString is String, so %#v redacts too.
func (c *Client) GoString() string { return c.String() }

// LogValue describes the client to log/slog as String does.
func (c *Client) LogValue() slog.Value {
	nickname, status := c.describe()

	return slog.GroupValue(
		slog.String("nickname", nickname),
		slog.String("address", c.addr),
		slog.String("status", status.String()),
	)
}

// ErrInvalidConfig reports a client New cannot build as configured.
var ErrInvalidConfig = errors.New("invalid client configuration")

// New returns a client that will connect to addr as id, under nickname. It does
// not connect; call Connect.
//
// addr is a host or host:port, resolved through SRV and TSDNS records as the
// TeamSpeak application does; with WithNicknameLookup it may also be a
// MyTeamSpeak nickname.
func New(id *identity.Identity, addr, nickname string, options ...Option) (*Client, error) {
	if identitykey.PrivateKey(id) == nil {
		return nil, fmt.Errorf("%w: no identity", ErrInvalidConfig)
	}
	if addr == "" {
		return nil, fmt.Errorf("%w: no server address", ErrInvalidConfig)
	}

	c := &Client{
		identity:          id,
		clientInitOptions: &clientInitOptions{version: defaultClientVersion},
		status:            StatusDisconnected,
		// Silent unless the application asks: a library has no business
		// writing to the application's default logger.
		logger:   slog.New(slog.DiscardHandler),
		addr:     addr,
		nickname: nickname,
		clients:  make(map[teamspeak.ClientID]teamspeak.ClientEntry),
		throttle: newCommandThrottle(),
		cmdTrack: newCommandTracker(),
		attempt:  newConnectAttempt(),
		stop:     make(chan struct{}),
	}

	c.typedCommands = teamspeak.NewCommands(c)

	for _, opt := range options {
		opt.apply(c)
	}

	err := validateClientVersion(c.clientInitOptions.version)
	if err != nil {
		return nil, err
	}

	c.handler = c.newHandler()
	if c.resolver == nil {
		c.resolver = defaultResolver{resolver: discovery.NewResolver(c.logger, c.lookupNicknames)}
	}

	c.buildMiddlewareChains()

	return c, nil
}

// Option configures a Client. Build one with the With functions.
type Option interface {
	apply(c *Client)
}

type optionFunc func(*Client)

func (f optionFunc) apply(c *Client) { f(c) }

// WithLogger sends the client's logs to logger. Without it the client is
// silent.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	})
}

// WithPacketConn dials no socket and instead runs the session over pc.
//
// The transport is otherwise closed: this is the only way to route traffic
// through a proxy or tunnel, or to drive the client from something that is not
// a real socket. pc must deliver whole datagrams, one per Read, and honour
// SetReadDeadline: closing a connection sets pc's read deadline to stop its
// reader, and the next Connect clears it. pc itself is never closed.
//
// ReadFrom must report the server's address as each datagram's source:
// datagrams from any other source are dropped, so another peer that can reach
// pc cannot inject packets into the session.
//
// The servers ignore a new handshake from the address of a session that ended
// a few seconds earlier, so a Connect on the same pc right after a Disconnect
// stalls until that has passed.
func WithPacketConn(pc net.PacketConn) Option {
	return optionFunc(func(c *Client) {
		c.packetConn = pc
	})
}

// WithReconnect reconnects after a dropped connection.
//
// Off unless this is set. A deliberate Disconnect never reconnects, whatever
// the policy says: retrying would keep a process alive that asked to stop.
func WithReconnect(options ReconnectOptions) Option {
	return optionFunc(func(c *Client) {
		c.reconnectOptions = &options
	})
}

// WithNicknameLookup makes the default resolver look a dot-less address up as
// a MyTeamSpeak nickname, at named.myteamspeak.com, before resolving it as a
// host. Off unless this is set: the lookup tells MyTeamSpeak which server the
// user is connecting to. It has no effect with WithResolver.
func WithNicknameLookup() Option {
	return optionFunc(func(c *Client) {
		c.lookupNicknames = true
	})
}

// WithResolver replaces the address resolver Connect uses.
func WithResolver(r AddrResolver) Option {
	return optionFunc(func(c *Client) {
		c.resolver = r
	})
}

// WithCommandMiddleware wraps every typed command, outermost first. See
// CommandMiddleware for what it sees and what it does not.
func WithCommandMiddleware(mw ...CommandMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.cmdMiddlewares = append(c.cmdMiddlewares, mw...)
	})
}

// WithEventMiddleware wraps every server event before it reaches the handlers,
// outermost first. Lifecycle events (connected, disconnected, kicked) do not
// pass through it.
func WithEventMiddleware(mw ...EventMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.eventMiddlewares = append(c.eventMiddlewares, mw...)
	})
}

// WithServerPassword sets the server password sent when connecting.
func WithServerPassword(password string) Option {
	return optionFunc(func(c *Client) {
		c.clientInitOptions.serverPasswordHash = prepareClientPassword(password)
	})
}

// WithDefaultChannel sets the channel to join when connecting.
func WithDefaultChannel(channel string) Option {
	return optionFunc(func(c *Client) {
		c.clientInitOptions.defaultChannel = channel
	})
}

// WithDefaultChannelPassword sets the default channel's password.
func WithDefaultChannelPassword(password string) Option {
	return optionFunc(func(c *Client) {
		c.clientInitOptions.defaultChannelPasswordHash = prepareClientPassword(password)
	})
}

// WithVersion sets the platform, version and signature clientinit sends.
// Without it the client sends a recent Windows build.
//
// Pick one from the versions package: only those carry a signature a server
// accepts, and a server refuses a build below its configured minimum. New
// returns ErrInvalidConfig if a field is empty or Sign is not the base64 of 64
// bytes; it does not check the signature itself, which the server does.
func WithVersion(v versions.ClientVersion) Option {
	return optionFunc(func(c *Client) {
		c.clientInitOptions.version = v
	})
}

// Connect connects to the server and returns once the handshake completes.
//
// A failed attempt returns its cause, such as the server's error for a
// rejected password. If ctx is done first, the attempt is abandoned and its
// error returned. Connect does not retry; WithReconnect only retries a
// connection that drops after it was established.
//
// ctx bounds only the connecting: once Connect returns, the connection lasts
// until Disconnect or a drop.
//
// An address that cannot be one fails at once with an error wrapping
// ErrInvalidAddress. On success the connected event is queued, and delivered
// on the event goroutine: register OnConnected before Connect to hear it.
//
// Called while a Disconnect is still saying goodbye, Connect waits for it
// first, so the old session is closed, and its disconnected event queued,
// before the new one starts. Events reach the handlers through one ordered
// queue, so they see the old session's disconnected before the new session's
// connected and before any other event of the new session. A Disconnect
// called during that wait, or during the handshake, wins: Connect then returns
// teamspeak.ErrNotConnected.
//
// Connect does not wait for event handlers, so a handler may call it.
func (c *Client) Connect(ctx context.Context) error {
	return c.connect(ctx, true, 1)
}

// Disconnect leaves the server and closes the connection.
//
// It says goodbye first, waiting for the server's acknowledgement for a second
// at most, or until ctx is done if that is sooner. The connection is closed
// either way. A Connect still waiting for its handshake returns
// teamspeak.ErrNotConnected, and so do the commands still waiting for an
// answer, and a reconnect still pending or waiting out its backoff is
// cancelled. Disconnect returns once the connection is closed and its
// disconnected event queued; the handlers run later, in order, ahead of any
// event of a session a later Connect starts. Disconnect on a client that is
// not connected does nothing; called while an earlier Disconnect is still
// saying goodbye, it waits for that one and returns its result.
//
// Disconnect does not wait for event handlers, so a handler may call it.
func (c *Client) Disconnect(ctx context.Context) error {
	return c.disconnect(ctx, nil)
}

// disconnect is Disconnect. With a non-nil only, it acts only while only is
// still the current handler, checked under the lock: a disconnect decided on
// for one connection must not end the next.
func (c *Client) disconnect(ctx context.Context, only *transport.PacketHandler) error {
	c.mu.Lock()
	if only != nil && c.handler != only {
		c.mu.Unlock()

		return nil
	}
	// Recorded before anything else: a dropped socket during the goodbye below
	// must not be mistaken for an outage worth retrying.
	c.setStoppedLocked(true)
	c.disconnects++
	if l := c.leaving; l != nil {
		// Another Disconnect is saying goodbye: join it.
		c.mu.Unlock()

		return l.wait(ctx)
	}
	oldStatus := c.status
	if oldStatus == StatusDisconnected {
		c.mu.Unlock()

		return nil
	}
	c.status = StatusDisconnected
	report := c.endAttemptLocked(errDisconnectedDuringHandshake)
	sessionEnd := c.endSessionLocked(nil)
	handler := c.handler
	l := &leaving{done: make(chan struct{})}
	c.leaving = l
	c.mu.Unlock()
	report()

	c.logger.InfoContext(ctx, "disconnecting from server")

	if oldStatus == StatusConnected {
		c.sayGoodbye(ctx, handler)
	}

	err := handler.Close()
	// Before finishLeaving queues disconnected.
	if sessionEnd != nil {
		sessionEnd()
	}
	c.finishLeaving(l, err)

	return err
}

// sayGoodbye tells the server on handler that the client is leaving, waiting
// for its acknowledgement for disconnectTimeout at most, with the trace's
// DisconnectStart and DisconnectDone.
func (c *Client) sayGoodbye(ctx context.Context, handler *transport.PacketHandler) {
	c.traceDisconnectStart()
	start := time.Now()
	goodbyeCtx, cancel := context.WithTimeout(ctx, disconnectTimeout)

	// The server answers clientdisconnect with a notifyclientleftview about
	// this client and no error line, so either one ends the wait.
	left := make(chan struct{})
	c.mu.Lock()
	c.goodbye = left
	c.mu.Unlock()
	answered := make(chan error, 1)
	go func() {
		_, err := c.execOn(goodbyeCtx, handler, "clientdisconnect reasonmsg=Shutdown")
		answered <- err
	}()
	var acknowledged bool
	select {
	case err := <-answered:
		acknowledged = err == nil
	case <-left:
		acknowledged = true
	}
	cancel()
	c.mu.Lock()
	c.goodbye = nil
	c.mu.Unlock()
	c.traceDisconnectDone(acknowledged, time.Since(start))
}

// finishLeaving ends Disconnect l with err: it fails the commands still
// waiting and queues disconnected, under the lock and before leaving is
// cleared. A Connect waits for that, so no new session has started whose
// commands the reset could fail, and the old session's disconnected is queued
// ahead of anything the new session queues.
func (c *Client) finishLeaving(l *leaving, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cmdTrack.reset(teamspeak.ErrNotConnected)
	// Announced here; handleConnectionClosed stays quiet once the status is
	// already Disconnected, so the handlers hear about it once.
	emit(c, &c.onDisconnected, "Disconnected", DisconnectedEvent{})
	c.leaving = nil
	l.err = err
	close(l.done)
}

// waitLeavingLocked waits for any Disconnect still saying goodbye, releasing
// c.mu meanwhile and holding it again on return. The goodbye involves no event
// handler, so a handler may wait for it. It fails if ctx ends first, or with
// errDisconnectedDuringHandshake if another Disconnect arrives: that one wins
// over the Connect waiting.
func (c *Client) waitLeavingLocked(ctx context.Context) error {
	disconnects := c.disconnects
	for c.leaving != nil {
		l := c.leaving
		c.mu.Unlock()
		_ = l.wait(ctx) // its own result is the Disconnect's
		c.mu.Lock()
		err := ctx.Err()
		if err != nil {
			return err
		}
	}
	if c.disconnects != disconnects {
		return errDisconnectedDuringHandshake
	}

	return nil
}

// leaving is a Disconnect saying goodbye. done is closed once it has closed
// the connection and queued disconnected; err, written before, is its result.
type leaving struct {
	done chan struct{}
	err  error
}

// wait returns the Disconnect's result once it has finished, or ctx's error if
// ctx ends first.
func (l *leaving) wait(ctx context.Context) error {
	select {
	case <-l.done:
		return l.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// describe snapshots what String and LogValue show. The nickname changes when
// the server renames the client, so it is read under the lock.
func (c *Client) describe() (string, Status) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.nickname, c.status
}

// connect runs one connection attempt. Only an explicit Connect (fromCaller)
// undoes a Disconnect; a reconnect that finds the client stopped gives up,
// whenever the Disconnect landed.
func (c *Client) connect(ctx context.Context, fromCaller bool, number int) error {
	attempt, handler, err := c.start(ctx, fromCaller, number)
	if err != nil {
		return err
	}

	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		// Abandon the attempt. The handshake may have completed meanwhile, in
		// which case failConnection leaves the session alone and Connect
		// reports the connection it made rather than one the caller would
		// believe had failed.
		c.failConnection(handler, ctx.Err())
		<-attempt.done

		return attempt.err
	}
}

// start resets the session and begins the handshake, returning the attempt
// that the handshake will resolve and the handler running it. fromCaller clears a previous Disconnect;
// otherwise a stopped client is refused with errStopped, checked under the
// same lock Disconnect takes so that one landing just before cannot be undone.
func (c *Client) start(
	ctx context.Context, fromCaller bool, number int,
) (*connectAttempt, *transport.PacketHandler, error) {
	// Checked before anything changes: an address that can never work leaves
	// the client as it was, with no attempt to announce the end of.
	err := validateAddress(c.addr)
	if err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	err = c.mayStartLocked(ctx, fromCaller)
	if err != nil {
		c.mu.Unlock()

		return nil, nil, err
	}

	// The handler resetForConnectLocked wires up reconnects on its own context:
	// a reconnection outlives the Connect that started the session.
	previous := c.handler
	finalAddr := c.resetForConnectLocked() //nolint:contextcheck // see above
	attempt := c.attempt
	attempt.begin(number, !fromCaller)
	stamp, _ := c.stampLocked()

	c.status = StatusConnecting
	handler := c.handler
	packetConn := c.packetConn
	c.mu.Unlock()

	err = c.resolveAndOpen(ctx, attempt, stamp, previous, handler, packetConn, finalAddr)
	if err != nil {
		// Without this the client stays in StatusConnecting and every later
		// Connect fails with ErrAlreadyConnected.
		c.failConnection(handler, err)
		// A Disconnect while the socket was opening closes it under the open,
		// which then fails with "use of closed network connection". The
		// attempt already holds the real outcome; report that.
		<-attempt.done
		if attempt.err != nil {
			err = attempt.err
		}

		return nil, nil, err
	}

	return attempt, handler, nil
}

// resolveAndOpen resolves the server's address and opens the transport, with
// the trace milestones of both.
func (c *Client) resolveAndOpen(
	ctx context.Context, attempt *connectAttempt, stamp attemptStamp,
	previous, handler *transport.PacketHandler, packetConn net.PacketConn, finalAddr string,
) error {
	c.traceResolveStart(stamp)
	resolveBegan := time.Now()
	targetAddr, source, candidates, resolveErr := c.resolveConnectTarget(ctx, finalAddr)
	c.traceResolveDone(attempt, stamp, ResolveDoneInfo{
		Target: targetAddr, Source: source, Candidates: candidates, Err: resolveErr,
		Duration: time.Since(resolveBegan),
	})
	c.logger.InfoContext(ctx, "connecting to server", slog.String("address", targetAddr), slog.String("source", source))

	// A resolver's answer is checked as the caller's address is.
	err := validateAddress(targetAddr)
	if err == nil {
		c.traceConnectStart(attempt, stamp, targetAddr)
		// ConnectDone comes from the transport, once the connection is
		// attached and before the first handshake packet goes out.
		handler.OnOpen = func(localAddr string) { c.traceConnectDone(attempt, stamp, targetAddr, localAddr) }
		err = open(ctx, previous, handler, packetConn, targetAddr)
	}

	return err
}

// mayStartLocked reports whether a connection attempt may start, with the
// lock held, waiting first for a Disconnect still saying goodbye: the old
// session is closed, and its end announced, before the new one starts, and a
// Disconnect called meanwhile wins. fromCaller clears an earlier Disconnect;
// otherwise a stopped client is refused with errStopped.
func (c *Client) mayStartLocked(ctx context.Context, fromCaller bool) error {
	err := c.waitLeavingLocked(ctx)
	if err != nil {
		return err
	}
	if fromCaller {
		c.setStoppedLocked(false)
	} else if c.stopped {
		return errStopped
	}
	if c.status != StatusDisconnected {
		return ErrAlreadyConnected
	}

	return nil
}

// open starts handler on the caller's PacketConn, if there is one, or on a
// socket dialled to targetAddr.
func open(
	ctx context.Context, previous, handler *transport.PacketHandler, packetConn net.PacketConn, targetAddr string,
) error {
	if packetConn != nil {
		return startOnPacketConn(ctx, previous, handler, packetConn, targetAddr)
	}

	return handler.Connect(ctx, targetAddr)
}

// startOnPacketConn starts handler on the caller's PacketConn, sending to
// targetAddr. The PacketConn outlives each connection, so the previous
// handler's reader must have stopped first: two readers would split the
// datagrams between them.
func startOnPacketConn(
	ctx context.Context, previous, handler *transport.PacketHandler, packetConn net.PacketConn, targetAddr string,
) error {
	if previous != nil {
		err := previous.WaitReaderStopped(ctx)
		if err != nil {
			return err
		}
	}
	// The adapter needs the peer address to send to; resolve it the same way
	// the dialling path would, without opening a socket.
	remote, err := resolveUDPAddr(ctx, targetAddr)
	if err != nil {
		return err
	}

	return handler.Start(transport.NewPacketConnAdapter(packetConn, remote))
}

// resolveUDPAddr resolves host:port, bounded by ctx.
func resolveUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", portStr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", errNoAddresses, host)
	}

	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0].Unmap(), uint16(port))), nil //nolint:gosec // a port
}

// validateAddress checks that addr, a host or host:port with 9987 as the
// default port, can be a server address, and returns an error wrapping
// ErrInvalidAddress if not.
func validateAddress(addr string) error {
	host, port := discovery.SplitHostPortOrDefault(addr, "9987")
	switch {
	case host == "":
		return fmt.Errorf("%w %q: no host", ErrInvalidAddress, addr)
	case strings.ContainsFunc(host, notInAHost),
		// A colon is left only in an IPv6 literal; anywhere else it is a port
		// that is not a number, which the split keeps as part of the host.
		strings.Contains(host, ":") && !isIPv6(host):
		return fmt.Errorf("%w %q: not a host name, IP address or host:port", ErrInvalidAddress, addr)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("%w %q: port %s is not from 1 to 65535", ErrInvalidAddress, addr, port)
	}

	return nil
}

// notInAHost reports a character no host name or IP address contains.
func notInAHost(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("/?#@[]\\", r)
}

func isIPv6(host string) bool {
	ip, err := netip.ParseAddr(host)

	return err == nil && ip.Is6()
}

func (c *Client) resetForConnectLocked() string {
	if c.handler != nil {
		_ = c.handler.Close()
	}
	c.handler = c.newHandler()
	// Keep an attempt nobody has resolved yet: something may already be
	// waiting on it, and must be released by this connection's handshake.
	if c.attempt.claimed {
		c.attempt = newConnectAttempt()
	}
	c.cmdTrack.reset(teamspeak.ErrNotConnected)
	c.clients = make(map[teamspeak.ClientID]teamspeak.ClientEntry)
	c.clid = 0
	// Reset to the TS3 default; initserver sets it from the server's version.
	c.uidAlgorithm = identity.UIDSHA1

	c.capabilities = unknownServerCapabilities()

	// Fallback used only if resolution fails. A colon check would misread any
	// IPv6 literal as already carrying a port.
	host, port := discovery.SplitHostPortOrDefault(c.addr, "9987")

	return net.JoinHostPort(host, port)
}

// resolveConnectTarget resolves the client's address within resolveTimeout,
// the budget for the whole of resolution. The resolver — the default chain or
// the caller's own — gets a context with that deadline, and is not waited for
// past it even if it ignores the context.
func (c *Client) resolveConnectTarget(
	ctx context.Context, fallbackAddr string,
) (string, string, []ResolvedAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	type answer struct {
		err      error
		resolved []ResolvedAddr
	}
	answered := make(chan answer, 1)
	go func() {
		resolved, err := c.resolver.Resolve(ctx, c.addr)
		answered <- answer{resolved: resolved, err: err}
	}()
	var resolved []ResolvedAddr
	var err error
	select {
	case a := <-answered:
		resolved, err = a.resolved, a.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil || len(resolved) == 0 {
		// An empty answer used to index resolved[0] and panic.
		c.logger.WarnContext(ctx, "address resolution failed, falling back to direct", slog.Any("error", err))

		return fallbackAddr, "Fallback", nil, err
	}

	return resolved[0].Addr, resolved[0].Source, resolved, nil
}

// newHandler creates a packet handler wired to this client. Its OnClosed is
// bound to the handler instance, so a close reported late by a handler that a
// later Connect already replaced cannot tear down the new connection.
func (c *Client) newHandler() *transport.PacketHandler {
	h := transport.NewPacketHandler(crypto.NewCrypt(c.identity), c.logger)
	h.OnPacket = func(p *transport.Packet) {
		c.handlePacket(h, p)
	}
	h.OnClosed = func(err error) {
		c.handleConnectionClosed(h, err)
	}

	return h
}

// failConnection ends a connection attempt that can no longer succeed: it
// records the cause for Connect to return, closes the transport, and reports the
// cause to disconnected handlers. It does nothing once the handshake has
// completed, so it cannot tear down a live session.
//
// Without it, a handshake the server rejects (a wrong password, say, which the
// server answers with an error instead of closing the socket) surfaced only as
// the caller's own timeout, and the client stayed in
// StatusConnecting forever without emitting disconnected.
//
// h is the handler whose connection failed. If a later Connect has replaced
// it, the failure was that earlier connection's and is ignored: checked under
// the lock, so it cannot land on the new attempt.
func (c *Client) failConnection(h *transport.PacketHandler, err error) {
	c.mu.Lock()
	if c.handler != h {
		c.mu.Unlock()
		c.logger.Debug("ignoring a failure of a replaced connection", slog.Any("error", err))

		return
	}
	c.failConnectionLocked(err)
}

// failConnectionLocked is failConnection for a caller already holding c.mu,
// which it releases.
func (c *Client) failConnectionLocked(err error) {
	if c.status == StatusConnected {
		c.mu.Unlock()

		return
	}
	// The report runs with the lock released: the AttemptFailed hook may read
	// the client.
	report := c.endAttemptLocked(err)
	if c.status == StatusDisconnected {
		c.mu.Unlock()
		report()

		return
	}
	c.status = StatusDisconnected
	handler := c.handler
	c.emitDisconnectedLocked(err, c.failedAttemptVerdictLocked(err))
	c.mu.Unlock()
	report()

	_ = handler.Close()
}

// handleConnectionClosed ends the session handler h ran, or the current one
// when h is nil.
//
// Whether h is still the current handler is checked under the same lock as
// the status it acts on. Checking it first and acting after let a close
// reported late by the previous connection's handler land just after a new
// Connect had begun, and fail that attempt instead.
func (c *Client) handleConnectionClosed(h *transport.PacketHandler, err error) {
	c.mu.Lock()
	if h != nil && c.handler != h {
		c.mu.Unlock()

		return
	}
	// Nothing in flight can be answered any more; failing it now, with the
	// reason, beats every caller timing out one by one. Harmless after a
	// deliberate Disconnect, which has already done it. Under the lock, so a
	// new connection's commands are not failed for the old one's close.
	cause := teamspeak.ErrNotConnected
	if err != nil {
		cause = fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, err)
	}
	c.cmdTrack.reset(cause)

	if c.status == StatusDisconnected {
		c.mu.Unlock()

		return
	}
	if c.status == StatusConnecting {
		// The socket closed before the handshake finished: a failed attempt,
		// not the end of a live session.
		switch {
		case err == nil:
			err = errClosedDuringHandshake
		case errors.Is(err, transport.ErrPacketHandling):
			err = fmt.Errorf("%w: %w", ErrHandshake, err)
		}
		c.failConnectionLocked(err)

		return
	}
	c.status = StatusDisconnected
	if err == nil {
		err = errConnectionClosed
	}
	c.runSessionEndLocked(c.endSessionLocked(err))
	// Announced first, then retried: a caller watching OnDisconnected should
	// hear about the drop even when a reconnect is already on its way, because
	// a silent recovery hides an outage.
	verdict := c.newVerdictLocked(err, 1)
	c.emitDisconnectedLocked(err, verdict)
	c.mu.Unlock()

	go c.scheduleReconnect(err, verdict)
}

// runSessionEndLocked runs the SessionEnd report, if there is one, with c.mu
// released and held again on return, so that the hook runs with no lock held
// but still before disconnected is queued. A leaving stands in for a
// Disconnect meanwhile, so a Connect waits for it as it waits for one, and the
// old session's disconnected still comes before the new one's connected.
func (c *Client) runSessionEndLocked(report func()) {
	if report == nil {
		return
	}
	l := &leaving{done: make(chan struct{})}
	c.leaving = l
	c.mu.Unlock()
	report()
	c.mu.Lock()
	c.leaving = nil
	close(l.done)
}

// scheduleReconnect retries a dropped connection according to the policy.
//
// Never runs after an explicit Disconnect, and never more than one at a time:
// two failures in quick succession would otherwise start competing loops, and a
// loop shorter than the server's antiflood window bans the IP rather than
// reconnecting it.
//
//nolint:funlen // one loop with its exits, each of which reports why it ended
func (c *Client) scheduleReconnect(connErr error, verdict *retryVerdict) {
	if verdict == nil {
		c.mu.Lock()
		verdict = c.newVerdictLocked(connErr, 1)
		c.mu.Unlock()
	}

	options, ok := c.beginReconnect(connErr, verdict)
	if !ok {
		return
	}

	defer c.endReconnect()

	// The loop's logging context; it ends with the loop or when Disconnect
	// stops the client.
	ctx, cancel := contextUntil(context.Background(), c.stopChan())
	defer cancel()

	made := 0
	for attempt := 1; options.Backoff.MaxAttempts == 0 || attempt <= options.Backoff.MaxAttempts; attempt++ {
		if c.isStopped() {
			c.traceReconnectStopped(made, nil)

			return
		}
		if !verdict.policy() {
			c.logger.InfoContext(ctx, "not retrying", slog.Int("attempt", attempt), slog.Any("error", connErr))
			c.traceReconnectStopped(made, connErr)

			return
		}

		delay := options.Backoff.Delay(attempt)
		c.logger.InfoContext(ctx, "reconnecting", slog.Int("attempt", attempt), slog.Duration("delay", delay))
		c.traceReconnectScheduled(attempt, delay, connErr)

		if !c.sleepWhileRunning(delay) {
			c.traceReconnectStopped(made, nil)

			return
		}

		retryErr := c.runConnect(attempt)
		if !errors.Is(retryErr, errStopped) && !errors.Is(retryErr, ErrAlreadyConnected) {
			made++
		}
		if retryErr == nil {
			c.logger.InfoContext(ctx, "reconnected", slog.Int("attempt", attempt))

			return
		}
		// Stopped: a Disconnect landed between the check above and the
		// attempt. Already connected: the caller reconnected by hand. Either
		// way there is nothing left to retry.
		if errors.Is(retryErr, errStopped) || errors.Is(retryErr, ErrAlreadyConnected) {
			c.logger.InfoContext(ctx, "reconnect no longer needed", slog.Any("reason", retryErr))
			if errors.Is(retryErr, errStopped) {
				retryErr = nil
			}
			c.traceReconnectStopped(made, retryErr)

			return
		}

		connErr = retryErr
		verdict = c.takeVerdict(retryErr, attempt+1)
		if options.ShouldRetry == nil && !verdict.policy() {
			c.logger.InfoContext(ctx, "reconnect refused", slog.Int("attempt", attempt), slog.Any("error", retryErr))
			c.traceReconnectStopped(made, retryErr)

			return
		}
	}

	c.logger.WarnContext(ctx, "reconnect attempts exhausted", slog.Int("attempts", options.Backoff.MaxAttempts))
	c.traceReconnectStopped(made, connErr)
}

// runConnect makes reconnection attempt number attempt.
//
// The attempt belongs to the client, not to any caller: it ends when it times
// out or when Disconnect stops the client, whichever comes first.
func (c *Client) runConnect(attempt int) error {
	stopCtx, stopCancel := contextUntil(context.Background(), c.stopChan())
	defer stopCancel()
	ctx, cancel := context.WithTimeout(stopCtx, reconnectAttemptTimeout)
	defer cancel()

	return c.connect(ctx, false, attempt)
}

// beginReconnect claims the reconnect slot, reporting false when reconnection
// is off, already running, or the client has been stopped deliberately.
func (c *Client) beginReconnect(connErr error, verdict *retryVerdict) (ReconnectOptions, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.reconnectOptions == nil || c.stopped {
		return ReconnectOptions{}, false
	}
	if c.reconnecting {
		// The running loop may already be past its last look at the status,
		// for instance between a handshake that succeeded and endReconnect.
		// Leave a note so the drop is retried once it ends.
		c.reconnectPending = true
		c.reconnectPendingErr = connErr
		c.reconnectPendingVerdict = verdict

		return ReconnectOptions{}, false
	}
	c.reconnecting = true
	c.attemptVerdict = nil

	return *c.reconnectOptions, true
}

// endReconnect releases the slot so a later drop can be retried, and retries
// one that arrived while the loop held it, unless the client is stopped or no
// longer disconnected.
func (c *Client) endReconnect() {
	c.mu.Lock()
	c.reconnecting = false
	pending, pendingErr, pendingVerdict := c.reconnectPending, c.reconnectPendingErr, c.reconnectPendingVerdict
	c.reconnectPending, c.reconnectPendingErr, c.reconnectPendingVerdict = false, nil, nil
	restart := pending && !c.stopped && c.status == StatusDisconnected
	c.mu.Unlock()

	if restart {
		go c.scheduleReconnect(pendingErr, pendingVerdict)
	}
}

// isStopped reports whether an explicit Disconnect has happened.
func (c *Client) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stopped
}

// setStoppedLocked records an explicit Disconnect, or its undoing by Connect,
// and keeps the stop channel in step. The caller holds c.mu.
func (c *Client) setStoppedLocked(stopped bool) {
	if stopped == c.stopped {
		return
	}
	c.stopped = stopped
	if stopped {
		close(c.stop)
	} else {
		c.stop = make(chan struct{})
	}
}

// stopChan returns the channel that is closed when the client is stopped by
// Disconnect. A Connect that clears the stop replaces it, so a waiter takes it
// once, when it starts to wait.
func (c *Client) stopChan() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stop
}

// contextUntil returns a context cancelled when done is closed or cancel is
// called, whichever comes first.
func contextUntil(parent context.Context, done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// sleepWhileRunning waits for d, returning false if the client was stopped
// meanwhile so the retry loop can end promptly rather than finishing its delay.
func (c *Client) sleepWhileRunning(d time.Duration) bool {
	stop := c.stopChan()
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-stop:
		return false
	case <-timer.C:
		return !c.isStopped()
	}
}
