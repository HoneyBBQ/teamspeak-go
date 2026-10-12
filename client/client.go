package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/discovery"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ErrAlreadyConnected reports a Connect on a client that is already connected
// or connecting.
var ErrAlreadyConnected = errors.New("already connecting or connected")

var (
	errClosedDuringHandshake       = errors.New("connection closed before the TeamSpeak handshake completed")
	errDisconnectedDuringHandshake = fmt.Errorf("%w: Disconnect was called before the handshake completed",
		teamspeak.ErrNotConnected)
)

// reconnectAttemptTimeout bounds each reconnection attempt.
const reconnectAttemptTimeout = 30 * time.Second

// resolveTimeout bounds address resolution, which falls back to the address
// as given rather than failing, so a slow DNS or TSDNS server costs at most
// this much of a Connect.
const resolveTimeout = 10 * time.Second

// disconnectTimeout bounds the goodbye Disconnect sends when its context sets
// no deadline: the server's acknowledgement is a courtesy, and a connection
// that has already died would otherwise hold Disconnect for a full command
// timeout.
const disconnectTimeout = time.Second

// ClientStatus represents the current connection state of the client.
type ClientStatus int

const (
	StatusDisconnected ClientStatus = iota
	StatusConnecting
	StatusConnected
)

// ResolvedAddr is one endpoint a server address resolved to.
type ResolvedAddr struct {
	// Expiry is when the answer stops being valid.
	Expiry time.Time
	// Addr is the endpoint, as host:port.
	Addr string
	// Source names how it was found: SRV, TSDNS, or the address as given.
	Source string
}

// AddrResolver resolves a TeamSpeak server address to host:port endpoints.
// Implementations may replace the default chain (SRV, TSDNS, direct).
type AddrResolver interface {
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

// CommandMiddleware wraps the final command sender; it may alter or drop commands.
type CommandMiddleware func(next func(string) error) func(string) error

// EventMiddleware wraps event dispatch; it may observe or replace notifications.
type EventMiddleware func(next func(any)) func(any)

type clientInitOptions struct {
	serverPassword         string
	defaultChannel         string
	defaultChannelPassword string
}

// Client is the TeamSpeak 3 client.
type Client struct {
	// Commands are the typed commands, running on this client's Send.
	*teamspeak.Commands

	resolver        AddrResolver
	finalCmdHandler func(string) error
	crypt           *crypto.Crypt
	attempt         *connectAttempt
	logger          *slog.Logger
	handler         *transport.PacketHandler
	cmdTrack        *commandTracker
	throttle        *commandThrottle
	clients         map[uint16]teamspeak.ClientInfo
	// evtChain is the event middleware wrapped around dispatchEvent.
	evtChain func(any)
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
	packetConn        net.PacketConn
	clientInitOptions clientInitOptions
	reconnectOptions  ReconnectOptions
	// reconnecting guards against competing retry loops after two failures in
	// quick succession.
	reconnecting bool
	// stopped is set by an explicit Disconnect, which must never be undone by a
	// retry.
	stopped          bool
	cmdMiddlewares   []CommandMiddleware
	eventMiddlewares []EventMiddleware
	events           eventQueue
	onTextMessage    subscribers[TextMessage]
	onClientEnter    subscribers[teamspeak.ClientInfo]
	onClientLeave    subscribers[ClientLeftViewEvent]
	onClientMoved    subscribers[ClientMovedEvent]
	onConnected      subscribers[struct{}]
	onDisconnected   subscribers[error]
	onPoked          subscribers[PokeEvent]
	onKicked         subscribers[KickedEvent]
	onVoiceData      subscribers[VoiceData]
	status           ClientStatus
	mu               sync.Mutex
	clid             uint16
}

// ErrInvalidConfig reports a client New cannot build as configured.
var ErrInvalidConfig = errors.New("invalid client configuration")

// New returns a client that will connect to addr as id, under nickname. It does
// not connect; call Connect.
//
// addr is a host, host:port, or a TeamSpeak nickname resolved through SRV and
// TSDNS records.
func New(id *identity.Identity, addr, nickname string, options ...Option) (*Client, error) {
	if id == nil || id.PrivateKey == nil {
		return nil, fmt.Errorf("%w: no identity", ErrInvalidConfig)
	}
	if addr == "" {
		return nil, fmt.Errorf("%w: no server address", ErrInvalidConfig)
	}

	c := &Client{
		crypt:  crypto.NewCrypt(id),
		status: StatusDisconnected,
		// Silent unless the application asks: a library has no business
		// writing to the application's default logger.
		logger:   slog.New(slog.DiscardHandler),
		addr:     addr,
		nickname: nickname,
		clients:  make(map[uint16]teamspeak.ClientInfo),
		throttle: newCommandThrottle(),
		cmdTrack: newCommandTracker(),
		attempt:  newConnectAttempt(),
	}

	c.Commands = teamspeak.NewCommands(c)

	for _, opt := range options {
		opt.apply(c)
	}

	c.handler = c.newHandler()
	if c.resolver == nil {
		c.resolver = defaultResolver{resolver: discovery.NewResolver(c.logger)}
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
// a real socket. pc must deliver whole datagrams, one per Read.
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
		c.reconnectOptions = options.withDefaults()
	})
}

// WithResolver replaces the address resolver Connect uses.
func WithResolver(r AddrResolver) Option {
	return optionFunc(func(c *Client) {
		c.resolver = r
	})
}

// WithCommandMiddleware wraps every outgoing command, outermost first.
func WithCommandMiddleware(mw ...CommandMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.cmdMiddlewares = append(c.cmdMiddlewares, mw...)
	})
}

// WithEventMiddleware wraps every event before it reaches the handlers.
func WithEventMiddleware(mw ...EventMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.eventMiddlewares = append(c.eventMiddlewares, mw...)
	})
}

// WithServerPassword sets the server password sent when connecting.
func WithServerPassword(password string) Option {
	return optionFunc(func(c *Client) {
		c.clientInitOptions.serverPassword = password
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
		c.clientInitOptions.defaultChannelPassword = password
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
func (c *Client) Connect(ctx context.Context) error {
	attempt, err := c.start(ctx)
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
		c.failConnection(ctx.Err())
		<-attempt.done

		return attempt.err
	}
}

// Disconnect leaves the server and closes the connection.
//
// It says goodbye first, waiting for the server's acknowledgement until ctx is
// done, or for a second when ctx sets no deadline. The connection is closed
// either way. A Connect still waiting for its handshake returns
// teamspeak.ErrNotConnected, and so do the commands still waiting for an
// answer. Disconnect on a client that is not connected does nothing.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	// Recorded before anything else: a dropped socket during the goodbye below
	// must not be mistaken for an outage worth retrying.
	c.stopped = true
	oldStatus := c.status
	if oldStatus == StatusDisconnected {
		c.mu.Unlock()

		return nil
	}
	c.status = StatusDisconnected
	c.attempt.finish(errDisconnectedDuringHandshake)
	handler := c.handler
	c.mu.Unlock()

	c.logger.InfoContext(ctx, "disconnecting from server")

	if oldStatus == StatusConnected {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, disconnectTimeout)
			defer cancel()
		}
		_, _ = c.execWithResponse(ctx, "clientdisconnect reasonmsg=Shutdown")
	}

	err := handler.Close()
	c.cmdTrack.reset(teamspeak.ErrNotConnected)
	// Announced here; handleConnectionClosed stays quiet once the status is
	// already Disconnected, so the handlers hear about it once.
	emit(c, &c.onDisconnected, nil)

	return err
}

// start resets the session and begins the handshake, returning the attempt
// that the handshake will resolve.
func (c *Client) start(ctx context.Context) (*connectAttempt, error) {
	c.mu.Lock()
	c.stopped = false
	if c.status != StatusDisconnected {
		c.mu.Unlock()

		return nil, ErrAlreadyConnected
	}

	// The handler resetForConnectLocked wires up reconnects on its own context:
	// a reconnection outlives the Connect that started the session.
	finalAddr := c.resetForConnectLocked() //nolint:contextcheck // see above
	attempt := c.attempt

	c.status = StatusConnecting
	handler := c.handler
	packetConn := c.packetConn
	c.mu.Unlock()

	targetAddr, source := c.resolveConnectTarget(ctx, finalAddr)
	c.logger.InfoContext(ctx, "connecting to server", slog.String("address", targetAddr), slog.String("source", source))

	var err error
	if packetConn != nil {
		// The adapter needs the peer address to send to; resolve it the same way
		// the dialling path would, without opening a socket.
		var remote *net.UDPAddr
		remote, err = net.ResolveUDPAddr("udp", targetAddr)
		if err == nil {
			err = handler.Start(transport.NewPacketConnAdapter(packetConn, remote))
		}
	} else {
		err = handler.Connect(targetAddr)
	}
	if err != nil {
		// Without this the client stays in StatusConnecting and every later
		// Connect fails with ErrAlreadyConnected.
		c.failConnection(err)

		return nil, err
	}

	return attempt, nil
}

func (c *Client) resetForConnectLocked() string {
	if c.handler != nil {
		_ = c.handler.Close()
	}
	id := c.crypt.Identity
	c.crypt = crypto.NewCrypt(id)
	c.handler = c.newHandler()
	// Keep an attempt nobody has resolved yet: something may already be
	// waiting on it, and must be released by this connection's handshake.
	if c.attempt.finished() {
		c.attempt = newConnectAttempt()
	}
	c.cmdTrack.reset(teamspeak.ErrNotConnected)
	c.clients = make(map[uint16]teamspeak.ClientInfo)
	c.clid = 0
	// Reset to the TS3 default; initserver sets it from the server's version.
	c.uidAlgorithm = identity.UIDSHA1

	c.capabilities = unknownServerCapabilities()

	// Fallback used only if resolution fails. A colon check would misread any
	// IPv6 literal as already carrying a port.
	host, port := discovery.SplitHostPortOrDefault(c.addr, "9987")

	return net.JoinHostPort(host, port)
}

func (c *Client) resolveConnectTarget(ctx context.Context, fallbackAddr string) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	resolved, err := c.resolver.Resolve(ctx, c.addr)
	if err != nil || len(resolved) == 0 {
		// An empty answer used to index resolved[0] and panic.
		c.logger.WarnContext(ctx, "address resolution failed, falling back to direct", slog.Any("error", err))

		return fallbackAddr, "Fallback"
	}

	return resolved[0].Addr, resolved[0].Source
}

// newHandler creates a packet handler wired to this client. Its OnClosed is
// bound to the handler instance, so a close reported late by a handler that a
// later Connect already replaced cannot tear down the new connection.
func (c *Client) newHandler() *transport.PacketHandler {
	h := transport.NewPacketHandler(c.crypt, c.logger)
	h.OnPacket = c.handlePacket
	h.OnClosed = func(err error) {
		c.mu.Lock()
		current := c.handler == h
		c.mu.Unlock()
		if current {
			c.handleConnectionClosed(err)
		}
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
func (c *Client) failConnection(err error) {
	c.mu.Lock()
	if c.status == StatusConnected {
		c.mu.Unlock()

		return
	}
	c.attempt.finish(err)
	if c.status == StatusDisconnected {
		c.mu.Unlock()

		return
	}
	c.status = StatusDisconnected
	handler := c.handler
	c.mu.Unlock()

	_ = handler.Close()
	emit(c, &c.onDisconnected, err)
}

func (c *Client) handleConnectionClosed(err error) {
	// Nothing in flight can be answered any more; failing it now, with the
	// reason, beats every caller timing out one by one. Harmless after a
	// deliberate Disconnect, which has already done it.
	cause := teamspeak.ErrNotConnected
	if err != nil {
		cause = fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, err)
	}
	c.cmdTrack.reset(cause)

	c.mu.Lock()
	if c.status == StatusDisconnected {
		c.mu.Unlock()

		return
	}
	if c.status == StatusConnecting {
		// The socket closed before the handshake finished: a failed attempt,
		// not the end of a live session.
		c.mu.Unlock()
		if err == nil {
			err = errClosedDuringHandshake
		}
		c.failConnection(err)

		return
	}
	c.status = StatusDisconnected
	c.mu.Unlock()

	if err == nil {
		err = errConnectionClosed
	}
	// Announced first, then retried: a caller watching OnDisconnected should
	// hear about the drop even when a reconnect is already on its way, because
	// a silent recovery hides an outage.
	emit(c, &c.onDisconnected, err)

	go c.scheduleReconnect(err)
}

// scheduleReconnect retries a dropped connection according to the policy.
//
// Never runs after an explicit Disconnect, and never more than one at a time:
// two failures in quick succession would otherwise start competing loops, and a
// loop shorter than the server's antiflood window bans the IP rather than
// reconnecting it.
func (c *Client) scheduleReconnect(connErr error) {
	options, ok := c.beginReconnect()
	if !ok {
		return
	}

	defer c.endReconnect()

	shouldRetry := options.ShouldRetry
	if shouldRetry == nil {
		shouldRetry = DefaultShouldRetry
	}

	for attempt := 1; options.Backoff.MaxAttempts == 0 || attempt <= options.Backoff.MaxAttempts; attempt++ {
		if c.isStopped() {
			return
		}
		if !shouldRetry(connErr, attempt) {
			c.logger.Info("not retrying", slog.Int("attempt", attempt), slog.Any("error", connErr))

			return
		}

		delay := BackoffDelay(options.Backoff, attempt, nil)
		c.logger.Info("reconnecting", slog.Int("attempt", attempt), slog.Duration("delay", delay))

		if !c.sleepWhileRunning(delay) {
			return
		}

		retryErr := c.runConnect()
		if retryErr == nil {
			c.logger.Info("reconnected", slog.Int("attempt", attempt))

			return
		}

		connErr = retryErr
		if options.ShouldRetry == nil && !DefaultShouldRetry(retryErr, attempt) {
			c.logger.Info("reconnect refused", slog.Int("attempt", attempt), slog.Any("error", retryErr))

			return
		}
	}

	c.logger.Warn("reconnect attempts exhausted", slog.Int("attempts", options.Backoff.MaxAttempts))
}

// runConnect makes one reconnection attempt.
func (c *Client) runConnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), reconnectAttemptTimeout)
	defer cancel()

	return c.Connect(ctx)
}

// beginReconnect claims the reconnect slot, reporting false when reconnection
// is off, already running, or the client has been stopped deliberately.
func (c *Client) beginReconnect() (ReconnectOptions, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.reconnectOptions.Enabled || c.reconnecting || c.stopped {
		return ReconnectOptions{}, false
	}
	c.reconnecting = true

	return c.reconnectOptions, true
}

// endReconnect releases the slot so a later drop can be retried.
func (c *Client) endReconnect() {
	c.mu.Lock()
	c.reconnecting = false
	c.mu.Unlock()
}

// isStopped reports whether an explicit Disconnect has happened.
func (c *Client) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stopped
}

// sleepWhileRunning waits for d, returning false if the client was stopped
// meanwhile so the retry loop can end promptly rather than finishing its delay.
func (c *Client) sleepWhileRunning(d time.Duration) bool {
	const step = 50 * time.Millisecond

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.isStopped() {
			return false
		}

		time.Sleep(min(time.Until(deadline), step))
	}

	return !c.isStopped()
}
