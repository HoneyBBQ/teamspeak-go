package teamspeak

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/honeybbq/teamspeak-go/crypto"
	"github.com/honeybbq/teamspeak-go/discovery"
	"github.com/honeybbq/teamspeak-go/transport"
)

var (
	errAlreadyConnectingOrConnected = errors.New("already connecting or connected")
	errClosedDuringHandshake        = errors.New("connection closed before the TeamSpeak handshake completed")
)

// ClientStatus represents the current connection state of the client.
type ClientStatus int

const (
	StatusDisconnected ClientStatus = iota
	StatusConnecting
	StatusConnected
)

// AddrResolver resolves a TeamSpeak server address to host:port endpoints.
// Implementations may replace the default chain (SRV, TSDNS, direct).
type AddrResolver interface {
	Resolve(ctx context.Context, addr string) ([]discovery.ResolvedAddr, error)
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
	resolver        AddrResolver
	finalCmdHandler func(string) error
	crypt           *crypto.Crypt
	attempt         *connectAttempt
	ftTrack         *fileTransferTracker
	logger          *slog.Logger
	handler         *transport.PacketHandler
	cmdTrack        *commandTracker
	throttle        *commandThrottle
	clients         map[uint16]ClientInfo
	finalEvtHandler func(any)
	addr            string
	nickname        string
	// uidAlgorithm is the hash the connected server uses for
	// client_unique_identifier, learned from virtualserver_version during
	// initserver: SHA-1 on TS3, SHA-256 on TS6.
	uidAlgorithm crypto.UidAlgorithm
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
	stopped              bool
	textMsgHandlers      []func(TextMessage)
	cmdMiddlewares       []CommandMiddleware
	eventMiddlewares     []EventMiddleware
	clientEnterHandlers  []func(ClientInfo)
	clientLeaveHandlers  []func(ClientLeftViewEvent)
	clientMoveHandlers   []func(ClientMovedEvent)
	connectedHandlers    []func()
	disconnectedHandlers []func(error)
	pokedHandlers        []func(PokeEvent)
	kickedHandlers       []func(string)
	voiceDataHandlers    []func(VoiceData)
	status               ClientStatus
	mu                   sync.Mutex
	clid                 uint16
}

// NewClient creates a new TeamSpeak 3 client.
func NewClient(identity *crypto.Identity, addr string, nickname string, options ...ClientOption) *Client {
	crypt := crypto.NewCrypt(identity)

	c := &Client{
		crypt:    crypt,
		status:   StatusDisconnected,
		logger:   slog.Default(),
		addr:     addr,
		nickname: nickname,
		clients:  make(map[uint16]ClientInfo),
		throttle: newCommandThrottle(),
		cmdTrack: newCommandTracker(),
		ftTrack:  newFileTransferTracker(),
		attempt:  newConnectAttempt(),
	}

	for _, opt := range options {
		opt(c)
	}

	c.handler = c.newHandler()
	if c.resolver == nil {
		c.resolver = discovery.NewResolver(c.logger)
	}

	c.rebuildMiddlewareChains()

	return c
}

type ClientOption func(*Client)

func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithPacketConn dials no socket and instead runs the session over pc.
//
// The transport is otherwise closed: this is the only way to route traffic
// through a proxy or tunnel, or to drive the client from something that is not
// a real socket. pc must deliver whole datagrams, one per Read.
func WithPacketConn(pc net.PacketConn) ClientOption {
	return func(c *Client) {
		c.packetConn = pc
	}
}

// WithReconnect reconnects after a dropped connection.
//
// Off unless this is set. A deliberate Disconnect never reconnects, whatever
// the policy says: retrying would keep a process alive that asked to stop.
func WithReconnect(options ReconnectOptions) ClientOption {
	return func(c *Client) {
		c.reconnectOptions = options.withDefaults()
	}
}

// WithResolver sets a custom address resolver used by Connect.
func WithResolver(r AddrResolver) ClientOption {
	return func(c *Client) {
		c.resolver = r
	}
}

func WithCommandMiddleware(mw ...CommandMiddleware) ClientOption {
	return func(c *Client) {
		c.cmdMiddlewares = append(c.cmdMiddlewares, mw...)
	}
}

func WithEventMiddleware(mw ...EventMiddleware) ClientOption {
	return func(c *Client) {
		c.eventMiddlewares = append(c.eventMiddlewares, mw...)
	}
}

// WithServerPassword configures the server password sent during clientinit.
func WithServerPassword(password string) ClientOption {
	return func(c *Client) {
		c.clientInitOptions.serverPassword = password
	}
}

// WithDefaultChannel configures the default channel requested during clientinit.
func WithDefaultChannel(channel string) ClientOption {
	return func(c *Client) {
		c.clientInitOptions.defaultChannel = channel
	}
}

// WithDefaultChannelPassword configures the password for the default channel.
func WithDefaultChannelPassword(password string) ClientOption {
	return func(c *Client) {
		c.clientInitOptions.defaultChannelPassword = password
	}
}

// Connect starts the UDP session and handshake to the server.
func (c *Client) Connect() error {
	c.mu.Lock()
	c.stopped = false
	if c.status != StatusDisconnected {
		c.mu.Unlock()

		return errAlreadyConnectingOrConnected
	}

	finalAddr := c.resetForConnectLocked()

	c.status = StatusConnecting
	c.mu.Unlock()

	targetAddr, source := c.resolveConnectTarget(finalAddr)
	c.logger.Info("connecting to server", slog.String("address", targetAddr), slog.String("source", source))

	c.mu.Lock()
	packetConn := c.packetConn
	c.mu.Unlock()

	var err error
	if packetConn != nil {
		// The adapter needs the peer address to send to; resolve it the same way
		// the dialling path would, without opening a socket.
		remote, resolveErr := net.ResolveUDPAddr("udp", targetAddr)
		if resolveErr != nil {
			c.failConnection(resolveErr)

			return resolveErr
		}
		err = c.handler.Start(transport.NewPacketConnAdapter(packetConn, remote))
	} else {
		err = c.handler.Connect(targetAddr)
	}
	if err != nil {
		// Without this the client stays in StatusConnecting and every later
		// Connect fails with errAlreadyConnectingOrConnected.
		c.failConnection(err)
	}

	return err
}

// Disconnect gracefully closes the connection.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	// Recorded before anything else: a dropped socket during the shutdown
	// command below must not be mistaken for an outage worth retrying.
	c.stopped = true
	oldStatus := c.status
	if oldStatus == StatusDisconnected {
		c.mu.Unlock()

		return nil
	}
	c.status = StatusDisconnected
	handlers := c.disconnectedHandlers
	c.mu.Unlock()

	c.logger.Info("disconnecting from server")

	if oldStatus == StatusConnected {
		_ = c.ExecCommand("clientdisconnect reasonmsg=Shutdown", 1*time.Second)
	}

	err := c.handler.Close()
	// Invoke disconnected handlers here; handleConnectionClosed skips them once
	// status is already Disconnected to avoid duplicate callbacks.
	for _, h := range handlers {
		go h(nil)
	}

	return err
}

func (c *Client) resetForConnectLocked() string {
	if c.handler != nil {
		_ = c.handler.Close()
	}
	identity := c.crypt.Identity
	c.crypt = crypto.NewCrypt(identity)
	c.handler = c.newHandler()
	// Keep an attempt nobody has resolved yet: a caller that started
	// WaitConnected before calling Connect is waiting on it, and must be
	// released by this connection's handshake.
	if c.attempt.finished() {
		c.attempt = newConnectAttempt()
	}
	c.cmdTrack.reset()
	c.ftTrack.reset()
	c.clients = make(map[uint16]ClientInfo)
	c.clid = 0
	// Reset to the TS3 default; initserver sets it from the server's version.
	c.uidAlgorithm = crypto.UidSha1

	c.capabilities = unknownServerCapabilities()

	// Fallback used only if resolution fails. A colon check would misread any
	// IPv6 literal as already carrying a port.
	host, port := discovery.SplitHostPortOrDefault(c.addr, "9987")

	return net.JoinHostPort(host, port)
}

func (c *Client) resolveConnectTarget(fallbackAddr string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolved, err := c.resolver.Resolve(ctx, c.addr)
	if err != nil {
		c.logger.Warn("address resolution failed, falling back to direct", slog.Any("error", err))

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
// records the cause for WaitConnected, closes the transport, and reports the
// cause to disconnected handlers. It does nothing once the handshake has
// completed, so it cannot tear down a live session.
//
// Without it, a handshake the server rejects (a wrong password, say, which the
// server answers with an error instead of closing the socket) surfaced only as
// the caller's own WaitConnected timeout, and the client stayed in
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
	handlers := c.disconnectedHandlers
	c.mu.Unlock()

	_ = handler.Close()
	for _, h := range handlers {
		go h(err)
	}
}

func (c *Client) handleConnectionClosed(err error) {
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
	handlers := c.disconnectedHandlers
	c.mu.Unlock()

	// Announced first, then retried: a caller watching OnDisconnected should
	// hear about the drop even when a reconnect is already on its way, because
	// a silent recovery hides an outage.
	for _, h := range handlers {
		go h(err)
	}

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

// runConnect connects and waits for the handshake, returning the failure of
// whichever step did not complete.
func (c *Client) runConnect() error {
	connectErr := c.Connect()
	if connectErr != nil {
		return connectErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return c.WaitConnected(ctx)
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
