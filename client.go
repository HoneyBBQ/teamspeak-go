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
	resolver             AddrResolver
	finalCmdHandler      func(string) error
	crypt                *crypto.Crypt
	attempt              *connectAttempt
	ftTrack              *fileTransferTracker
	logger               *slog.Logger
	handler              *transport.PacketHandler
	cmdTrack             *commandTracker
	throttle             *commandThrottle
	clients              map[uint16]ClientInfo
	finalEvtHandler      func(any)
	addr                 string
	nickname             string
	clientInitOptions    clientInitOptions
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
	if c.status != StatusDisconnected {
		c.mu.Unlock()

		return errAlreadyConnectingOrConnected
	}

	finalAddr := c.resetForConnectLocked()

	c.status = StatusConnecting
	c.mu.Unlock()

	targetAddr, source := c.resolveConnectTarget(finalAddr)
	c.logger.Info("connecting to server", slog.String("address", targetAddr), slog.String("source", source))

	err := c.handler.Connect(targetAddr)
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

	for _, h := range handlers {
		go h(err)
	}
}
