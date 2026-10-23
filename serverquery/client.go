package serverquery

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/eventbus"
	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// typedCommands names teamspeak.Commands under an unexported name, so the
// embedded field promotes the typed commands as the client's methods but
// cannot be replaced from outside.
type typedCommands = teamspeak.Commands

// Client is a TeamSpeak ServerQuery client: the typed commands over one of the
// three query transports, with the server's notifications delivered as events.
//
// The typed commands of teamspeak.Commands — ListChannels, MoveClient and the
// rest — are its methods, running on Send.
//
// Experimental: this package may change in a minor release.
type Client struct {
	*typedCommands

	executor         teamspeak.Executor
	dialer           Dialer
	transport        engine.Transport
	logger           *slog.Logger
	server           *serverTarget
	stop             chan struct{}
	warned           map[string]bool
	clients          map[teamspeak.ClientID]teamspeak.ClientEntry
	engine           *engine.Client
	reconnectOptions *teamspeak.ReconnectOptions
	// keepAlive is how long a TCP or SSH session may idle before a command is
	// sent to keep it open; zero is off.
	keepAlive time.Duration
	// verdict and loopAttempt belong to the reconnect loop: the policy's answer
	// for the failure just announced, and the attempt the loop is on.
	verdict        *retryVerdict
	loopAttempt    int
	nickname       string
	selfNickname   string
	family         teamspeak.ServerFamily
	version        string
	categories     []Category
	cmdMiddlewares []teamspeak.CommandMiddleware
	subs           subscribers
	onKicked       eventbus.Subscribers[teamspeak.KickedEvent]
	onDisconnected eventbus.Subscribers[teamspeak.DisconnectedEvent]
	onConnected    eventbus.Subscribers[teamspeak.ConnectedEvent]
	events         eventbus.Queue
	status         teamspeak.Status
	mu             sync.Mutex
	selfID         teamspeak.ClientID
	namedID        bool
	namedPort      bool
	stopped        bool
	reconnecting   bool
	registerEvents bool
	// eventsPending is set while the session has no server: the events are
	// registered by the first Use.
	eventsPending   bool
	eventsRequested bool
}

// subscribers holds the handlers for each server event.
type subscribers struct {
	textMessage eventbus.Subscribers[teamspeak.TextMessageEvent]
	clientEnter eventbus.Subscribers[teamspeak.ClientEnterEvent]
	clientLeave eventbus.Subscribers[teamspeak.ClientLeaveEvent]
	clientMoved eventbus.Subscribers[teamspeak.ClientMovedEvent]

	channelCreated  eventbus.Subscribers[teamspeak.ChannelCreatedEvent]
	channelEdited   eventbus.Subscribers[teamspeak.ChannelEditedEvent]
	channelMoved    eventbus.Subscribers[teamspeak.ChannelMovedEvent]
	channelDeleted  eventbus.Subscribers[teamspeak.ChannelDeletedEvent]
	channelDesc     eventbus.Subscribers[teamspeak.ChannelDescriptionChangedEvent]
	channelPassword eventbus.Subscribers[teamspeak.ChannelPasswordChangedEvent]
	serverEdited    eventbus.Subscribers[teamspeak.ServerEditedEvent]

	notification eventbus.Subscribers[teamspeak.NotificationEvent]
}

// login is a query account to log in with, carried by the dialer that sends
// it as a command.
type login struct {
	name     string
	password string
}

// serverTarget is the server `use` selects.
type serverTarget struct {
	id   teamspeak.ServerID
	port uint16
}

// New returns a query client that will connect through d, configured by opts.
// It does not connect; call Connect.
//
// It returns an error wrapping ErrInvalidConfig for a configuration it cannot
// honour: no dialer, a login or a server over a transport that has neither, or
// events asked for over a transport that cannot deliver them, or a reconnect
// backoff that cannot work.
//
// Experimental: this package may change in a minor release.
func New(d Dialer, opts ...Option) (*Client, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: no dialer", ErrInvalidConfig)
	}

	c := &Client{
		dialer: d,
		// Silent unless the application asks: a library has no business
		// writing to the application's default logger.
		logger:         slog.New(slog.DiscardHandler),
		categories:     defaultCategories(),
		registerEvents: true,
		keepAlive:      defaultKeepAlive,
		status:         teamspeak.StatusDisconnected,
		clients:        make(map[teamspeak.ClientID]teamspeak.ClientEntry),
		warned:         make(map[string]bool),
		stop:           make(chan struct{}),
	}

	for _, opt := range opts {
		opt.apply(c)
	}

	err := validateConfig(c)
	if err != nil {
		return nil, err
	}

	c.buildMiddlewareChains()
	c.typedCommands = teamspeak.NewCommands(c)

	return c, nil
}

// validateConfig checks the assembled configuration, returning an error
// wrapping ErrInvalidConfig for a combination the transport cannot serve.
func validateConfig(c *Client) error {
	if c.reconnectOptions != nil {
		err := c.reconnectOptions.Backoff.Validate()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	err := c.dialer.validate()
	if err != nil {
		return err
	}

	if c.namedID && c.namedPort {
		return fmt.Errorf("%w: WithServer and WithServerPort name one server two ways", ErrInvalidConfig)
	}
	if c.server != nil && c.server.id == 0 && c.server.port == 0 {
		return fmt.Errorf("%w: a server is named by a non-zero id or a non-zero port",
			ErrInvalidConfig)
	}
	if c.keepAlive < 0 {
		return fmt.Errorf("%w: WithKeepAlive takes an interval of zero or more", ErrInvalidConfig)
	}
	if c.eventsRequested && !c.dialer.SupportsNotifications() {
		return fmt.Errorf("%w: %s cannot deliver events, so WithEvents cannot be honoured",
			ErrInvalidConfig, c.dialer)
	}

	return nil
}

// defaultKeepAlive is how long a session may sit idle before the client sends
// a command to keep it open: well inside the 300 seconds after which the
// server closes an idle one, see [WithKeepAlive].
const defaultKeepAlive = 2 * time.Minute

// defaultCategories are the notification categories registered without
// WithEvents: the five both the raw protocol and SSH accept.
func defaultCategories() []Category {
	return []Category{
		CategoryServer,
		CategoryChannel,
		CategoryTextServer,
		CategoryTextChannel,
		CategoryTextPrivate,
	}
}
