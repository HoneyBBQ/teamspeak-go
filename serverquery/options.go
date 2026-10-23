package serverquery

import (
	"log/slog"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// Category is a notification category to register with the server, as
// servernotifyregister names it (its `event` parameter).
//
// Experimental: this package may change in a minor release.
type Category string

// The categories both the raw protocol and SSH accept. `bans` is deliberately
// not among the defaults: TeamSpeak 3 refuses it with error 1539, so
// registering it unconditionally would fail every connect against a TS3
// server.
const (
	// CategoryServer is "server": virtual server events.
	CategoryServer Category = "server"
	// CategoryChannel is "channel": channel events, for one channel or, with
	// id 0, all of them. Registering it takes no channel here.
	CategoryChannel Category = "channel"
	// CategoryTextServer is "textserver": text messages to the server.
	CategoryTextServer Category = "textserver"
	// CategoryTextChannel is "textchannel": text messages to a channel.
	CategoryTextChannel Category = "textchannel"
	// CategoryTextPrivate is "textprivate": text messages to this client.
	CategoryTextPrivate Category = "textprivate"
	// CategoryBans is "bans": ban events. Accepted on TeamSpeak 6 and refused
	// on TeamSpeak 3, so it is opt-in.
	CategoryBans Category = "bans"
	// CategoryTokenUsed is "tokenused": a client redeemed a privilege key. Both
	// TeamSpeak 3.13.8 and 6.0.0-beta13.1 accept it and then send
	// notifytokenused with the client, the key and its two ids. The key is a
	// credential, so the notification stays a NotificationEvent and the category
	// is never registered by default: name it in WithEvents to receive it.
	CategoryTokenUsed Category = "tokenused"
)

// WithServer selects the virtual server to address by id, as `use sid=N` does.
// Without it the client selects no server: over TCP and SSH that addresses the
// instance, which is enough for the instance-wide commands and not for the
// rest; the events are registered by the first Use. TeamSpeak 3's WebQuery runs every command on a virtual server even
// with none in the path, so an instance command such as queryloginadd answers
// 1539 there; TeamSpeak 6's WebQuery reads it as the instance.
//
// It is mutually exclusive with WithServerPort; New returns ErrInvalidConfig
// if both are set.
//
// Experimental: this package may change in a minor release.
func WithServer(id teamspeak.ServerID) Option {
	return optionFunc(func(c *Client) {
		c.server = &serverTarget{id: id}
		c.namedID = true
	})
}

// WithServerPort selects the virtual server to address by its voice port, as
// `use port=N` does. Over WebQuery it addresses the server as /byport/N.
//
// It is mutually exclusive with WithServer; New returns ErrInvalidConfig if
// both are set.
//
// Experimental: this package may change in a minor release.
func WithServerPort(port uint16) Option {
	return optionFunc(func(c *Client) {
		c.server = &serverTarget{port: port}
		c.namedPort = true
	})
}

// WithNickname sets the nickname the query connection takes, as clientupdate
// does once a server is selected. Without it the server's default for the
// account is kept, and with no WithServer or WithServerPort it is not used.
//
// Experimental: this package may change in a minor release.
func WithNickname(nickname string) Option {
	return optionFunc(func(c *Client) {
		c.nickname = nickname
	})
}

// WithEvents registers exactly the notification categories named, in place of
// the default five. Called with none, it registers the default five.
//
// `bans` is not among the defaults because TeamSpeak 3 refuses it; name it
// explicitly to register it on a TeamSpeak 6 server.
//
// Over a transport that cannot deliver events — WebQuery — this is a
// configuration that cannot be honoured, and New returns an error wrapping
// ErrInvalidConfig. Ask for no events, or use WithoutEvents, instead.
//
// Experimental: this package may change in a minor release.
func WithEvents(categories ...Category) Option {
	return optionFunc(func(c *Client) {
		c.eventsRequested = true
		if len(categories) == 0 {
			c.categories = defaultCategories()

			return
		}
		c.categories = append([]Category(nil), categories...)
	})
}

// WithoutEvents registers no notification category: the client connects and
// runs commands, and the On… methods for server events never fire. The
// lifecycle events, OnConnected and OnDisconnected, still do.
//
// Experimental: this package may change in a minor release.
func WithoutEvents() Option {
	return optionFunc(func(c *Client) {
		c.registerEvents = false
		c.categories = nil
	})
}

// WithReconnect reconnects after a dropped connection.
//
// Off unless this is set. A deliberate Disconnect never reconnects, whatever
// the policy says: retrying would keep a process alive that asked to stop.
//
// Reconnection never retries a refused login or a refused `use`: those are the
// server saying the credentials or the server id are wrong, and repeating them
// only risks the flood ban that TeamSpeak applies to an IP that connects too
// often. That is the default ShouldRetry; supplying another replaces it
// entirely. New returns ErrInvalidConfig for a backoff that cannot work, see
// teamspeak.BackoffPolicy.Validate.
//
// Experimental: this package may change in a minor release.
func WithReconnect(options teamspeak.ReconnectOptions) Option {
	return optionFunc(func(c *Client) {
		c.reconnectOptions = &options
	})
}

// WithKeepAlive sets how long a raw TCP or SSH session may sit idle before the
// client sends `version` to keep it open. The default is two minutes; zero
// turns it off, and a negative interval is refused by [New] with
// [ErrInvalidConfig].
//
// Measured on TeamSpeak 3 3.13.8 (raw TCP and SSH) and TeamSpeak 6
// 6.0.0-beta13.1 (SSH): the server closes a query session that has sent no
// command for 300 seconds, and a session that sends one every 200 seconds stays
// open. Notifications arriving do not count: a raw TCP session on TeamSpeak 3
// that received nine and sent nothing was closed at 300 seconds all the same.
// The command is sent only when none has been for this long, so a busy client
// sends nothing extra. WebQuery has no session to keep, and a [Custom]
// transport is left to its own owner.
//
// Experimental: this package may change in a minor release.
func WithKeepAlive(idle time.Duration) Option {
	return optionFunc(func(c *Client) {
		c.keepAlive = idle
	})
}

// WithCommandMiddleware wraps every typed command, outermost first. See
// teamspeak.CommandMiddleware for what it sees and what it does not.
//
// Experimental: this package may change in a minor release.
func WithCommandMiddleware(mw ...teamspeak.CommandMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.cmdMiddlewares = append(c.cmdMiddlewares, mw...)
	})
}

// WithLogger sends the client's logs to logger. Without it the client is
// silent.
//
// Experimental: this package may change in a minor release.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	})
}
