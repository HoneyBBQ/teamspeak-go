package serverquery

import (
	"log/slog"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// Category is a notification category to register with the server, as
// servernotifyregister names it (its `event` parameter).
//
// Experimental: this package may change in a minor release.
type Category string

// The categories both the raw protocol and SSH accept. `bans` is separate:
// TeamSpeak 3 refuses it with error 1539, so registering it fails every
// connect against a TS3 server.
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

// WithEvents registers the notification categories named, and reads the client
// list the events draw their fields from. Without it nothing is registered:
// the client connects and runs commands, and the On… methods for server events
// never fire. The lifecycle events, OnConnected and OnDisconnected, always do.
//
// Name the categories wanted: CategoryServer, CategoryChannel,
// CategoryTextServer, CategoryTextChannel and CategoryTextPrivate are accepted
// by raw TCP and SSH, and `bans` only by TeamSpeak 6, since TeamSpeak 3
// refuses it. Called with none, New returns an error wrapping ErrInvalidConfig.
//
// Over a transport that cannot deliver events — WebQuery — this is a
// configuration that cannot be honoured, and New returns an error wrapping
// ErrInvalidConfig. Leave WithEvents out instead.
//
// Experimental: this package may change in a minor release.
func WithEvents(categories ...Category) Option {
	return optionFunc(func(c *Client) {
		c.eventsRequested = true
		c.categories = append([]Category(nil), categories...)
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

// WithCommandMiddleware wraps every typed command, outermost first. See
// teamspeak.CommandMiddleware for what it sees and what it does not.
//
// Experimental: this package may change in a minor release.
func WithCommandMiddleware(mw ...teamspeak.CommandMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.cmdMiddlewares = append(c.cmdMiddlewares, mw...)
	})
}

// WithLineMiddleware wraps the sending of every command line, outermost first.
// See teamspeak.LineMiddleware for what it sees and what it does not.
//
// A line goes through it inside the serial queue's turn: ServerQuery answers
// one command at a time, so a middleware that waits holds every later command,
// in order. The commands the client sends on its own — login, use, version,
// whoami, servernotifyregister, clientlist, logout — pass it too; the quit of
// Disconnect does not, and cancels the context of a line still waiting in it.
// Without a middleware a line goes out at once: the client does not pace its
// commands, resend a refused one or keep an idle session open.
//
// Experimental: this package may change in a minor release.
func WithLineMiddleware(mw ...teamspeak.LineMiddleware) Option {
	return optionFunc(func(c *Client) {
		c.lineMiddlewares = append(c.lineMiddlewares, mw...)
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
