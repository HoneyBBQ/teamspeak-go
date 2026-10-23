package serverquery

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"
	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// The session commands: the ones that change who the connection is, which
// server it is on and what it is told about. Connect runs them from the
// options given to New, and a caller driving the session by hand runs them
// here, mid-session.
//
// They act on the connection that is open and nothing else. The options a
// reconnect starts from — the login of [TCPLogin], WithServer, WithEvents — are not changed
// by them, so a reconnect does not repeat a Login, a Use or a
// RegisterNotifications made by hand: it starts over from the options. A
// caller that wants the new state to survive a drop sets it as the options.

// ServerSelector names the virtual server Use selects: by id, as `use sid=N`
// does, or by voice port, as `use port=N` does. Build one with [ByID] or
// [ByPort]; the zero value names nothing, and Use refuses it.
//
// Experimental: this package may change in a minor release.
type ServerSelector struct {
	target serverTarget
}

// ByID selects the virtual server with the given id.
//
// Experimental: this package may change in a minor release.
func ByID(id teamspeak.ServerID) ServerSelector {
	return ServerSelector{target: serverTarget{id: id}}
}

// ByPort selects the virtual server listening on the given voice port. Over
// WebQuery it addresses the server as /byport/N.
//
// Experimental: this package may change in a minor release.
func ByPort(port uint16) ServerSelector {
	return ServerSelector{target: serverTarget{port: port}}
}

// UseOptions are Use's optional parameters.
//
// Experimental: this package may change in a minor release.
type UseOptions struct {
	// Nickname is the nickname the query client takes on the server
	// (client_nickname); "" keeps the server's default. Over WebQuery, which
	// has no client on the server, it is ignored.
	Nickname string
}

// Login logs the connection in as a query account, with the raw protocol's
// `login`. Connect runs the same command for a [TCPLogin] dialer.
//
// The server answers a wrong name or password with 520, and an account that may
// not log in with 2568. Over SSH the session is logged in already, and over
// WebQuery the api key is the login: WebQuery refuses the command with 5120.
//
// It does not select a server: Use does. A Login after Logout starts a new
// session, on no server.
//
// Experimental: this package may change in a minor release.
func (c *Client) Login(ctx context.Context, name, password string) error {
	eng := c.currentEngine()
	if eng == nil {
		return teamspeak.ErrNotConnected
	}

	_, err := eng.Exec(ctx, wire.BuildCommandOrdered("login", [][2]string{
		{"client_login_name", name},
		{"client_login_password", password},
	}))

	return err
}

// Logout ends the query login and deselects the virtual server, with the raw
// protocol's `logout`. The connection stays open, with no account and on no
// server. Use still selects a server then, as a client with no rights: a
// command that needs one is refused with 2568 until Login. Over SSH, where the
// login is the session's own, the server accepts Logout all the same and the
// session carries on as an account without rights; WebQuery refuses it with
// 5120.
//
// The client's own id and its knowledge of the other clients are cleared, as
// they belong to the server that was left. Needs b_serverquery_login.
//
// To end the connection, use Disconnect.
//
// Experimental: this package may change in a minor release.
func (c *Client) Logout(ctx context.Context) error {
	eng := c.currentEngine()
	if eng == nil {
		return teamspeak.ErrNotConnected
	}

	_, err := eng.Exec(ctx, "logout")
	if err != nil {
		return err
	}
	c.forgetServer()

	return nil
}

// Use selects the virtual server the following commands address, with the raw
// protocol's `use`. Connect runs the same command from WithServer and
// WithServerPort. Over WebQuery, which has no session, the transport answers
// it by addressing that server from then on.
//
// The connection becomes a client of the new server, with an id of its own, so
// the client reads its id again and drops what it knew of the clients of the
// server it was on: its own kick and move are recognised by that id. If the
// client was configured with events, it reads the new server's client list as
// Connect does.
//
// A client connected with no server has registered no events yet, as the
// server refuses that with none selected: the first successful Use registers
// them, and then reads the client list.
//
// Selecting the server the connection is already on changes nothing, a new
// nickname included. A server that is not there, or not running, is refused
// with 1033, and a
// connection with no rights to select a server with 2568. A server's refusal
// leaves the connection on no server, not on the one it was on: the server
// drops the earlier selection, measured on TeamSpeak 3 and 6, and the client
// forgets its id with it. The notifications registered for that selection go
// too, so after a refused Use, Use again and RegisterNotifications again. A
// selector that names nothing is refused with teamspeak.ErrInvalidCommand
// before anything is sent.
//
// Experimental: this package may change in a minor release.
func (c *Client) Use(ctx context.Context, server ServerSelector, opts UseOptions) error {
	eng := c.currentEngine()
	if eng == nil {
		return teamspeak.ErrNotConnected
	}

	params, err := useParams(server)
	if err != nil {
		return err
	}
	if opts.Nickname != "" {
		params = append(params, [2]string{"client_nickname", opts.Nickname})
	}

	_, err = eng.Exec(ctx, wire.BuildCommandOrdered("use", params))
	if err != nil {
		if _, refused := errors.AsType[*teamspeak.ServerError](err); refused {
			c.forgetServer()
		}

		return err
	}

	c.forgetServer()
	err = c.readSelf(ctx, eng)
	if err != nil {
		return fmt.Errorf("whoami after use: %w", err)
	}

	return c.learnServer(ctx, eng)
}

// learnServer does for the server just selected what Connect does for the one
// it selects: register the events a client with no server could not yet, or
// read the client list again.
func (c *Client) learnServer(ctx context.Context, eng *engine.Client) error {
	c.mu.Lock()
	events := c.registerEvents && c.dialer.SupportsNotifications()
	categories, pending := c.categories, c.eventsPending && events
	listClients := events && len(categories) > 0
	c.mu.Unlock()
	if pending {
		err := c.registerCategories(ctx, eng, categories)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.eventsPending = false
		c.mu.Unlock()

		return nil
	}
	if listClients {
		c.readClientList(ctx, eng)
	}

	return nil
}

// useParams encodes a selector as `use`'s parameters.
func useParams(server ServerSelector) ([][2]string, error) {
	switch {
	case server.target.id != 0 && server.target.port != 0:
		return nil, fmt.Errorf("%w: a server is selected by id or by port, not both", teamspeak.ErrInvalidCommand)
	case server.target.id != 0:
		return [][2]string{{"sid", strconv.FormatUint(uint64(server.target.id), 10)}}, nil
	case server.target.port != 0:
		return [][2]string{{"port", strconv.FormatUint(uint64(server.target.port), 10)}}, nil
	default:
		return nil, fmt.Errorf("%w: no server selected", teamspeak.ErrInvalidCommand)
	}
}

// forgetServer drops what the client knew of the server it was on: its own id
// and the clients it had seen. Both belong to the server, and are read again
// for the next one.
func (c *Client) forgetServer() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.selfID = 0
	c.selfNickname = ""
	clear(c.clients)
}

// NotificationOptions are RegisterNotifications' optional parameters.
//
// Experimental: this package may change in a minor release.
type NotificationOptions struct {
	// ChannelID limits a notification category to one channel (id), and with a
	// pointer to 0 widens `channel` to all of them. nil sends no id, which is
	// right for every category but `channel`: the server refuses that one
	// without an id. Connect registers `channel` with id 0.
	ChannelID *teamspeak.ChannelID
}

// RegisterNotifications asks the server for the notifications of one category,
// with `servernotifyregister`. Connect runs the same command once per
// category it is configured with (WithEvents).
//
// Once the server has accepted it, the client reads the server's client list
// again, as Connect does, so the events it fills from it — a text message's
// sender groups — are filled. Registering the same category twice is
// accepted.
//
// Needs b_virtualserver_notify_register, and b_client_ban_list for
// CategoryBans, which TeamSpeak 3 refuses with 1539. WebQuery has no session
// to notify, and refuses it with 5120.
//
// Experimental: this package may change in a minor release.
func (c *Client) RegisterNotifications(ctx context.Context, category Category, opts NotificationOptions) error {
	eng := c.currentEngine()
	if eng == nil {
		return teamspeak.ErrNotConnected
	}

	_, err := eng.Exec(ctx, notifyLine("servernotifyregister", category, opts.ChannelID))
	if err != nil {
		return err
	}
	c.readClientList(ctx, eng)

	return nil
}

// UnregisterNotificationsOptions are UnregisterNotifications' optional
// parameters. With none set it unregisters everything.
//
// Experimental: this package may change in a minor release.
type UnregisterNotificationsOptions struct {
	// ChannelID names the channel of a `channel` registration to drop (id); nil
	// sends none.
	ChannelID *teamspeak.ChannelID
	// Category drops that category only (event); "" drops every category. Only
	// TeamSpeak 6 takes it: TeamSpeak 3's servernotifyunregister has no
	// parameters, and accepts them without error and drops every category all
	// the same, measured.
	Category Category
}

// UnregisterNotifications stops the server's notifications, with
// `servernotifyunregister`: all of them, or with a Category on TeamSpeak 6
// that category's only. The On… handlers hear nothing more of what was
// dropped; they stay registered, and RegisterNotifications brings it back.
//
// It takes effect for this connection only. Needs
// b_virtualserver_notify_unregister, and b_client_ban_list for CategoryBans.
// Unregistering what was never registered is accepted. WebQuery refuses it
// with 5120.
//
// Experimental: this package may change in a minor release.
func (c *Client) UnregisterNotifications(ctx context.Context, opts UnregisterNotificationsOptions) error {
	eng := c.currentEngine()
	if eng == nil {
		return teamspeak.ErrNotConnected
	}

	_, err := eng.Exec(ctx, notifyLine("servernotifyunregister", opts.Category, opts.ChannelID))

	return err
}

// notifyLine builds servernotifyregister or servernotifyunregister: the
// category as event, when there is one, and the channel as id.
func notifyLine(command string, category Category, channelID *teamspeak.ChannelID) string {
	var params [][2]string
	if category != "" {
		params = append(params, [2]string{"event", string(category)})
	}
	if channelID != nil {
		params = append(params, [2]string{"id", strconv.FormatUint(uint64(*channelID), 10)})
	}

	return wire.BuildCommandOrdered(command, params)
}
