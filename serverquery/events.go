package serverquery

import (
	"log/slog"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// Event delivery
//
// Handlers run one at a time, in the order their events arrived, on a goroutine
// of the client's own, so a handler may send a command on the query connection
// and wait for its answer without stalling the read loop. A handler that
// blocks does hold up the events behind it; hand long work to a goroutine of
// your own. A handler that panics is recovered and logged at Error with the
// event type; the other handlers and later events are still delivered.
//
// The queue and the subscribers are shared with the voice client; see
// internal/eventbus.
//
// Registration is a property of the transport. Over WebQuery, which the server
// can push nothing to, the On… methods for server events below are inert, and
// they say so once, at Warn, rather than failing: see the package
// documentation for why. OnConnected and OnDisconnected report the connection
// itself and work over every transport.

// OnTextMessage registers a handler for incoming text messages. It returns a
// function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — no message arrives,
// and the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnTextMessage(handler func(teamspeak.TextMessageEvent)) func() {
	return c.serverEvent("OnTextMessage", func() func() {
		return c.subs.textMessage.Add(handler)
	})
}

// OnClientEnter registers a handler for clients coming into view: on
// connecting, for everyone already there, and whenever someone joins. It
// returns a function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — no client enters
// view, and the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnClientEnter(handler func(teamspeak.ClientEnterEvent)) func() {
	return c.serverEvent("OnClientEnter", func() func() {
		return c.subs.clientEnter.Add(handler)
	})
}

// OnClientLeave registers a handler for clients leaving view. It returns a
// function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — no client leaves
// view, and the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnClientLeave(handler func(teamspeak.ClientLeaveEvent)) func() {
	return c.serverEvent("OnClientLeave", func() func() {
		return c.subs.clientLeave.Add(handler)
	})
}

// OnClientMoved registers a handler for clients moving between channels,
// itself included. It returns a function that removes the handler.
//
// A move of this client's own names no invoker in the notification, so the
// event's InvokerID and InvokerName are filled from what the client knows of
// itself.
//
// Over a transport that cannot deliver events — WebQuery — no client moves, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnClientMoved(handler func(teamspeak.ClientMovedEvent)) func() {
	return c.serverEvent("OnClientMoved", func() func() {
		return c.subs.clientMoved.Add(handler)
	})
}

// OnChannelCreated registers a handler for channels being created. It is
// delivered under the channel category. The event's Changes hold the properties
// the server sent, which are those that differ from a new channel's defaults. It
// returns a function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelCreated(handler func(teamspeak.ChannelCreatedEvent)) func() {
	return c.serverEvent("OnChannelCreated", func() func() {
		return c.subs.channelCreated.Add(handler)
	})
}

// OnChannelEdited registers a handler for channels being edited, delivered under
// the channel category. The event's Changes hold only what changed. It returns a
// function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelEdited(handler func(teamspeak.ChannelEditedEvent)) func() {
	return c.serverEvent("OnChannelEdited", func() func() {
		return c.subs.channelEdited.Add(handler)
	})
}

// OnChannelMoved registers a handler for channels being moved or reordered,
// delivered under the channel category. It returns a function that removes the
// handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelMoved(handler func(teamspeak.ChannelMovedEvent)) func() {
	return c.serverEvent("OnChannelMoved", func() func() {
		return c.subs.channelMoved.Add(handler)
	})
}

// OnChannelDeleted registers a handler for channels being deleted, delivered
// under the channel category. It returns a function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelDeleted(handler func(teamspeak.ChannelDeletedEvent)) func() {
	return c.serverEvent("OnChannelDeleted", func() func() {
		return c.subs.channelDeleted.Add(handler)
	})
}

// OnChannelDescriptionChanged registers a handler for a channel's description
// changing, delivered under the channel category. The event does not carry the
// text; GetChannelInfo has it. It returns a function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelDescriptionChanged(handler func(teamspeak.ChannelDescriptionChangedEvent)) func() {
	return c.serverEvent("OnChannelDescriptionChanged", func() func() {
		return c.subs.channelDesc.Add(handler)
	})
}

// OnChannelPasswordChanged registers a handler for a channel's password being
// set, changed or removed, delivered under the channel category. It returns a
// function that removes the handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnChannelPasswordChanged(handler func(teamspeak.ChannelPasswordChangedEvent)) func() {
	return c.serverEvent("OnChannelPasswordChanged", func() func() {
		return c.subs.channelPassword.Add(handler)
	})
}

// OnServerEdited registers a handler for the virtual server's settings being
// edited, delivered under the server category. The event's Changes are the
// changed properties by their wire names. It returns a function that removes the
// handler.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives, and
// the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnServerEdited(handler func(teamspeak.ServerEditedEvent)) func() {
	return c.serverEvent("OnServerEdited", func() func() {
		return c.subs.serverEdited.Add(handler)
	})
}

// OnKicked registers a handler for this client being kicked from its channel.
// It returns a function that removes the handler.
//
// A query client cannot be kicked from the server: the server refuses that
// with 516. A channel kick is accepted and arrives as a move, so OnKicked
// reports it while the connection stays up and the client lands in the default
// channel. A ban still ends the session, and is reported here too.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives,
// and the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnKicked(handler func(teamspeak.KickedEvent)) func() {
	return c.serverEvent("OnKicked", func() func() {
		return c.onKicked.Add(handler)
	})
}

// OnNotification registers a handler for every notification the server sends,
// as it arrived: the way to hear one the SDK does not model. It runs after the
// typed handler for the same notification. It returns a function that removes
// the handler. The notify package names the notifications to match on.
//
// Over a transport that cannot deliver events — WebQuery — nothing arrives,
// and the returned function does nothing; the client logs once at Warn.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnNotification(handler func(teamspeak.NotificationEvent)) func() {
	return c.serverEvent("OnNotification", func() func() {
		return c.subs.notification.Add(handler)
	})
}

// OnConnected registers a handler for the connection becoming ready, on
// Connect and on every reconnection the reconnect options allow; the event's
// Reconnected tells them apart. It returns a function that removes the
// handler. The event is queued as Connect returns, so register the handler
// first to be sure to hear it.
//
// This is the connection's own event rather than the server's, so it fires
// over every transport, WebQuery included.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnConnected(handler func(teamspeak.ConnectedEvent)) func() {
	return c.onConnected.Add(handler)
}

// OnDisconnected registers a handler for the connection ending, or an attempt
// to make one failing. Err is nil after Disconnect, and the cause otherwise:
// a refused login, a closed transport, or teamspeak.ErrNotConnected for a
// connection that ended without saying why. WillReconnect says whether the
// reconnect loop will try again. It returns a function that removes the
// handler.
//
// This is the connection's own event rather than the server's, so it fires
// over every transport, WebQuery included.
//
// Experimental: this package may change in a minor release.
func (c *Client) OnDisconnected(handler func(teamspeak.DisconnectedEvent)) func() {
	return c.onDisconnected.Add(handler)
}

// serverEvent registers a handler for a server event, or, over a transport
// that cannot deliver events, returns an inert unsubscribe and warns once.
//
// It is a no-op rather than an error because the On… methods cannot return
// one — the voice client's signature is what a caller switching between the
// two expects — and because refusing the connection outright would refuse the
// one transport TeamSpeak 6 serves by default. The warning fires once per
// method, so a caller registering in a loop is not flooded.
func (c *Client) serverEvent(method string, register func() func()) func() {
	if c.dialer.SupportsNotifications() {
		return register()
	}

	c.mu.Lock()
	warned := c.warned[method]
	c.warned[method] = true
	dialer, logger := c.dialer, c.logger
	c.mu.Unlock()

	if !warned {
		logger.Warn(method+" will never fire over this transport",
			slog.String("transport", dialer.String()),
			slog.String("reason", "the server cannot push notifications to it"))
	}

	return func() {}
}
