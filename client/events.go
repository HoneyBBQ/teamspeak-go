package client

import (
	"maps"
	"slices"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/eventbus"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// Event delivery
//
// Handlers run one at a time, in the order their events arrived, on a goroutine
// of the client's own, so a handler may call the client — send a command and
// wait for its answer — without stalling the connection. The queue itself, and
// the rule about a panic in a handler, are shared with the ServerQuery client;
// see internal/eventbus.

// The handlers registered for each event, and the queue they are delivered on.
// The types come from internal/eventbus, which both clients use.
type (
	subscribers[E any] = eventbus.Subscribers[E]
	eventQueue         = eventbus.Queue
)

// OnTextMessage registers a handler for incoming text messages. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnTextMessage(handler func(TextMessageEvent)) func() {
	return c.onTextMessage.Add(handler)
}

// OnClientEnter registers a handler for clients entering view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientEnter(handler func(ClientEnterEvent)) func() {
	return c.onClientEnter.Add(handler)
}

// OnClientLeave registers a handler for clients leaving view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientLeave(handler func(ClientLeaveEvent)) func() {
	return c.onClientLeave.Add(handler)
}

// OnPoked registers a handler for pokes this client receives. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnPoked(handler func(PokeEvent)) func() {
	return c.onPoked.Add(handler)
}

// OnKicked registers a handler for this client being kicked from its channel
// or the server. A kick from the server also ends the connection, which
// OnDisconnected reports with a *RemovedError. It returns a function that
// removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnKicked(handler func(KickedEvent)) func() {
	return c.onKicked.Add(handler)
}

// OnClientMoved registers a handler for clients moving between channels. It
// returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientMoved(handler func(ClientMovedEvent)) func() {
	return c.onClientMoved.Add(handler)
}

// OnVoiceData registers a handler for incoming voice or whisper audio. It
// returns a function that removes the handler.
//
// Voice is the one event that can be dropped: when more than 256 deliveries
// of any kind are waiting for the handlers, incoming voice is discarded until
// they catch up, and the client logs a warning, at most once every ten
// seconds, with how much it dropped. Every other event is always delivered.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnVoiceData(handler func(VoiceDataEvent)) func() {
	return c.onVoiceData.Add(handler)
}

// OnNotification registers a handler for every notification the server sends,
// as it arrived: the way to hear one the SDK does not model. It runs after the
// typed handlers for the same notification. It returns a function that removes
// the handler. The notify package names the notifications to match on.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnNotification(handler func(NotificationEvent)) func() {
	return c.onNotification.Add(handler)
}

// OnConnected registers a handler for the handshake completing, on Connect and
// on every reconnection; the event's Reconnected tells them apart. It returns a function that removes the handler.
//
// The event is queued as the handshake completes, when Connect returns nil,
// and delivered on the event goroutine: register the handler before Connect
// to be sure to hear it.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnConnected(handler func(ConnectedEvent)) func() {
	return c.onConnected.Add(handler)
}

// OnDisconnected registers a handler for the connection ending, or a
// connection attempt failing. The event's Err is nil after Disconnect, and the
// cause otherwise: a failed handshake, ErrConnectionTimeout for a server that
// stopped answering, or a *RemovedError for a kick, a ban or a server
// stopping; its WillReconnect says whether the reconnect loop will try again.
// It returns a function that removes the handler.
//
// Disconnect returns once the connection is closed and this event queued;
// the handlers run later, in order. Events go through one ordered queue, and
// a session's disconnected is queued before the next Connect can queue
// anything, so handlers see it before that session's connected and before
// any other event of it. A handler may call Connect and Disconnect.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnDisconnected(handler func(DisconnectedEvent)) func() {
	return c.onDisconnected.Add(handler)
}

// currentHandler returns the packet handler of the current connection.
func (c *Client) currentHandler() *transport.PacketHandler {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.handler
}

// connectedHandler returns the current packet handler if its handshake has
// completed, or nil. Commands and voice go only to a connected session: sent
// mid-handshake they would reach a server that cannot read them yet, under
// the dummy key.
func (c *Client) connectedHandler() *transport.PacketHandler {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.status != StatusConnected {
		return nil
	}

	return c.handler
}

// sendLine sends a command line on h.
func (c *Client) sendLine(h *transport.PacketHandler, line string) error {
	if c.wireHook != nil {
		err := c.wireHook(line)
		if err != nil {
			return err
		}
	}

	return notConnected(h.SendPacket(byte(transport.PacketTypeCommand), []byte(line), 0))
}

// buildMiddlewareChains wraps the typed commands and the event dispatch in
// the configured middleware. It runs once, in New: the chains are read on every
// command and event, so changing them afterwards would race with both.
func (c *Client) buildMiddlewareChains() {
	c.executor = teamspeak.ExecutorFunc(c.sendRequest)
	for _, middleware := range slices.Backward(c.cmdMiddlewares) {
		c.executor = middleware(c.executor)
	}

	c.evtChain = c.dispatchEvent
	for _, middleware := range slices.Backward(c.eventMiddlewares) {
		c.evtChain = middleware(c.evtChain)
	}
}

// emitEvent queues a server event. The middleware runs on the delivery
// goroutine too, so a slow middleware does not stall the read loop either.
func (c *Client) emitEvent(evt Event) {
	run := func() { eventbus.CallHandler(c.logger, eventbus.EventName(evt), func() { c.evtChain(evt) }) }
	if _, voice := evt.(VoiceDataEvent); voice {
		c.events.PushVoice(run, c.logger)

		return
	}
	c.events.Push(run)
}

// emit queues a lifecycle event, which middleware does not see.
func emit[E any](c *Client, subs *subscribers[E], name string, evt E) {
	c.events.Push(func() { subs.Deliver(c.logger, name, evt, nil) })
}

// dispatchEvent hands a server event, as the middleware left it, to its
// handlers.
func (c *Client) dispatchEvent(evt Event) {
	switch e := evt.(type) {
	case TextMessageEvent:
		c.onTextMessage.Deliver(c.logger, eventbus.EventName(e), e, func(m TextMessageEvent) TextMessageEvent {
			m.InvokerGroups = slices.Clone(m.InvokerGroups)

			return m
		})
	case ClientEnterEvent:
		c.onClientEnter.Deliver(c.logger, eventbus.EventName(e), e, func(enter ClientEnterEvent) ClientEnterEvent {
			enter.ServerGroups = slices.Clone(enter.ServerGroups)

			return enter
		})
	case ClientLeaveEvent:
		c.onClientLeave.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientMovedEvent:
		c.onClientMoved.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case PokeEvent:
		c.onPoked.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case VoiceDataEvent:
		c.onVoiceData.Deliver(c.logger, eventbus.EventName(e), e, func(v VoiceDataEvent) VoiceDataEvent {
			v.Data = slices.Clone(v.Data)

			return v
		})
	case NotificationEvent:
		c.onNotification.Deliver(c.logger, eventbus.EventName(e), e, func(n NotificationEvent) NotificationEvent {
			n.Params = maps.Clone(n.Params)

			return n
		})
	}
}
