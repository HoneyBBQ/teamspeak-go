package client

import (
	"slices"
	"sync"
	"sync/atomic"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// Event delivery
//
// Handlers run one at a time, in the order their events arrived, on a goroutine
// of the client's own. Order matters: a client that enters and leaves at once
// must not be reported as leaving first, and the old per-handler goroutines
// could do exactly that. The read loop never waits for a handler, so a handler
// may call the client — send a command and wait for its answer — without
// stalling the connection. A handler that blocks does hold up the events
// queued behind it; hand long work to a goroutine of your own.
//
// Each handler gets its own copy of the event, so one handler changing a slice
// it was given cannot change what the next one sees.

// OnTextMessage registers a handler for incoming text messages. It returns a
// function that removes the handler.
func (c *Client) OnTextMessage(handler func(TextMessage)) func() {
	return c.onTextMessage.add(handler)
}

// OnClientEnter registers a handler for clients entering view. It returns a
// function that removes the handler.
func (c *Client) OnClientEnter(handler func(teamspeak.ClientInfo)) func() {
	return c.onClientEnter.add(handler)
}

// OnClientLeave registers a handler for clients leaving view. It returns a
// function that removes the handler.
func (c *Client) OnClientLeave(handler func(ClientLeftViewEvent)) func() {
	return c.onClientLeave.add(handler)
}

// OnPoked registers a handler for pokes this client receives. It returns a
// function that removes the handler.
func (c *Client) OnPoked(handler func(PokeEvent)) func() {
	return c.onPoked.add(handler)
}

// OnKicked registers a handler for this client being kicked from its channel
// or the server. A kick from the server also ends the connection, which
// OnDisconnected reports with a *RemovedError. It returns a function that
// removes the handler.
func (c *Client) OnKicked(handler func(KickedEvent)) func() {
	return c.onKicked.add(handler)
}

// OnClientMoved registers a handler for clients moving between channels. It
// returns a function that removes the handler.
func (c *Client) OnClientMoved(handler func(ClientMovedEvent)) func() {
	return c.onClientMoved.add(handler)
}

// OnVoiceData registers a handler for incoming voice or whisper audio. It
// returns a function that removes the handler.
func (c *Client) OnVoiceData(handler func(VoiceData)) func() {
	return c.onVoiceData.add(handler)
}

// OnConnected registers a handler for the handshake completing, on Connect and
// on every reconnection. It returns a function that removes the handler.
func (c *Client) OnConnected(handler func()) func() {
	return c.onConnected.add(func(struct{}) { handler() })
}

// OnDisconnected registers a handler for the connection ending. It receives
// nil after Disconnect, and the cause otherwise: a failed handshake, ErrTimedOut
// for a server that stopped answering, or a *RemovedError for a kick, a ban or
// a server stopping. It returns a function that removes the handler.
func (c *Client) OnDisconnected(handler func(err error)) func() {
	return c.onDisconnected.add(handler)
}

// buildMiddlewareChains wraps the command sender and the event dispatch in the
// configured middleware. It runs once, in New: the chains are read on every
// command and event, so changing them afterwards would race with both.
func (c *Client) buildMiddlewareChains() {
	c.finalCmdHandler = func(cmd string) error {
		return c.currentHandler().SendPacket(2, []byte(cmd), 0)
	}
	for _, middleware := range slices.Backward(c.cmdMiddlewares) {
		c.finalCmdHandler = middleware(c.finalCmdHandler)
	}

	c.evtChain = c.dispatchEvent
	for _, middleware := range slices.Backward(c.eventMiddlewares) {
		c.evtChain = middleware(c.evtChain)
	}
}

// currentHandler returns the packet handler of the current connection.
func (c *Client) currentHandler() *transport.PacketHandler {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.handler
}

// emitEvent queues a notification event. The middleware runs on the delivery
// goroutine too, so a slow middleware does not stall the read loop either.
func (c *Client) emitEvent(evt any) {
	c.events.push(func() { c.evtChain(evt) })
}

// emit queues a lifecycle event, which middleware does not see.
func emit[E any](c *Client, subs *subscribers[E], evt E) {
	c.events.push(func() { subs.deliver(evt, nil) })
}

// dispatchEvent hands a notification event, as the middleware left it, to its
// handlers.
func (c *Client) dispatchEvent(evt any) {
	switch e := evt.(type) {
	case TextMessage:
		c.onTextMessage.deliver(e, func(m TextMessage) TextMessage {
			m.InvokerGroups = slices.Clone(m.InvokerGroups)

			return m
		})
	case teamspeak.ClientInfo:
		c.onClientEnter.deliver(e, func(info teamspeak.ClientInfo) teamspeak.ClientInfo {
			info.ServerGroups = slices.Clone(info.ServerGroups)

			return info
		})
	case ClientLeftViewEvent:
		c.onClientLeave.deliver(e, nil)
	case ClientMovedEvent:
		c.onClientMoved.deliver(e, nil)
	case PokeEvent:
		c.onPoked.deliver(e, nil)
	case VoiceData:
		c.onVoiceData.deliver(e, func(v VoiceData) VoiceData {
			v.Data = slices.Clone(v.Data)

			return v
		})
	}
}

// subscribers are the handlers registered for one kind of event. The zero
// value is ready to use.
type subscribers[E any] struct {
	list []*subscriber[E]
	mu   sync.Mutex
}

type subscriber[E any] struct {
	fn func(E)
	// removed is checked before every call, so a handler is not called again
	// once its unsubscribe has returned, even for an event already queued.
	removed atomic.Bool
}

func (s *subscribers[E]) add(fn func(E)) func() {
	sub := &subscriber[E]{fn: fn}
	s.mu.Lock()
	s.list = append(s.list, sub)
	s.mu.Unlock()

	return func() {
		if sub.removed.Swap(true) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// A new slice rather than an edit in place: a delivery may be ranging
		// over the old one.
		s.list = slices.DeleteFunc(slices.Clone(s.list), func(x *subscriber[E]) bool { return x == sub })
	}
}

// any reports whether a handler is registered, so a producer can skip building
// an event nobody will receive.
func (s *subscribers[E]) any() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.list) > 0
}

// deliver calls each handler with evt, or with its own copy when clone is set.
func (s *subscribers[E]) deliver(evt E, clone func(E) E) {
	s.mu.Lock()
	list := s.list
	s.mu.Unlock()

	for i, sub := range list {
		if sub.removed.Load() {
			continue
		}
		e := evt
		// The last handler can have the original: nobody else will see it.
		if clone != nil && i < len(list)-1 {
			e = clone(evt)
		}
		sub.fn(e)
	}
}

// eventQueue runs queued deliveries one at a time, in order. Its goroutine
// exists only while there is something to deliver, so a client that is
// dropped without Disconnect leaks nothing.
type eventQueue struct {
	pending []func()
	mu      sync.Mutex
	running bool
}

func (q *eventQueue) push(delivery func()) {
	q.mu.Lock()
	q.pending = append(q.pending, delivery)
	if q.running {
		q.mu.Unlock()

		return
	}
	q.running = true
	q.mu.Unlock()

	go q.drain()
}

func (q *eventQueue) drain() {
	for {
		q.mu.Lock()
		if len(q.pending) == 0 {
			q.running = false
			q.pending = nil
			q.mu.Unlock()

			return
		}
		delivery := q.pending[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		q.mu.Unlock()

		delivery()
	}
}
