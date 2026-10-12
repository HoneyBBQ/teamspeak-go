package client

import (
	"fmt"
	"log/slog"
	"maps"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
//
// A handler that panics does not take the process down, nor stop delivery: the
// panic is recovered, logged at Error with the event type, the panic value
// and the stack, and the remaining handlers and events are delivered as
// usual. The same holds for event middleware. The client's own state is not
// touched by a handler, so it stays consistent.

// OnTextMessage registers a handler for incoming text messages. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnTextMessage(handler func(TextMessageEvent)) func() {
	return c.onTextMessage.add(handler)
}

// OnClientEnter registers a handler for clients entering view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientEnter(handler func(ClientEnterEvent)) func() {
	return c.onClientEnter.add(handler)
}

// OnClientLeave registers a handler for clients leaving view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientLeave(handler func(ClientLeaveEvent)) func() {
	return c.onClientLeave.add(handler)
}

// OnPoked registers a handler for pokes this client receives. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnPoked(handler func(PokeEvent)) func() {
	return c.onPoked.add(handler)
}

// OnKicked registers a handler for this client being kicked from its channel
// or the server. A kick from the server also ends the connection, which
// OnDisconnected reports with a *RemovedError. It returns a function that
// removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnKicked(handler func(KickedEvent)) func() {
	return c.onKicked.add(handler)
}

// OnClientMoved registers a handler for clients moving between channels. It
// returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientMoved(handler func(ClientMovedEvent)) func() {
	return c.onClientMoved.add(handler)
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
	return c.onVoiceData.add(handler)
}

// OnNotification registers a handler for every notification the server sends,
// as it arrived: the way to hear one the SDK does not model. It runs after the
// typed handlers for the same notification. It returns a function that removes
// the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnNotification(handler func(NotificationEvent)) func() {
	return c.onNotification.add(handler)
}

// OnConnected registers a handler for the handshake completing, on Connect and
// on every reconnection. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnConnected(handler func()) func() {
	return c.onConnected.add(func(struct{}) { handler() })
}

// OnDisconnected registers a handler for the connection ending. It receives
// nil after Disconnect, and the cause otherwise: a failed handshake, ErrTimedOut
// for a server that stopped answering, or a *RemovedError for a kick, a ban or
// a server stopping. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnDisconnected(handler func(err error)) func() {
	return c.onDisconnected.add(handler)
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

// emitEvent queues a server event. The middleware runs on the delivery
// goroutine too, so a slow middleware does not stall the read loop either.
func (c *Client) emitEvent(evt Event) {
	run := func() { callHandler(c.logger, eventName(evt), func() { c.evtChain(evt) }) }
	if _, voice := evt.(VoiceDataEvent); voice {
		c.events.pushVoice(run, c.logger)

		return
	}
	c.events.push(run)
}

// emit queues a lifecycle event, which middleware does not see.
func emit[E any](c *Client, subs *subscribers[E], name string, evt E) {
	c.events.push(func() { subs.deliver(c.logger, name, evt, nil) })
}

// dispatchEvent hands a server event, as the middleware left it, to its
// handlers.
func (c *Client) dispatchEvent(evt Event) {
	switch e := evt.(type) {
	case TextMessageEvent:
		c.onTextMessage.deliver(c.logger, eventName(e), e, func(m TextMessageEvent) TextMessageEvent {
			m.InvokerGroups = slices.Clone(m.InvokerGroups)

			return m
		})
	case ClientEnterEvent:
		c.onClientEnter.deliver(c.logger, eventName(e), e, func(enter ClientEnterEvent) ClientEnterEvent {
			enter.ServerGroups = slices.Clone(enter.ServerGroups)

			return enter
		})
	case ClientLeaveEvent:
		c.onClientLeave.deliver(c.logger, eventName(e), e, nil)
	case ClientMovedEvent:
		c.onClientMoved.deliver(c.logger, eventName(e), e, nil)
	case PokeEvent:
		c.onPoked.deliver(c.logger, eventName(e), e, nil)
	case VoiceDataEvent:
		c.onVoiceData.deliver(c.logger, eventName(e), e, func(v VoiceDataEvent) VoiceDataEvent {
			v.Data = slices.Clone(v.Data)

			return v
		})
	case NotificationEvent:
		c.onNotification.deliver(c.logger, eventName(e), e, func(n NotificationEvent) NotificationEvent {
			n.Params = maps.Clone(n.Params)

			return n
		})
	}
}

// eventName is the event's type name, as the panic log reports it.
func eventName(evt Event) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", evt), "client.")
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
// A handler that panics is logged under name and skipped; the rest still run.
func (s *subscribers[E]) deliver(logger *slog.Logger, name string, evt E, clone func(E) E) {
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
		callHandler(logger, name, func() { sub.fn(e) })
	}
}

// callHandler runs fn, a handler or middleware for an event of type name, and
// recovers a panic in it: logged at Error, so it is not hidden, but one bad
// handler does not end delivery for the others or crash the process.
func callHandler(logger *slog.Logger, name string, fn func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		logger.Error("event handler panicked",
			slog.String("event", name),
			slog.Any("panic", r),
			slog.String("stack", string(debug.Stack())))
	}()
	fn()
}

// maxQueuedForVoice is how many deliveries may be pending before voice is
// dropped. Ordinary events are rare and always queued; voice arrives fifty
// times a second per speaker, so a handler slower than that would otherwise
// grow the queue without bound.
const maxQueuedForVoice = 256

// voiceDropWarnInterval is the least time between two warnings about dropped
// voice.
const voiceDropWarnInterval = 10 * time.Second

// eventQueue runs queued deliveries one at a time, in order. Its goroutine
// exists only while there is something to deliver, so a client that is
// dropped without Disconnect leaks nothing.
type eventQueue struct {
	lastVoiceWarn time.Time
	pending       []func()
	// voiceDropped counts voice deliveries dropped since the last warning.
	voiceDropped uint64
	mu           sync.Mutex
	running      bool
}

// pushVoice queues a voice delivery, or drops it when more than
// maxQueuedForVoice deliveries are already waiting, warning at most once per
// voiceDropWarnInterval with how many were dropped.
func (q *eventQueue) pushVoice(delivery func(), logger *slog.Logger) {
	q.mu.Lock()
	if len(q.pending) > maxQueuedForVoice {
		q.voiceDropped++
		now := time.Now()
		if now.Sub(q.lastVoiceWarn) < voiceDropWarnInterval {
			q.mu.Unlock()

			return
		}
		dropped := q.voiceDropped
		q.voiceDropped = 0
		q.lastVoiceWarn = now
		q.mu.Unlock()
		logger.Warn("event handlers are falling behind, dropping voice data",
			slog.Uint64("dropped", dropped), slog.Int("queued", maxQueuedForVoice))

		return
	}
	q.mu.Unlock()
	q.push(delivery)
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
