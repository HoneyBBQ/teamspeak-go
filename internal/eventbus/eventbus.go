// Package eventbus delivers events to handlers: one at a time, in the order
// they arrived, on a goroutine of its own.
//
// Both clients need the same delivery, so it is here rather than in either of
// them. Order matters: a client that enters and leaves at once must not be
// reported as leaving first, and a goroutine per handler can do exactly that.
// The queue never waits for a handler, so a handler may send a command on the
// connection and wait for its answer without stalling it. A handler that
// blocks does hold up the events queued behind it; hand long work to a
// goroutine of your own.
//
// Each handler gets its own copy of the event when the producer asks for one,
// so one handler changing a slice it was given cannot change what the next one
// sees.
//
// A handler that panics does not take the process down, nor stop delivery: the
// panic is recovered, logged at Error with the event type, the panic value and
// the stack, and the remaining handlers and events are delivered as usual.
package eventbus

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Queue runs queued deliveries one at a time, in order. Its goroutine exists
// only while there is something to deliver, so a client that is dropped
// without ever disconnecting leaks nothing.
//
// The zero value is ready to use.
type Queue struct {
	lastVoiceWarn time.Time
	pending       []func()
	// voiceDropped counts voice deliveries dropped since the last warning.
	voiceDropped uint64
	mu           sync.Mutex
	running      bool
}

// Push queues a delivery.
func (q *Queue) Push(delivery func()) {
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

// Queued reports how many deliveries are pending, counting the one running.
// It is meant for tests: a caller has no reason to look.
func (q *Queue) Queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		return 0
	}

	return len(q.pending) - 1 + boolToInt(q.running)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// Subscribers are the handlers registered for one kind of event. The zero
// value is ready to use.
type Subscribers[E any] struct {
	list []*subscriber[E]
	mu   sync.Mutex
}

type subscriber[E any] struct {
	fn func(E)
	// removed is checked before every call, so a handler is not called again
	// once its unsubscribe has returned, even for an event already queued.
	removed atomic.Bool
}

// Add registers fn and returns a function that removes it.
func (s *Subscribers[E]) Add(fn func(E)) func() {
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

// Any reports whether a handler is registered, so a producer can skip building
// an event nobody will receive.
func (s *Subscribers[E]) Any() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.list) > 0
}

// Deliver calls each handler with evt, or with its own copy when clone is set.
// name is the event's type name, for the panic log. A handler that panics is
// logged under name and skipped; the rest still run.
func (s *Subscribers[E]) Deliver(logger *slog.Logger, name string, evt E, clone func(E) E) {
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
		CallHandler(logger, name, func() { sub.fn(e) })
	}
}

// CallHandler runs fn, a handler or middleware for an event of type name, and
// recovers a panic in it: logged at Error, so it is not hidden, but one bad
// handler does not end delivery for the others or crash the process.
func CallHandler(logger *slog.Logger, name string, fn func()) {
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

// EventName is the event's type name without its package path, as the panic
// log reports it.
func EventName(evt any) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", evt), "teamspeak.")
}

// MaxQueuedForVoice is how many deliveries may be pending before voice is
// dropped. Ordinary events are rare and always queued; voice arrives fifty
// times a second per speaker, so a handler slower than that would otherwise
// grow the queue without bound.
const MaxQueuedForVoice = 256

// VoiceDropWarnInterval is the least time between two warnings about dropped
// voice.
const VoiceDropWarnInterval = 10 * time.Second

// PushVoice queues a voice delivery, or drops it when more than
// MaxQueuedForVoice deliveries are already waiting, warning at most once per
// VoiceDropWarnInterval with how many were dropped.
func (q *Queue) PushVoice(delivery func(), logger *slog.Logger) {
	q.mu.Lock()
	if len(q.pending) > MaxQueuedForVoice {
		q.voiceDropped++
		now := time.Now()
		if now.Sub(q.lastVoiceWarn) < VoiceDropWarnInterval {
			q.mu.Unlock()

			return
		}
		dropped := q.voiceDropped
		q.voiceDropped = 0
		q.lastVoiceWarn = now
		q.mu.Unlock()
		logger.Warn("event handlers are falling behind, dropping voice data",
			slog.Uint64("dropped", dropped), slog.Int("queued", MaxQueuedForVoice))

		return
	}
	q.mu.Unlock()
	q.Push(delivery)
}

func (q *Queue) drain() {
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
