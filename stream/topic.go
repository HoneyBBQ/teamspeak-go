package stream

import (
	"container/list"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/honeybbq/teamspeak-go/internal/eventbus"
)

// maxKept is how many events a topic keeps for its first handler.
const maxKept = 256

// bus is where every handler of a Streams runs: one queue, so events reach
// handlers one at a time, in the order they happened.
type bus struct {
	logger *slog.Logger
	// mu is the Streams' lock, which guards every topic.
	mu    *sync.Mutex
	queue eventbus.Queue
}

// handler is one registered function.
type handler[E any] struct {
	fn func(E)
	// removed is checked before every call, so a handler is not called again
	// once its off function has returned, even for an event already queued.
	removed atomic.Bool
}

// topic delivers one kind of event to the handlers registered for it.
//
// Its methods run with the Streams' lock held and never wait: an emit only
// queues a delivery, and the handlers run later on the bus's goroutine, so a
// handler may call any method of the package. Queuing under the lock is what
// makes the order of events the order of the state changes behind them.
//
// A topic made with keep holds the events that happen while no handler has ever
// been added, up to maxKept, and hands them in order to the first handler. That
// bridges the time between being given an object and attaching to it, in
// which the server does not wait. Past the bound the oldest is dropped and
// onDrop hears of it.
type topic[E any] struct {
	bus      *bus
	clone    func(E) E
	onDrop   func(name string)
	name     string
	handlers []*handler[E]
	kept     []E
	keep     bool
	attached bool
}

func newTopic[E any](b *bus, name string, keep bool) *topic[E] {
	return &topic[E]{bus: b, name: name, keep: keep}
}

// on adds fn and returns the function that removes it. The caller holds the
// lock.
func (t *topic[E]) on(fn func(E)) func() {
	h := &handler[E]{fn: fn}
	// A new slice, because a delivery already queued ranges over the old one.
	t.handlers = append(slices.Clone(t.handlers), h)
	if !t.attached {
		t.attached = true
		for _, e := range t.kept {
			t.bus.queue.Push(func() { t.call(h, e) })
		}
		t.kept = nil
	}

	return func() {
		if h.removed.Swap(true) {
			return
		}
		t.bus.mu.Lock()
		defer t.bus.mu.Unlock()
		t.handlers = slices.DeleteFunc(slices.Clone(t.handlers), func(x *handler[E]) bool { return x == h })
	}
}

// emit queues e for the handlers, or keeps it for the first one. The caller
// holds the lock.
func (t *topic[E]) emit(e E) {
	if !t.attached {
		if t.keep {
			t.hold(e)
		}

		return
	}
	handlers := t.handlers
	t.bus.queue.Push(func() {
		for i, h := range handlers {
			// Each handler gets its own copy when the event holds pointers,
			// so one cannot change what the next sees.
			own := e
			if t.clone != nil && i < len(handlers)-1 {
				own = t.clone(e)
			}
			t.call(h, own)
		}
	})
}

func (t *topic[E]) hold(e E) {
	t.kept = append(t.kept, e)
	if len(t.kept) > maxKept {
		t.kept = slices.Delete(t.kept, 0, 1)
		if t.onDrop != nil {
			t.onDrop(t.name)
		}
	}
}

func (t *topic[E]) call(h *handler[E], e E) {
	if h.removed.Load() {
		return
	}
	eventbus.CallHandler(t.bus.logger, "stream."+t.name, func() { h.fn(e) })
}

// lru is a set that remembers its most recent members, up to a bound: adding
// one past it forgets the oldest, and adding a member again makes it the
// newest. It is not safe for concurrent use; the Streams' lock guards it.
type lru[K comparable] struct {
	items map[K]*list.Element
	order list.List
	max   int
}

func newLRU[K comparable](limit int) *lru[K] {
	return &lru[K]{items: make(map[K]*list.Element), max: limit}
}

func (l *lru[K]) add(k K) {
	if el, ok := l.items[k]; ok {
		l.order.MoveToBack(el)

		return
	}
	l.items[k] = l.order.PushBack(k)
	if l.order.Len() > l.max {
		oldest := l.order.Front()
		delete(l.items, oldest.Value.(K)) //nolint:forcetypeassert // only K is stored
		l.order.Remove(oldest)
	}
}

func (l *lru[K]) has(k K) bool {
	_, ok := l.items[k]

	return ok
}

func (l *lru[K]) remove(k K) {
	if el, ok := l.items[k]; ok {
		l.order.Remove(el)
		delete(l.items, k)
	}
}

func (l *lru[K]) clear() {
	clear(l.items)
	l.order.Init()
}
