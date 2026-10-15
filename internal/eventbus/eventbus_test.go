package eventbus_test

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/eventbus"
)

// Voice is dropped once the queue is backed up; other events are not.
func TestQueueDropsVoiceWhenBackedUp(t *testing.T) {
	var q eventbus.Queue
	release := make(chan struct{})
	q.Push(func() { <-release })
	var delivered atomic.Int32
	for range eventbus.MaxQueuedForVoice + 50 {
		q.PushVoice(func() { delivered.Add(1) }, slog.New(slog.DiscardHandler))
	}
	ordinary := make(chan struct{})
	q.Push(func() { close(ordinary) })
	close(release)

	select {
	case <-ordinary:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary event not delivered")
	}
	want := int32(eventbus.MaxQueuedForVoice)
	if got := delivered.Load(); got > want+1 || got < want {
		t.Errorf("delivered %d voice events, want about %d", got, want)
	}
}

// Deliveries run one at a time, in the order they were queued: a client that
// enters and leaves at once must not be reported as leaving first.
func TestQueueDeliversInOrder(t *testing.T) {
	var q eventbus.Queue
	const n = 50
	var mu sync.Mutex
	var seen []int
	done := make(chan struct{})

	for i := range n {
		q.Push(func() {
			mu.Lock()
			seen = append(seen, i)
			mu.Unlock()
		})
	}
	q.Push(func() { close(done) })

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the queue did not drain")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != n {
		t.Fatalf("delivered %d events, want %d", len(seen), n)
	}
	for i, got := range seen {
		if got != i {
			t.Fatalf("delivered %v, want the queue's order", seen)
		}
	}
}

// The queue's goroutine goes away once there is nothing left to deliver, so a
// client that is dropped without disconnecting leaks nothing.
func TestQueueIsIdleWhenEmpty(t *testing.T) {
	var q eventbus.Queue
	done := make(chan struct{})
	q.Push(func() { close(done) })
	<-done

	deadline := time.Now().Add(2 * time.Second)
	for q.Queued() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the queue stayed busy with nothing to deliver")
		}
		time.Sleep(time.Millisecond)
	}
}

// A removed handler is not called again, even for an event already queued when
// its unsubscribe returned.
func TestSubscribers_RemoveStopsDelivery(t *testing.T) {
	var subs eventbus.Subscribers[int]
	calls := make(chan int, 4)
	remove := subs.Add(func(v int) { calls <- v })

	if !subs.Any() {
		t.Fatal("Any reported no handlers after one was added")
	}
	remove()
	if subs.Any() {
		t.Fatal("Any still reports a handler that was removed")
	}
	subs.Deliver(slog.New(slog.DiscardHandler), "Int", 1, nil)

	select {
	case v := <-calls:
		t.Fatalf("a removed handler was called with %d", v)
	case <-time.After(50 * time.Millisecond):
	}
}

// Each handler but the last gets its own copy, so one changing what it was
// given cannot change what the next one sees.
func TestSubscribers_CloneReachesAllButTheLast(t *testing.T) {
	var subs eventbus.Subscribers[[]string]
	var first, last []string
	subs.Add(func(v []string) { first = v })
	subs.Add(func(v []string) { last = v })

	original := []string{"a"}
	clone := func(v []string) []string { return append([]string(nil), v...) }
	subs.Deliver(slog.New(slog.DiscardHandler), "List", original, clone)

	first[0] = "changed"
	if last[0] != "a" {
		t.Errorf("the second handler saw %v, want its own copy", last)
	}
}

// A handler that panics is logged and skipped; the rest still run. Without
// this the process would die on a caller's bug.
func TestCallHandlerRecoversPanic(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	reached := false
	eventbus.CallHandler(logger, "Panicky", func() { panic("boom") })
	eventbus.CallHandler(logger, "Panicky", func() { reached = true })

	if !reached {
		t.Error("delivery did not continue after a handler panicked")
	}
}
