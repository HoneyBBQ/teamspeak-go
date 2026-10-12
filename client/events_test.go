package client

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// receive waits for one value from ch.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Second):
		t.Fatal("handler not called")

		var zero T

		return zero
	}
}

// settle waits for every queued delivery to finish.
func settle(t *testing.T, c *Client) {
	t.Helper()
	done := make(chan struct{})
	c.events.push(func() { close(done) })
	receive(t, done)
}

func TestOnTextMessage_RegistersHandler(t *testing.T) {
	c := newTestClient(t)
	called := make(chan TextMessage, 1)
	c.OnTextMessage(func(m TextMessage) { called <- m })

	c.emitEvent(TextMessage{Message: "hi"})

	if m := receive(t, called); m.Message != "hi" {
		t.Errorf("got %q, want hi", m.Message)
	}
}

func TestOnClientLeave_RegistersHandler(t *testing.T) {
	c := newTestClient(t)
	called := make(chan ClientLeftViewEvent, 1)
	c.OnClientLeave(func(e ClientLeftViewEvent) { called <- e })

	c.emitEvent(ClientLeftViewEvent{ID: 5})

	if e := receive(t, called); e.ID != 5 {
		t.Errorf("got ID %d, want 5", e.ID)
	}
}

func TestOnDisconnected_HearsADeliberateDisconnectAsNil(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusConnecting
	c.mu.Unlock()
	called := make(chan error, 1)
	c.OnDisconnected(func(err error) { called <- err })

	err := c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	got := receive(t, called)
	if got != nil {
		t.Errorf("OnDisconnected got %v, want nil after Disconnect", got)
	}
}

func TestMultipleHandlers_AllCalled(t *testing.T) {
	c := newTestClient(t)
	a := make(chan struct{}, 1)
	b := make(chan struct{}, 1)
	c.OnTextMessage(func(TextMessage) { a <- struct{}{} })
	c.OnTextMessage(func(TextMessage) { b <- struct{}{} })

	c.emitEvent(TextMessage{Message: "test"})

	receive(t, a)
	receive(t, b)
}

// Each handler used to run on a goroutine of its own, so a client that entered
// and left could be reported leaving first.
func TestEvents_ArriveInOrder(t *testing.T) {
	c := newTestClient(t)
	var mu sync.Mutex
	var got []uint16
	c.OnClientEnter(func(info teamspeak.ClientInfo) {
		mu.Lock()
		got = append(got, info.ID)
		mu.Unlock()
	})

	want := make([]uint16, 0, 200)
	for i := range uint16(200) {
		want = append(want, i)
		c.emitEvent(teamspeak.ClientInfo{ID: i})
	}
	settle(t, c)

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("events out of order: %v", got)
	}
}

func TestEvents_UnsubscribeStopsDelivery(t *testing.T) {
	c := newTestClient(t)
	called := make(chan TextMessage, 2)
	unsubscribe := c.OnTextMessage(func(m TextMessage) { called <- m })

	c.emitEvent(TextMessage{Message: "first"})
	receive(t, called)

	unsubscribe()
	unsubscribe() // a second call is harmless
	c.emitEvent(TextMessage{Message: "second"})
	settle(t, c)

	select {
	case m := <-called:
		t.Errorf("handler called after unsubscribe with %q", m.Message)
	default:
	}
}

// An event already queued when its handler is removed is not delivered to it.
func TestEvents_UnsubscribeCoversQueuedEvents(t *testing.T) {
	c := newTestClient(t)
	release := make(chan struct{})
	c.OnConnected(func() { <-release })
	called := make(chan TextMessage, 1)
	unsubscribe := c.OnTextMessage(func(m TextMessage) { called <- m })

	emit(c, &c.onConnected, struct{}{}) // holds the queue
	c.emitEvent(TextMessage{Message: "queued"})
	unsubscribe()
	close(release)
	settle(t, c)

	select {
	case <-called:
		t.Error("removed handler got an event queued before its removal")
	default:
	}
}

// A handler that waits on the client — here, for the next event — must not
// stall the code that produces events.
func TestEvents_ABlockedHandlerDoesNotBlockTheProducer(t *testing.T) {
	c := newTestClient(t)
	release := make(chan struct{})
	c.OnTextMessage(func(TextMessage) { <-release })
	defer close(release)

	done := make(chan struct{})
	go func() {
		for range 100 {
			c.emitEvent(TextMessage{})
		}
		close(done)
	}()
	receive(t, done)
}

func TestEvents_EachHandlerGetsItsOwnCopy(t *testing.T) {
	c := newTestClient(t)
	seen := make(chan []uint64, 2)
	c.OnTextMessage(func(m TextMessage) {
		m.InvokerGroups[0] = 99
		seen <- m.InvokerGroups
	})
	c.OnTextMessage(func(m TextMessage) { seen <- m.InvokerGroups })

	c.emitEvent(TextMessage{InvokerGroups: []uint64{1, 2}})

	receive(t, seen)
	if second := receive(t, seen); second[0] != 1 {
		t.Errorf("second handler saw %v; the first handler's change leaked", second)
	}
}

func TestCommandMiddleware_InterceptsCommands(t *testing.T) {
	intercepted := make(chan string, 1)
	c := newTestClient(t, WithCommandMiddleware(func(next func(string) error) func(string) error {
		return func(cmd string) error {
			intercepted <- cmd

			return next(cmd)
		}
	}))

	err := c.finalCmdHandler("test cmd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd := receive(t, intercepted); cmd != "test cmd" {
		t.Errorf("got %q, want test cmd", cmd)
	}
}

func TestCommandMiddleware_ChainOrder(t *testing.T) {
	var order []string
	c := newTestClient(t, WithCommandMiddleware(
		func(next func(string) error) func(string) error {
			return func(cmd string) error {
				order = append(order, "first")

				return next(cmd)
			}
		},
		func(next func(string) error) func(string) error {
			return func(cmd string) error {
				order = append(order, "second")

				return next(cmd)
			}
		},
	))

	_ = c.finalCmdHandler("x")

	if !slices.Equal(order, []string{"first", "second"}) {
		t.Errorf("middleware order = %v, want first, second", order)
	}
}

func TestCommandMiddleware_CanShortCircuit(t *testing.T) {
	reached := false
	c := newTestClient(t,
		WithCommandMiddleware(func(next func(string) error) func(string) error {
			return func(cmd string) error {
				if cmd == "blocked" {
					return nil // don't call next
				}

				return next(cmd)
			}
		}),
		WithCommandMiddleware(func(func(string) error) func(string) error {
			return func(string) error {
				reached = true

				return nil
			}
		}),
	)

	_ = c.ExecNoWait(context.Background(), "blocked")

	if reached {
		t.Error("short-circuited command reached the next middleware")
	}
}

func TestEventMiddleware_InterceptsEvents(t *testing.T) {
	intercepted := make(chan any, 1)
	c := newTestClient(t, WithEventMiddleware(func(next func(any)) func(any) {
		return func(evt any) {
			intercepted <- evt
			next(evt)
		}
	}))

	c.emitEvent(TextMessage{Message: "intercepted"})

	if m, ok := receive(t, intercepted).(TextMessage); !ok || m.Message != "intercepted" {
		t.Errorf("unexpected event: %v", m)
	}
}

func TestEventMiddleware_CanFilter(t *testing.T) {
	c := newTestClient(t, WithEventMiddleware(func(next func(any)) func(any) {
		return func(evt any) {
			if _, ok := evt.(TextMessage); ok {
				return // drop
			}
			next(evt)
		}
	}))
	reached := make(chan TextMessage, 1)
	c.OnTextMessage(func(m TextMessage) { reached <- m })

	c.emitEvent(TextMessage{Message: "filtered"})
	settle(t, c)

	select {
	case <-reached:
		t.Error("filtered event reached the handler")
	default:
	}
}

func TestEmitEvent_UnknownType_NoPanic(t *testing.T) {
	c := newTestClient(t)
	c.emitEvent(struct{ X int }{X: 42})
	settle(t, c)
}
