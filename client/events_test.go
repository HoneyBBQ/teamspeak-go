package client

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	called := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { called <- m })

	c.emitEvent(TextMessageEvent{Message: "hi"})

	if m := receive(t, called); m.Message != "hi" {
		t.Errorf("got %q, want hi", m.Message)
	}
}

func TestOnClientLeave_RegistersHandler(t *testing.T) {
	c := newTestClient(t)
	called := make(chan ClientLeaveEvent, 1)
	c.OnClientLeave(func(e ClientLeaveEvent) { called <- e })

	c.emitEvent(ClientLeaveEvent{ClientID: 5})

	if e := receive(t, called); e.ClientID != 5 {
		t.Errorf("got ID %d, want 5", e.ClientID)
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
	c.OnTextMessage(func(TextMessageEvent) { a <- struct{}{} })
	c.OnTextMessage(func(TextMessageEvent) { b <- struct{}{} })

	c.emitEvent(TextMessageEvent{Message: "test"})

	receive(t, a)
	receive(t, b)
}

// Each handler used to run on a goroutine of its own, so a client that entered
// and left could be reported leaving first.
func TestEvents_ArriveInOrder(t *testing.T) {
	c := newTestClient(t)
	var mu sync.Mutex
	var got []teamspeak.ClientID
	c.OnClientEnter(func(info ClientEnterEvent) {
		mu.Lock()
		got = append(got, info.ID)
		mu.Unlock()
	})

	want := make([]teamspeak.ClientID, 0, 200)
	for i := range teamspeak.ClientID(200) {
		want = append(want, i)
		c.emitEvent(ClientEnterEvent{ClientInfo: teamspeak.ClientInfo{ID: i}})
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
	called := make(chan TextMessageEvent, 2)
	unsubscribe := c.OnTextMessage(func(m TextMessageEvent) { called <- m })

	c.emitEvent(TextMessageEvent{Message: "first"})
	receive(t, called)

	unsubscribe()
	unsubscribe() // a second call is harmless
	c.emitEvent(TextMessageEvent{Message: "second"})
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
	called := make(chan TextMessageEvent, 1)
	unsubscribe := c.OnTextMessage(func(m TextMessageEvent) { called <- m })

	emit(c, c.epoch.Load(), &c.onConnected, "Connected", struct{}{}) // holds the queue
	c.emitEvent(TextMessageEvent{Message: "queued"})
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
	c.OnTextMessage(func(TextMessageEvent) { <-release })
	defer close(release)

	done := make(chan struct{})
	go func() {
		for range 100 {
			c.emitEvent(TextMessageEvent{})
		}
		close(done)
	}()
	receive(t, done)
}

func TestEvents_EachHandlerGetsItsOwnCopy(t *testing.T) {
	c := newTestClient(t)
	seen := make(chan []teamspeak.ServerGroupID, 2)
	c.OnTextMessage(func(m TextMessageEvent) {
		m.InvokerGroups[0] = 99
		seen <- m.InvokerGroups
	})
	c.OnTextMessage(func(m TextMessageEvent) { seen <- m.InvokerGroups })

	c.emitEvent(TextMessageEvent{InvokerGroups: []teamspeak.ServerGroupID{1, 2}})

	receive(t, seen)
	if second := receive(t, seen); second[0] != 1 {
		t.Errorf("second handler saw %v; the first handler's change leaked", second)
	}
}

func TestCommandMiddleware_SeesTypedCommands(t *testing.T) {
	seen := make(chan string, 1)
	var sawDeadline bool
	c := newTestClient(t, WithCommandMiddleware(func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			seen <- req.Command()
			_, sawDeadline = ctx.Deadline()

			return next.Send(ctx, req)
		})
	}))
	c.wireHook = func(string) error { return errCaptured }

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := c.ListChannels(ctx)
	if !errors.Is(err, errCaptured) {
		t.Fatalf("ListChannels = %v, want the wire hook's error", err)
	}
	if got := receive(t, seen); got != "channellist" {
		t.Errorf("middleware saw %q, want channellist", got)
	}
	if !sawDeadline {
		t.Error("middleware did not see the caller's context")
	}
}

func TestCommandMiddleware_ChainOrder(t *testing.T) {
	var order []string
	record := func(name string) CommandMiddleware {
		return func(next teamspeak.Executor) teamspeak.Executor {
			return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
				order = append(order, name)

				return next.Send(ctx, req)
			})
		}
	}
	c := newTestClient(t, WithCommandMiddleware(record("first"), record("second")))
	c.wireHook = func(string) error { return errCaptured }

	_, _ = c.ListChannels(t.Context())

	if !slices.Equal(order, []string{"first", "second"}) {
		t.Errorf("middleware order = %v, want first, second", order)
	}
}

// A middleware can answer a command itself: the caller gets its rows at once,
// and nothing reaches the wire.
func TestCommandMiddleware_CanAnswerACommand(t *testing.T) {
	c := newTestClient(t, WithCommandMiddleware(func(teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(context.Context, teamspeak.Request) ([]map[string]string, error) {
			return []map[string]string{{"cid": "7", "channel_name": "Cached"}}, nil
		})
	}))
	c.wireHook = func(string) error {
		t.Error("an answered command reached the wire")

		return errCaptured
	}

	start := time.Now()
	channels, err := c.ListChannels(t.Context())
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) != 1 || channels[0].Name != "Cached" {
		t.Errorf("channels = %+v, want the middleware's answer", channels)
	}
	if time.Since(start) > time.Second {
		t.Error("an answered command waited for the server")
	}
}

// Raw lines do not pass through the typed middleware.
func TestCommandMiddleware_DoesNotSeeRawLines(t *testing.T) {
	c := newTestClient(t, WithCommandMiddleware(func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			t.Errorf("middleware saw raw %q", req.Command())

			return next.Send(ctx, req)
		})
	}))
	c.wireHook = func(string) error { return errCaptured }

	_ = c.ExecNoWait(t.Context(), "clientupdate")
}

func TestEventMiddleware_InterceptsEvents(t *testing.T) {
	intercepted := make(chan Event, 1)
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(evt Event) {
			intercepted <- evt
			next(evt)
		}
	}))

	c.emitEvent(TextMessageEvent{Message: "intercepted"})

	if m, ok := receive(t, intercepted).(TextMessageEvent); !ok || m.Message != "intercepted" {
		t.Errorf("unexpected event: %v", m)
	}
}

func TestEventMiddleware_CanFilter(t *testing.T) {
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(evt Event) {
			if _, ok := evt.(TextMessageEvent); ok {
				return // drop
			}
			next(evt)
		}
	}))
	reached := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { reached <- m })

	c.emitEvent(TextMessageEvent{Message: "filtered"})
	settle(t, c)

	select {
	case <-reached:
		t.Error("filtered event reached the handler")
	default:
	}
}

func TestEventMiddleware_CanReplace(t *testing.T) {
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(evt Event) {
			if m, ok := evt.(TextMessageEvent); ok {
				m.Message = strings.ToUpper(m.Message)
				evt = m
			}
			next(evt)
		}
	}))
	reached := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { reached <- m })

	c.emitEvent(TextMessageEvent{Message: "quiet"})

	if m := receive(t, reached); m.Message != "QUIET" {
		t.Errorf("handler got %q, want the middleware's replacement", m.Message)
	}
}

// Middleware runs outermost first, and each sees what the one before passed.
func TestEventMiddleware_RunsInOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	tag := func(name string) EventMiddleware {
		return func(next func(Event)) func(Event) {
			return func(evt Event) {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				next(evt)
			}
		}
	}
	c := newTestClient(t, WithEventMiddleware(tag("outer"), tag("inner")))

	c.emitEvent(PokeEvent{})
	settle(t, c)

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"outer", "inner"}) {
		t.Errorf("middleware ran %v, want [outer inner]", order)
	}
}

// Lifecycle events report the connection itself; a middleware that dropped one
// would leave the application wrong about its own state.
func TestEventMiddleware_DoesNotSeeLifecycleEvents(t *testing.T) {
	seen := make(chan Event, 4)
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(evt Event) {
			seen <- evt
			next(evt)
		}
	}))
	connected := make(chan struct{}, 1)
	c.OnConnected(func() { connected <- struct{}{} })

	emit(c, c.epoch.Load(), &c.onConnected, "Connected", struct{}{})
	receive(t, connected)

	select {
	case evt := <-seen:
		t.Errorf("middleware saw %T", evt)
	default:
	}
}

// Every notification reaches OnNotification as it arrived, after the typed
// event it produced.
func TestOnNotification_FollowsTheTypedEvent(t *testing.T) {
	c := newTestClient(t)
	var mu sync.Mutex
	var order []string
	c.OnTextMessage(func(TextMessageEvent) {
		mu.Lock()
		order = append(order, "typed")
		mu.Unlock()
	})
	raw := make(chan NotificationEvent, 2)
	c.OnNotification(func(n NotificationEvent) {
		mu.Lock()
		order = append(order, "raw")
		mu.Unlock()
		raw <- n
	})

	c.handleCommandLines(c.handler, `notifytextmessage targetmode=3 msg=hello\sthere invokerid=7`)
	c.handleCommandLines(c.handler, "notifysomethingnew a=1")

	first := receive(t, raw)
	if first.Name != "notifytextmessage" || first.Params["msg"] != "hello there" {
		t.Errorf("raw = %+v, want the text message, unescaped", first)
	}
	if second := receive(t, raw); second.Name != "notifysomethingnew" || second.Params["a"] != "1" {
		t.Errorf("raw = %+v, want the unmodelled notification", second)
	}

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"typed", "raw", "raw"}) {
		t.Errorf("delivered %v, want the typed event first", order)
	}
}

// A batched notification is one NotificationEvent per row.
func TestOnNotification_SplitsRows(t *testing.T) {
	c := newTestClient(t)
	raw := make(chan NotificationEvent, 2)
	c.OnNotification(func(n NotificationEvent) { raw <- n })

	c.handleCommandLines(c.handler, "notifychanneledited cid=1 reasonid=10|cid=2")

	if n := receive(t, raw); n.Params["cid"] != "1" {
		t.Errorf("row 0 = %v", n.Params)
	}
	if n := receive(t, raw); n.Params["cid"] != "2" || n.Params["reasonid"] != "10" {
		t.Errorf("row 1 = %v, want the inherited reasonid", n.Params)
	}
}

// One handler editing its params must not change what the next one sees.
func TestOnNotification_CopiesParamsPerHandler(t *testing.T) {
	c := newTestClient(t)
	c.OnNotification(func(n NotificationEvent) { n.Params["a"] = "changed" })
	got := make(chan string, 1)
	c.OnNotification(func(n NotificationEvent) { got <- n.Params["a"] })

	c.handleCommandLines(c.handler, "notifysomething a=1")

	if v := receive(t, got); v != "1" {
		t.Errorf("second handler saw a=%q, want 1", v)
	}
}

// Raw notifications pass through event middleware like every server event.
func TestOnNotification_PassesThroughMiddleware(t *testing.T) {
	seen := make(chan NotificationEvent, 1)
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(evt Event) {
			if n, ok := evt.(NotificationEvent); ok {
				seen <- n
			}
			next(evt)
		}
	}))

	c.handleCommandLines(c.handler, "notifysomething a=1")

	if n := receive(t, seen); n.Name != "notifysomething" {
		t.Errorf("middleware saw %+v", n)
	}
}

// Nobody listening, no middleware: nothing to build.
func TestOnNotification_NotBuiltWithoutAnyone(t *testing.T) {
	c := newTestClient(t)
	c.handleCommandLines(c.handler, "notifysomething a=1")

	c.events.mu.Lock()
	queued := len(c.events.pending) + boolToInt(c.events.running)
	c.events.mu.Unlock()
	if queued != 0 {
		t.Errorf("%d deliveries queued with nobody to receive them", queued)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// A handler changing the groups it was given cannot edit the client list.
func TestOnClientEnter_GroupsAreTheEventsOwn(t *testing.T) {
	c := newTestClient(t)
	c.OnClientEnter(func(e ClientEnterEvent) { e.ServerGroups[0] = 99 })

	c.handleCommandLines(c.handler, "notifycliententerview clid=5 client_nickname=a client_servergroups=6,7")
	settle(t, c)

	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.clients[5].ServerGroups; !slices.Equal(got, []teamspeak.ServerGroupID{6, 7}) {
		t.Errorf("client list groups = %v, want [6 7]", got)
	}
}

// Voice is dropped once the queue is backed up; other events are not.
func TestEventQueueDropsVoiceWhenBackedUp(t *testing.T) {
	var q eventQueue
	release := make(chan struct{})
	q.push(func() { <-release })
	var delivered atomic.Int32
	for range maxQueuedForVoice + 50 {
		q.pushVoice(func() { delivered.Add(1) }, slog.New(slog.DiscardHandler))
	}
	ordinary := make(chan struct{})
	q.push(func() { close(ordinary) })
	close(release)

	select {
	case <-ordinary:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary event not delivered")
	}
	if got := delivered.Load(); got > maxQueuedForVoice+1 || got < maxQueuedForVoice {
		t.Errorf("delivered %d voice events, want about %d", got, maxQueuedForVoice)
	}
}

// A handler that panics must not crash the process or stop delivery: the
// handlers after it, and the events after that one, still arrive, and the
// panic is logged at Error with the event type.
func TestHandlerPanicIsLoggedAndDeliveryContinues(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	c := newTestClient(t, WithLogger(logger))

	got := make(chan string, 4)
	defer c.OnPoked(func(PokeEvent) { panic("boom") })()
	defer c.OnPoked(func(e PokeEvent) { got <- e.Message })()
	defer c.OnDisconnected(func(error) { panic("lifecycle boom") })()
	defer c.OnConnected(func() { got <- "connected" })()

	c.emitEvent(PokeEvent{Message: "first"})
	c.emitEvent(PokeEvent{Message: "second"})
	emit(c, c.epoch.Load(), &c.onDisconnected, "Disconnected", error(nil))
	emit(c, c.epoch.Load(), &c.onConnected, "Connected", struct{}{})

	for _, want := range []string{"first", "second", "connected"} {
		if v := receive(t, got); v != want {
			t.Fatalf("delivered %q, want %q", v, want)
		}
	}
	out := logs.String()
	wants := []string{"level=ERROR", "event handler panicked", "event=PokeEvent", "boom", "event=Disconnected"}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

// A panicking event middleware is recovered the same way.
func TestMiddlewarePanicIsRecovered(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	panicking := func(next func(Event)) func(Event) {
		return func(evt Event) {
			if p, ok := evt.(PokeEvent); ok && p.Message == "bad" {
				panic("middleware boom")
			}
			next(evt)
		}
	}
	c := newTestClient(t, WithLogger(logger), WithEventMiddleware(panicking))
	got := make(chan string, 2)
	defer c.OnPoked(func(e PokeEvent) { got <- e.Message })()

	c.emitEvent(PokeEvent{Message: "bad"})
	c.emitEvent(PokeEvent{Message: "good"})

	if v := receive(t, got); v != "good" {
		t.Fatalf("delivered %q, want %q", v, "good")
	}
	if !strings.Contains(logs.String(), "middleware boom") {
		t.Errorf("the middleware panic was not logged:\n%s", logs.String())
	}
}

type syncBuffer struct {
	buf strings.Builder
	mu  sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
