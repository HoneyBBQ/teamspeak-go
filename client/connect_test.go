package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

type fixedResolver string

func (r fixedResolver) Resolve(context.Context, string) ([]ResolvedAddr, error) {
	return []ResolvedAddr{{Addr: string(r), Source: "test"}}, nil
}

// silentServerClient returns a client pointed at a UDP socket that never
// answers, so its handshake never completes.
func silentServerClient(t *testing.T) *Client {
	t.Helper()
	silent, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })

	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c := mustNew(t, id, "TestBot", WithResolver(fixedResolver(silent.LocalAddr().String())))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	return c
}

func TestConnect_AbandonsTheAttemptWhenCtxIsDone(t *testing.T) {
	c := silentServerClient(t)

	err := c.Connect(ctxWithin(t, 100*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect = %v, want context.DeadlineExceeded", err)
	}
	if c.Status() != StatusDisconnected {
		t.Errorf("status = %v, want StatusDisconnected", c.Status())
	}

	// Abandoned, not stuck: the client can try again.
	err = c.Connect(ctxWithin(t, 50*time.Millisecond))
	if errors.Is(err, ErrAlreadyConnected) {
		t.Errorf("second Connect = %v; the first attempt was left in place", err)
	}
}

func TestConnect_ReturnsWhenDisconnectIsCalled(t *testing.T) {
	c := silentServerClient(t)

	result := make(chan error, 1)
	go func() { result <- c.Connect(context.Background()) }()

	deadline := time.Now().Add(time.Second)
	for c.Status() != StatusConnecting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("Connect = %v, want teamspeak.ErrNotConnected", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect still waiting after Disconnect; without a deadline it would wait forever")
	}
}

func TestConnect_RefusesASecondConnect(t *testing.T) {
	c := silentServerClient(t)
	go func() { _ = c.Connect(context.Background()) }()

	deadline := time.Now().Add(time.Second)
	for c.Status() != StatusConnecting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	err := c.Connect(context.Background())
	if !errors.Is(err, ErrAlreadyConnected) {
		t.Errorf("Connect while connecting = %v, want ErrAlreadyConnected", err)
	}
}

// The goodbye waits a second at most, even when the caller's context would
// allow much longer: a server that does not answer it costs no more.
func TestDisconnect_GoodbyeWaitsASecondAtMost(t *testing.T) {
	c := newTestClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_ = c.Disconnect(ctx)
	if took := time.Since(start); took > 1500*time.Millisecond || took < 900*time.Millisecond {
		t.Errorf("Disconnect took %v, want about a second", took)
	}
}

// stuckResolver records the deadline it is given and then ignores its
// context, as a careless custom resolver might.
type stuckResolver struct {
	deadline chan time.Time
	release  chan struct{}
}

func (r stuckResolver) Resolve(ctx context.Context, _ string) ([]ResolvedAddr, error) {
	d, _ := ctx.Deadline()
	r.deadline <- d
	<-r.release

	return nil, nil
}

// A custom resolver gets the resolution budget as its context's deadline, and
// is not waited for past the caller's context even if it ignores its own.
func TestConnect_BoundsACustomResolver(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	r := stuckResolver{deadline: make(chan time.Time, 1), release: make(chan struct{})}
	defer close(r.release)
	c := mustNew(t, id, "TestBot", WithResolver(r))

	// No deadline of the caller's, so the resolver's is the budget's own.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	err = c.Connect(ctx)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Connect took %v with a resolver that never answers", took)
	}
	if err == nil {
		t.Fatal("Connect succeeded")
	}
	deadline := <-r.deadline
	want := start.Add(resolveTimeout)
	if deadline.Before(want.Add(-time.Second)) || deadline.After(want.Add(time.Second)) {
		t.Errorf("resolver deadline = %v, want within %v of the start", deadline, resolveTimeout)
	}
}

// leavingClient returns a connected client whose goodbye goes unanswered, so a
// Disconnect on it says goodbye for a full second, and whose next Connect
// dials a server that never answers.
func leavingClient(t *testing.T) *Client {
	t.Helper()
	silent, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	c := newTestClient(t, WithResolver(fixedResolver(silent.LocalAddr().String())))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	return c
}

// waitLeaving waits until a Disconnect on c has begun its goodbye.
func waitLeaving(t *testing.T, c *Client) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		c.mu.Lock()
		l := c.leaving
		c.mu.Unlock()
		if l != nil {
			return
		}
	}
	t.Fatal("Disconnect did not start saying goodbye")
}

// A Connect while a Disconnect says goodbye waits for it: the new session
// starts only once the old one is closed and its end announced.
func TestConnect_WaitsForADisconnectSayingGoodbye(t *testing.T) {
	c := leavingClient(t)
	disconnected := make(chan time.Time, 1)
	go func() {
		_ = c.Disconnect(context.Background())
		disconnected <- time.Now()
	}()
	waitLeaving(t, c)

	connecting := make(chan time.Time, 1)
	go func() {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			for c.Status() != StatusConnecting {
				time.Sleep(time.Millisecond)
			}
			connecting <- time.Now()
			cancel()
		}()
		_ = c.Connect(ctx)
	}()

	left := <-disconnected
	select {
	case started := <-connecting:
		if started.Before(left) {
			t.Errorf("the new attempt started %v before Disconnect returned", left.Sub(started))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Connect never started after the Disconnect")
	}
}

// A second Disconnect joins the first and returns when it does; a Disconnect
// while a Connect waits for the first makes that Connect fail.
func TestDisconnect_JoinsTheOneSayingGoodbye(t *testing.T) {
	c := leavingClient(t)
	go func() { _ = c.Disconnect(context.Background()) }()
	waitLeaving(t, c)

	connectErr := make(chan error, 1)
	go func() { connectErr <- c.Connect(t.Context()) }()
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	_ = c.Disconnect(context.Background())
	if took := time.Since(start); took < 500*time.Millisecond {
		t.Errorf("the second Disconnect returned after %v, before the first had finished", took)
	}
	select {
	case err := <-connectErr:
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("Connect = %v, want ErrNotConnected", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Connect did not return")
	}
	if got := c.Status(); got != StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}
}

// eventLog records the lifecycle and text events a client's handlers see, in
// the order they see them.
type eventLog struct {
	seen []string
	mu   sync.Mutex
}

func (l *eventLog) add(name string) {
	l.mu.Lock()
	l.seen = append(l.seen, name)
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.seen)
}

// commandPacket is a decrypted command packet carrying line.
func commandPacket(line string) *transport.Packet {
	return &transport.Packet{TypeFlagged: byte(transport.PacketTypeCommand), Data: []byte(line)}
}

// completeHandshake finishes the attempt the current handler runs, as the
// server's initserver would.
func completeHandshake(t *testing.T, c *Client) *transport.PacketHandler {
	t.Helper()
	h := c.currentHandler()
	completeCryptoInit(t, h)
	c.cmdTrack.signalWelcomeComplete()
	c.handleCommand(h, "initserver aclid=9 virtualserver_version=3.13.7\\s[Build:\\s1655727713]")

	return h
}

// Disconnect then Connect back to back: Connect does not wait for the
// handlers, yet they see the old session's disconnected strictly before the
// new session's connected, and nothing of the old session after it.
func TestDisconnectThenConnect_HandlersSeeTheOldSessionEndFirst(t *testing.T) {
	c := leavingClient(t)
	var log eventLog
	releaseHandler := make(chan struct{})
	c.OnDisconnected(func(e DisconnectedEvent) {
		<-releaseHandler // a slow handler holds the queue
		log.add(fmt.Sprintf("disconnected(%v)", e.Err))
	})
	c.OnConnected(func(ConnectedEvent) { log.add("connected") })
	c.OnTextMessage(func(m TextMessageEvent) { log.add("text " + m.Message) })
	old := c.currentHandler()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	_ = c.Disconnect(ctx)
	cancel()
	connected := make(chan error, 1)
	go func() { connected <- c.Connect(t.Context()) }()
	for deadline := time.Now().Add(2 * time.Second); c.Status() != StatusConnecting; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Connect did not start while the disconnected handler was still running")
		}
	}
	h := completeHandshake(t, c)
	err := <-connected
	if err != nil {
		t.Fatalf("Connect = %v", err)
	}
	c.handlePacket(old, commandPacket("notifytextmessage targetmode=1 msg=old invokerid=5"))
	c.handlePacket(h, commandPacket("notifytextmessage targetmode=1 msg=new invokerid=5"))
	close(releaseHandler)
	// Events are delivered in order: once this marker has run, so has
	// everything queued before it, and nothing of the old session is left.
	waitDelivered(t, c)

	want := []string{"disconnected(<nil>)", "connected", "text new"}
	if got := log.snapshot(); !slices.Equal(got, want) {
		t.Errorf("handlers saw %q, want %q", got, want)
	}
}

// A handler may call Disconnect and Connect, from OnDisconnected and from
// OnConnected: neither waits for the handlers, so neither deadlocks.
func TestLifecycleCallsFromAHandlerDoNotDeadlock(t *testing.T) {
	c := leavingClient(t)
	fromConnected := make(chan error, 1)
	fromDisconnected := make(chan error, 1)
	var once sync.Once
	c.OnConnected(func(ConnectedEvent) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = c.Disconnect(ctx)
		select {
		case fromConnected <- c.Connect(ctx):
		default:
		}
	})
	c.OnDisconnected(func(DisconnectedEvent) {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_ = c.Disconnect(ctx)
			fromDisconnected <- c.Connect(ctx)
		})
	})

	markConnecting(c)
	completeHandshake(t, c)
	for name, ch := range map[string]chan error{"OnConnected": fromConnected, "OnDisconnected": fromDisconnected} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("Disconnect and Connect from %s deadlocked", name)
		}
	}
}

// An address that cannot be one fails Connect with ErrInvalidAddress before
// anything starts: no socket, no attempt, no disconnected event, no retry.
func TestConnect_RefusesAnInvalidAddress(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for _, addr := range []string{
		"127.0.0.1:70000", "127.0.0.1:0", "[::1]:99999", "  ", "bad host:9987", "127.0.0.1:abc", ":9987",
		"a:b:c", "host/path",
	} {
		var c *Client
		c, err = New(id, addr, "TestBot", WithResolver(fixedResolver("127.0.0.1:9")))
		if err != nil {
			t.Fatalf("New(%q): %v", addr, err)
		}
		heard := make(chan error, 1)
		c.OnDisconnected(func(e DisconnectedEvent) { heard <- e.Err })

		err = c.Connect(t.Context())
		if !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("Connect(%q) = %v, want ErrInvalidAddress", addr, err)
		}
		if DefaultShouldRetry(err, 1) {
			t.Errorf("DefaultShouldRetry(%q's error) = true", addr)
		}
		if got := c.Status(); got != StatusDisconnected {
			t.Errorf("%q: status = %v", addr, got)
		}
		select {
		case e := <-heard:
			t.Errorf("%q: disconnected announced (%v)", addr, e)
		case <-time.After(10 * time.Millisecond):
		}
	}
	for _, addr := range []string{"127.0.0.1", "[::1]:9987", "::1", "fe80::1%en0", "ts.example.com:1", "nickname"} {
		err = validateAddress(addr)
		if err != nil {
			t.Errorf("validateAddress(%q) = %v", addr, err)
		}
	}
}

// A resolver's answer is held to the same rule.
func TestConnect_RefusesAnInvalidResolvedAddress(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c := mustNew(t, id, "TestBot", WithResolver(fixedResolver("127.0.0.1:0")))
	err = c.Connect(t.Context())
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Connect = %v, want ErrInvalidAddress", err)
	}
	if got := c.Status(); got != StatusDisconnected {
		t.Errorf("status = %v", got)
	}
}
