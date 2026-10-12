package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
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
