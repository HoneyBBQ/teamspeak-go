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
