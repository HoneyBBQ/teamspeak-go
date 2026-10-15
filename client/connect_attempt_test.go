package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var errStaleSocketClosed = errors.New("old socket closed")

// connectingClient returns a client in the state Connect leaves it in while
// the handshake is in flight.
func connectingClient(t *testing.T) *Client {
	t.Helper()
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusConnecting
	c.mu.Unlock()

	return c
}

// reconnect does what Connect does before the handshake starts: reset the
// session and bring up a fresh, started handler.
func reconnect(t *testing.T, c *Client) {
	t.Helper()
	c.mu.Lock()
	c.resetForConnectLocked()
	c.status = StatusConnecting
	h := c.handler
	c.mu.Unlock()
	err := h.Start(newTestConn())
	if err != nil {
		t.Fatalf("handler.Start: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
}

func waitWithin(t *testing.T, c *Client, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	return c.waitConnected(ctx)
}

func TestWaitConnected_ReturnsServerErrorInsteadOfTimingOut(t *testing.T) {
	c := connectingClient(t)
	disconnected := make(chan error, 1)
	c.OnDisconnected(func(e DisconnectedEvent) { disconnected <- e.Err })

	c.handleCommand(c.handler, `error id=1028 msg=invalid\sserver\spassword`)

	err := waitWithin(t, c, time.Second)
	if err == nil || errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(err.Error(), "invalid server password") {
		t.Fatalf("WaitConnected = %v, want the server's invalid server password error", err)
	}

	c.mu.Lock()
	status := c.status
	c.mu.Unlock()
	if status != StatusDisconnected {
		t.Errorf("status = %v, want StatusDisconnected", status)
	}

	select {
	case got := <-disconnected:
		if got == nil || !strings.Contains(got.Error(), "invalid server password") {
			t.Errorf("disconnected handler got %v, want the server error", got)
		}
	case <-time.After(time.Second):
		t.Error("disconnected handler was not called after the handshake failed")
	}
}

func TestWaitConnected_LaterWaitersSeeTheSameFailure(t *testing.T) {
	c := connectingClient(t)
	c.handleCommand(c.handler, `error id=1028 msg=invalid\sserver\spassword`)

	err := waitWithin(t, c, time.Second)
	if err == nil || !strings.Contains(err.Error(), "invalid server password") {
		t.Errorf("WaitConnected after the failure = %v, want the recorded server error", err)
	}
}

func TestWaitConnected_ErrorAfterConnectDoesNotDisconnect(t *testing.T) {
	c := connectingClient(t)
	c.handleCommand(c.handler, "initserver aclid=3 virtualserver_name=X")

	// An ordinary command failure on a live session.
	c.handleCommand(c.handler, `error id=768 msg=invalid\schannelID return_code=99`)

	c.mu.Lock()
	status := c.status
	c.mu.Unlock()
	if status != StatusConnected {
		t.Errorf("status = %v after a command error on a live session, want StatusConnected", status)
	}
	err := waitWithin(t, c, time.Second)
	if err != nil {
		t.Errorf("WaitConnected = %v, want nil", err)
	}
}

func TestWaitConnected_CalledBeforeConnectIsReleasedByTheHandshake(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	before := c.attempt
	c.mu.Unlock()
	result := make(chan error, 1)
	go func() { result <- waitWithin(t, c, 2*time.Second) }()

	reconnect(t, c)
	// The attempt nobody has resolved is kept, so a waiter that grabbed it
	// before the reconnect, or after, is released by this handshake.
	if c.attempt != before {
		t.Fatal("reconnect replaced an unresolved attempt")
	}
	completeCryptoInit(t, c.handler)
	c.handleCommand(c.handler, "initserver aclid=3 virtualserver_name=X")

	err := <-result
	if err != nil {
		t.Errorf("WaitConnected started before Connect = %v, want nil", err)
	}
}

func TestReconnectStartsAFreshAttemptAfterAFailure(t *testing.T) {
	c := connectingClient(t)
	c.handleCommand(c.handler, `error id=1028 msg=invalid\sserver\spassword`)

	reconnect(t, c)

	// The previous failure must not leak into the new attempt.
	err := waitWithin(t, c, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("WaitConnected on a fresh attempt = %v, want it to keep waiting", err)
	}
}

func TestCloseFromAReplacedHandlerIsIgnored(t *testing.T) {
	c := connectingClient(t)
	c.mu.Lock()
	stale := c.handler
	c.mu.Unlock()
	reconnect(t, c)

	// The old handler's receive loop reports its close after the new attempt began.
	stale.OnClosed(errStaleSocketClosed)

	c.mu.Lock()
	status := c.status
	c.mu.Unlock()
	if status != StatusConnecting {
		t.Errorf("status = %v after a stale close, want StatusConnecting", status)
	}
}

// A server error the previous connection's handler delivers after a new
// Connect began belongs to that old connection; it must not fail the new
// attempt, nor a ban from it disconnect the new one.
func TestErrorFromAReplacedHandlerIsIgnored(t *testing.T) {
	for name, line := range map[string]string{
		"refusal": `error id=1028 msg=invalid\sserver\spassword`,
		"ban":     `error id=3329 msg=connection\sfailed,\syou\sare\sbanned`,
	} {
		t.Run(name, func(t *testing.T) {
			c := connectingClient(t)
			c.mu.Lock()
			stale := c.handler
			c.mu.Unlock()
			reconnect(t, c)

			c.handleCommand(stale, line)
			c.background.Wait() // a ban disconnects from a goroutine

			if got := c.Status(); got != StatusConnecting {
				t.Errorf("status = %v after a stale %s, want StatusConnecting", got, name)
			}
			err := waitWithin(t, c, 50*time.Millisecond)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("WaitConnected after a stale %s = %v, want it to keep waiting", name, err)
			}
		})
	}
}

// A ban noticed on a connection that a new Connect then replaced must not
// disconnect the new one.
func TestBanDisconnectSparesAReplacingConnection(t *testing.T) {
	c := connectingClient(t)
	stale := c.currentHandler()
	reconnect(t, c)

	c.disconnectBanned(stale)

	if got := c.Status(); got != StatusConnecting {
		t.Errorf("status = %v, want the new attempt left alone", got)
	}
}
