package client

import (
	"errors"
	"testing"
	"time"
)

func TestBackoffPolicy_DoublesUpToTheCeiling(t *testing.T) {
	p := BackoffPolicy{InitialDelay: time.Second, MaxDelay: 5 * time.Second, Factor: 2, Jitter: -1}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i, w := range want {
		if got := p.Delay(i + 1); got != w {
			t.Errorf("Delay(%d) = %v, want %v", i+1, got, w)
		}
	}
}

// A zero field used to mean the default everywhere except Jitter, where it
// meant none, so a zero policy retried a fleet in lockstep.
func TestBackoffPolicy_ZeroValueIsTheDefault(t *testing.T) {
	got := BackoffPolicy{}.withDefaults()
	if got != DefaultBackoffPolicy() {
		t.Errorf("zero policy = %+v, want the default %+v", got, DefaultBackoffPolicy())
	}
}

func TestBackoffPolicy_JitterStaysUnderTheCeiling(t *testing.T) {
	p := BackoffPolicy{InitialDelay: time.Second, MaxDelay: 4 * time.Second, Factor: 2, Jitter: 0.5}.withDefaults()

	if got := p.delay(10, func() float64 { return 1 }); got != 4*time.Second {
		t.Errorf("highest jitter at the ceiling = %v, want the ceiling", got)
	}
	if got := p.delay(1, func() float64 { return 0 }); got != 500*time.Millisecond {
		t.Errorf("lowest jitter on the first delay = %v, want 500ms", got)
	}
}

var errTestDrop = errors.New("test drop")

func withFastReconnect(c *Client, shouldRetry ShouldRetryFunc) {
	options := ReconnectOptions{
		ShouldRetry: shouldRetry,
		Backoff:     BackoffPolicy{InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, Jitter: -1},
	}.withDefaults()
	c.mu.Lock()
	c.reconnectOptions = &options
	c.mu.Unlock()
}

// A drop that arrives while a retry loop still holds the slot, after its
// handshake completed but before it let go, must be retried when the loop
// ends rather than lost.
func TestReconnectRetriesADropThatArrivedWhileALoopRan(t *testing.T) {
	c := newTestClient(t)
	asked := make(chan error, 1)
	withFastReconnect(c, func(err error, _ int) bool {
		asked <- err

		return false
	})
	c.mu.Lock()
	c.reconnecting = true // a loop that has just reconnected
	c.status = StatusDisconnected
	c.mu.Unlock()

	drop := errTestDrop
	c.scheduleReconnect(drop)
	select {
	case err := <-asked:
		t.Fatalf("a second loop ran alongside the first (asked about %v)", err)
	default:
	}

	c.endReconnect()
	select {
	case err := <-asked:
		if !errors.Is(err, drop) {
			t.Errorf("the restarted loop retried %v, want %v", err, drop)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drop that arrived while the loop ran was never retried")
	}
}

// The note is not acted on once the client is stopped or connected again.
func TestReconnectPendingDropIsDroppedWhenNoLongerNeeded(t *testing.T) {
	for name, set := range map[string]func(c *Client){
		"stopped":   func(c *Client) { c.stopped = true; c.status = StatusDisconnected },
		"connected": func(c *Client) { c.status = StatusConnected },
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t)
			asked := make(chan struct{}, 1)
			withFastReconnect(c, func(error, int) bool {
				asked <- struct{}{}

				return false
			})
			c.mu.Lock()
			c.reconnecting = true
			c.reconnectPending = true
			set(c)
			c.mu.Unlock()

			c.endReconnect()
			select {
			case <-asked:
				t.Fatal("a loop started for a drop that no longer needs retrying")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// A Disconnect that lands just before a reconnect attempt takes the lock must
// not be undone by it.
func TestReconnectAttemptRefusesAStoppedClient(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusDisconnected
	c.stopped = true
	c.mu.Unlock()

	err := c.runConnect()
	if !errors.Is(err, errStopped) {
		t.Fatalf("reconnect attempt after Disconnect = %v, want errStopped", err)
	}
	if got := c.Status(); got != StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}
}

// After the caller reconnected by hand, the loop has nothing to do; it must
// end rather than spin on ErrAlreadyConnected.
func TestReconnectLoopEndsWhenAlreadyConnected(t *testing.T) {
	c := newTestClient(t) // connected
	withFastReconnect(c, func(error, int) bool { return true })

	done := make(chan struct{})
	go func() {
		c.scheduleReconnect(errTestDrop)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reconnect loop kept retrying a client that is already connected")
	}
}
