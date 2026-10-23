package client

import (
	"errors"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/identity"
)

var errTestDrop = errors.New("test drop")

func withFastReconnect(c *Client, shouldRetry ShouldRetryFunc) {
	options := ReconnectOptions{
		ShouldRetry: shouldRetry,
		Backoff:     BackoffPolicy{InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, Jitter: -1},
	}
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
	c.scheduleReconnect(drop, nil)
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

	err := c.runConnect(1)
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
		c.scheduleReconnect(errTestDrop, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reconnect loop kept retrying a client that is already connected")
	}
}

func TestRetryVerdict_WillReconnect(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(c *Client)
		attempt int
		want    bool
	}{
		"policy accepts":  {func(c *Client) { withFastReconnect(c, func(error, int) bool { return true }) }, 1, true},
		"policy declines": {func(c *Client) { withFastReconnect(c, func(error, int) bool { return false }) }, 1, false},
		"reconnect off":   {func(*Client) {}, 1, false},
		"stopped": {func(c *Client) {
			withFastReconnect(c, func(error, int) bool { return true })
			c.mu.Lock()
			c.stopped = true
			c.mu.Unlock()
		}, 1, false},
		"attempts used up": {func(c *Client) {
			withFastReconnect(c, func(error, int) bool { return true })
			c.mu.Lock()
			c.reconnectOptions.Backoff.MaxAttempts = 2
			c.mu.Unlock()
		}, 3, false},
		"last attempt left": {func(c *Client) {
			withFastReconnect(c, func(error, int) bool { return true })
			c.mu.Lock()
			c.reconnectOptions.Backoff.MaxAttempts = 2
			c.mu.Unlock()
		}, 2, true},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t)
			tc.setup(c)
			c.mu.Lock()
			v := c.newVerdictLocked(errTestDrop, tc.attempt)
			c.mu.Unlock()

			if got := v.willReconnect(); got != tc.want {
				t.Errorf("willReconnect = %v, want %v", got, tc.want)
			}
		})
	}
}

// The loop and the event both ask, and the caller's ShouldRetry hears the
// failure once.
func TestRetryVerdict_AsksThePolicyOnce(t *testing.T) {
	c := newTestClient(t)
	var asked int
	withFastReconnect(c, func(error, int) bool {
		asked++

		return true
	})
	c.mu.Lock()
	v := c.newVerdictLocked(errTestDrop, 1)
	c.mu.Unlock()

	v.willReconnect()
	v.policy()
	v.willReconnect()
	if asked != 1 {
		t.Errorf("ShouldRetry asked %d times, want 1", asked)
	}
}

func TestDisconnectedEvent_AFailedConnectWillNotReconnect(t *testing.T) {
	c := newTestClient(t)
	withFastReconnect(c, func(error, int) bool { return true })
	markConnecting(c)
	heard := make(chan DisconnectedEvent, 1)
	c.OnDisconnected(func(e DisconnectedEvent) { heard <- e })

	c.failConnection(c.handler, errTestDrop)

	if e := receive(t, heard); !errors.Is(e.Err, errTestDrop) || e.WillReconnect {
		t.Errorf("event = %+v, want the cause and no reconnect for a failed Connect", e)
	}
}

func TestDisconnectedEvent_AFailedReconnectAttemptWillReconnectWhenThePolicyAllows(t *testing.T) {
	for _, accept := range []bool{true, false} {
		c := newTestClient(t)
		withFastReconnect(c, func(error, int) bool { return accept })
		markConnecting(c)
		c.mu.Lock()
		c.attempt.reconnect = true
		c.mu.Unlock()
		heard := make(chan DisconnectedEvent, 1)
		c.OnDisconnected(func(e DisconnectedEvent) { heard <- e })

		c.failConnection(c.handler, errTestDrop)

		if e := receive(t, heard); e.WillReconnect != accept {
			t.Errorf("policy accepts %v: WillReconnect = %v", accept, e.WillReconnect)
		}
	}
}

// A backoff that would retry in a tight loop is refused up front.
func TestNew_RefusesABackoffThatCannotWork(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(id, unitTestServerAddr, "Bot", WithReconnect(ReconnectOptions{
		Backoff: BackoffPolicy{InitialDelay: time.Second, MaxDelay: time.Millisecond},
	}))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with a ceiling below the first delay = %v, want ErrInvalidConfig", err)
	}
	_, err = New(id, unitTestServerAddr, "Bot", WithReconnect(ReconnectOptions{}))
	if err != nil {
		t.Errorf("New with the zero policy = %v, want it accepted", err)
	}
}
