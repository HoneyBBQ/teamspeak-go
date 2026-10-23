package client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// sentLines records every line the client sends from now on.
func sentLines(c *Client) func() []string {
	var mu sync.Mutex
	var lines []string
	c.wireHook = func(line string) error {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)

		return nil
	}

	return func() []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), lines...)
	}
}

// emptyThrottle leaves c with no token, so every command waits for its turn.
func emptyThrottle(c *Client) {
	c.throttle.mu.Lock()
	c.throttle.tokens = 0
	c.throttle.lastUpdate = time.Now()
	c.throttle.mu.Unlock()
}

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}

	return n
}

// The goodbye does not queue behind the commands waiting for the flood
// throttle, which would leave it unsent within its second; and what waits is
// rejected rather than sent after it.
func TestDisconnect_GoodbyePassesTheThrottleAndRejectsTheQueue(t *testing.T) {
	c := newTestClient(t)
	lines := sentLines(c)
	emptyThrottle(c)

	const waiting = 6
	errs := make(chan error, waiting*2)
	for range waiting {
		go func() { errs <- c.ExecNoWait(t.Context(), "clientupdate client_away=1") }()
		go func() {
			_, err := c.Exec(t.Context(), "whoami")
			errs <- err
		}()
	}
	time.Sleep(100 * time.Millisecond)

	_ = c.Disconnect(t.Context())

	for range waiting * 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, teamspeak.ErrNotConnected) {
				t.Errorf("a command that waited for its turn returned %v, want ErrNotConnected", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a command still waits for the throttle after Disconnect")
		}
	}
	got := lines()
	if countPrefix(got, "clientdisconnect") != 1 {
		t.Errorf("sent %q, want exactly one clientdisconnect", got)
	}
	if len(got) != 1 {
		t.Errorf("sent %q after the throttle emptied, want the goodbye only", got)
	}
}

// A client still connecting says goodbye once clientinit is out, since the
// server may already hold a session for it; before the keys exist it cannot.
func TestDisconnect_GoodbyeWhileConnecting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cryptoInit bool
		want       int
	}{
		{"after clientinit", true, 1},
		{"before the keys exist", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClientInit(t, tc.cryptoInit)
			lines := sentLines(c)
			c.mu.Lock()
			c.status = StatusConnecting
			c.mu.Unlock()

			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_ = c.Disconnect(ctx)

			if got := countPrefix(lines(), "clientdisconnect"); got != tc.want {
				t.Errorf("clientdisconnect sent %d times, want %d", got, tc.want)
			}
		})
	}
}

var errRejected = errors.New("rejected")

func TestCommandThrottle_RejectAll(t *testing.T) {
	th := newCommandThrottle()
	th.tokens = 0
	boom := errRejected
	errs := make(chan error, 3)
	for range 3 {
		go func() { errs <- th.wait(t.Context()) }()
	}
	time.Sleep(50 * time.Millisecond)
	th.rejectAll(boom)
	for range 3 {
		select {
		case err := <-errs:
			if !errors.Is(err, boom) {
				t.Errorf("wait = %v, want the rejection", err)
			}
		case <-time.After(time.Second):
			t.Fatal("a waiter was not rejected")
		}
	}
	// Later waiters line up as before.
	th.mu.Lock()
	th.tokens = 1
	th.mu.Unlock()
	err := th.wait(t.Context())
	if err != nil {
		t.Errorf("wait after rejectAll = %v", err)
	}
}
