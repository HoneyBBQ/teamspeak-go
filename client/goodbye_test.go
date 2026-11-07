package client

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
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

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}

	return n
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
