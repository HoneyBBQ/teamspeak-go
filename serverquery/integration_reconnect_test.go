//go:build integration

package serverquery_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// rewritingConn changes the `use sid=1` a reconnect writes into a `use` of a
// server that is not there.
type rewritingConn struct {
	net.Conn

	rewrite bool
}

func (c rewritingConn) Write(p []byte) (int, error) {
	if c.rewrite && bytes.HasPrefix(p, []byte("use ")) {
		_, err := c.Conn.Write([]byte("use sid=999\n"))

		return len(p), err
	}

	return c.Conn.Write(p)
}

// TestQueryReconnect_GivesUpAtAServerThatIsGone connects, drops the connection,
// and has every later `use` name a virtual server that is not running, which
// TeamSpeak 3 3.13.8 answers with 1033, "server is not running". A reconnect
// loop used to try again until its attempts ran out (or, unbounded, for ever),
// every try a login and a use that count towards the server's flood ban. It now
// stops at the first refusal and reports the server's own error.
func TestQueryReconnect_GivesUpAtAServerThatIsGone(t *testing.T) {
	addr, name, password := tcpVars(t)
	waitForOtherSuites()

	var dials atomic.Int32
	var mu sync.Mutex
	var first net.Conn
	dialer := serverquery.TCPLoginWith(addr, name, password, serverquery.TCPOptions{
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			n := dials.Add(1)
			if n == 1 {
				mu.Lock()
				first = conn
				mu.Unlock()
			}

			return rewritingConn{Conn: conn, rewrite: n > 1}, nil
		},
	})
	c, err := serverquery.New(dialer, serverquery.WithServer(1), serverquery.WithoutEvents(),
		serverquery.WithReconnect(teamspeak.ReconnectOptions{Backoff: teamspeak.BackoffPolicy{
			InitialDelay: 200 * time.Millisecond, MaxDelay: 300 * time.Millisecond, Jitter: -1, MaxAttempts: 6,
		}}))
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan teamspeak.DisconnectedEvent, 16)
	c.OnDisconnected(func(e teamspeak.DisconnectedEvent) { events <- e })
	open(t, c)

	mu.Lock()
	_ = first.Close()
	mu.Unlock()

	// The first event is the drop itself; the loop's own verdict is the one
	// that says it will not try again.
	var last teamspeak.DisconnectedEvent
	deadline := time.After(20 * time.Second)
	for {
		select {
		case last = <-events:
		case <-deadline:
			t.Fatalf("the reconnect loop did not stop; %d dials so far, last event %+v", dials.Load(), last)
		}
		if !last.WillReconnect {
			break
		}
	}
	// A loop that did not stop would dial again within the delay.
	time.Sleep(time.Second)
	if got := dials.Load(); got != 2 {
		t.Errorf("dials = %d, want 2: the first connection and one reconnect attempt", got)
	}
	if !errors.Is(last.Err, errcode.ServerIsNotRunning) {
		t.Errorf("the loop ended with %v, want the server's 1033", last.Err)
	}
}
