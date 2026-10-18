package client

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func mustIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	return id
}

// stalledAt connects to a server that never answers, lets drive bring the
// attempt to a step of the handshake, and ends the attempt with ctx. It returns
// Connect's error.
func stalledAt(
	t *testing.T, cancelWith func() (context.Context, context.CancelFunc),
	drive func(c *Client, h *transport.PacketHandler),
) error {
	t.Helper()
	c := silentServerClient(t)
	ctx, cancel := cancelWith()
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.Connect(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		opened := c.attempt.opened
		h := c.handler
		c.mu.Unlock()
		if opened {
			drive(c, h)

			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the attempt never opened")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	return <-result
}

func manualCancel(t *testing.T) func() (context.Context, context.CancelFunc) {
	t.Helper()

	return func() (context.Context, context.CancelFunc) { return context.WithCancel(t.Context()) }
}

func puzzleData() []byte {
	data := make([]byte, 1+64+64+4+100)
	data[0] = 0x03
	data[64] = 2
	data[128] = 17
	data[132] = 1

	return data
}

func TestConnect_NamesTheStepACancelledAttemptWaitedIn(t *testing.T) {
	beta := base64.StdEncoding.EncodeToString(make([]byte, 54))
	cases := []struct {
		name  string
		drive func(c *Client, h *transport.PacketHandler)
		want  string
	}{
		{"first init1 answer", func(*Client, *transport.PacketHandler) {},
			"the server's first answer to init1"},
		{"init1 step", func(c *Client, h *transport.PacketHandler) {
			c.answerInit1(h, make([]byte, 21))
		}, "the server's init1 step after step 0"},
		{"puzzle being solved", func(c *Client, h *transport.PacketHandler) {
			c.setStage(h, stagePuzzleSolve, -1)
		}, "the RSA puzzle to be solved"},
		{"answer to the puzzle", func(c *Client, h *transport.PacketHandler) {
			c.answerInit1(h, puzzleData())
		}, "the server's answer to the RSA puzzle"},
		{"answer to clientek", func(c *Client, h *transport.PacketHandler) {
			_, err := c.sendClientEkPacket(h, beta)
			if err != nil {
				t.Errorf("sendClientEkPacket: %v", err)
			}
			completeCryptoInit(t, h)
			c.traceHandshakeDone(h, "")
		}, "the server's answer to clientek"},
		{"answer to clientinit", func(c *Client, h *transport.PacketHandler) {
			completeCryptoInit(t, h)
			c.traceHandshakeDone(h, "")
		}, "the server's answer to clientinit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := stalledAt(t, manualCancel(t), tc.drive)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Connect = %v, want context.Canceled", err)
			}
			if !strings.Contains(err.Error(), "while waiting for "+tc.want) {
				t.Errorf("Connect = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

func TestConnect_NamesTheStepADeadlineEndedIn(t *testing.T) {
	c := silentServerClient(t)
	err := c.Connect(ctxWithin(t, 100*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "while waiting for the server's first answer to init1") {
		t.Errorf("Connect = %q, want the first init1 answer named", err)
	}
}

// A caller's context that ends while the address resolves or the socket opens
// leaves the attempt waiting for the connection: resolution gives up with the
// context, and falls back to the address as given.
func TestConnect_NamesTheConnectionThatNeverOpened(t *testing.T) {
	r := stuckResolver{deadline: make(chan time.Time, 1), release: make(chan struct{})}
	defer close(r.release)
	c := mustNew(t, mustIdentity(t), "TestBot", WithResolver(r))
	defer func() { _ = c.Disconnect(context.Background()) }()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := c.Connect(ctx)
	if !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(err.Error(), "while waiting for the connection to open") {
		t.Errorf("Connect = %v, want the deadline, naming the connection", err)
	}
}

func TestConnectAttempt_WaitingBeforeTheSocketOpens(t *testing.T) {
	a := newConnectAttempt()
	a.begin(1, false)
	if got := a.waiting(false); got != "the connection to open" {
		t.Errorf("before the socket opens: %q", got)
	}
}
