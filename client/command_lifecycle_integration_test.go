//go:build integration

package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// A Disconnect with commands waiting in the flood throttle still reaches the
// server: the same identity connects again at once, which a ghost session of
// the first would refuse with error 521 (too many clones).
func TestIntegration_DisconnectWithQueuedCommandsIsHeard(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	first := newClient(t, id, addr, "teamspeak-go-lc", integrationClientOptions(nil)...)
	t.Cleanup(func() { _ = first.Disconnect(context.Background()) })
	requireNoErr(t, paceConnect(t.Context()))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	requireNoErr(t, first.Connect(ctx))

	rejected := disconnectWithQueue(t, first)
	if rejected == 0 {
		t.Error("no queued command was rejected")
	}

	second := newClient(t, id, addr, "teamspeak-go-lc2", integrationClientOptions(nil)...)
	t.Cleanup(func() { _ = second.Disconnect(context.Background()) })
	requireNoErr(t, paceConnect(t.Context()))
	ctx2, cancel2 := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel2()
	requireNoErr(t, second.Connect(ctx2))
}

// disconnectWithQueue queues far more commands than the throttle's burst on c,
// disconnects it, and returns how many of the queued ones were rejected with
// ErrNotConnected, failing the test for any other outcome.
func disconnectWithQueue(t *testing.T, c *client.Client) int {
	t.Helper()
	const queued = 16
	outcomes := make(chan error, queued)
	for range queued {
		go func() {
			_, err := c.Exec(t.Context(), "whoami")
			outcomes <- err
		}()
	}
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	requireNoErr(t, c.Disconnect(t.Context()))
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("Disconnect took %v, the goodbye was not answered", took)
	}
	rejected := 0
	for range queued {
		err := <-outcomes
		switch {
		case err == nil:
		case errors.Is(err, teamspeak.ErrNotConnected):
			rejected++
		default:
			t.Errorf("a queued command ended with %v", err)
		}
	}

	return rejected
}
