//go:build integration

package client_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// A Disconnect with commands held in a line middleware still reaches the
// server: the same identity connects again at once, which a ghost session of
// the first would refuse with error 521 (too many clones). The held commands
// are rejected and never written.
func TestIntegration_DisconnectWithQueuedCommandsIsHeard(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	hold := &holdingLines{}
	first := newClient(t, id, addr, "teamspeak-go-lc",
		append(integrationClientOptions(nil), client.WithLineMiddleware(hold.middleware))...)
	t.Cleanup(func() { _ = first.Disconnect(context.Background()) })
	requireNoErr(t, paceConnect(t.Context()))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	requireNoErr(t, first.Connect(ctx))

	rejected := disconnectWithQueue(t, first, hold)
	if rejected == 0 {
		t.Error("no held command was rejected")
	}

	second := newClient(t, id, addr, "teamspeak-go-lc2", integrationClientOptions(nil)...)
	t.Cleanup(func() { _ = second.Disconnect(context.Background()) })
	requireNoErr(t, paceConnect(t.Context()))
	ctx2, cancel2 := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel2()
	requireNoErr(t, second.Connect(ctx2))
}

// holdingLines is a line middleware that holds every line until its context
// ends, then hands it on regardless, as a middleware that ignores its context
// would: the client must refuse to write it.
type holdingLines struct {
	holding atomic.Bool
	arrived atomic.Int32
}

func (h *holdingLines) middleware(next teamspeak.LineSender) teamspeak.LineSender {
	return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
		if !h.holding.Load() {
			return next(ctx, line)
		}
		h.arrived.Add(1)
		<-ctx.Done()

		return next(context.WithoutCancel(ctx), line)
	}
}

// disconnectWithQueue holds far more commands than a burst in h on c,
// disconnects it, and returns how many of the held ones were rejected with
// ErrNotConnected, failing the test for any other outcome. The goodbye is not
// held: Disconnect returns within its acknowledgement time.
func disconnectWithQueue(t *testing.T, c *client.Client, h *holdingLines) int {
	t.Helper()
	const queued = 16
	h.holding.Store(true)
	outcomes := make(chan error, queued)
	for range queued {
		go func() {
			_, err := c.Exec(t.Context(), "whoami")
			outcomes <- err
		}()
	}
	for h.arrived.Load() < queued {
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	requireNoErr(t, c.Disconnect(t.Context()))
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("Disconnect took %v, the goodbye was held or not answered", took)
	}
	rejected := 0
	for range queued {
		err := <-outcomes
		switch {
		case err == nil:
		case errors.Is(err, teamspeak.ErrNotConnected):
			rejected++
		default:
			t.Errorf("a held command ended with %v", err)
		}
	}

	return rejected
}
