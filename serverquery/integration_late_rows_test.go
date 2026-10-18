//go:build integration

package serverquery_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// TestQueryLateRows_CreateKeepsItsRowAndTheNextCommandNeverGetsIt creates
// channels back to back, each followed at once by another command, while two
// other sessions create and delete channels. TeamSpeak 6 over SSH writes a
// create's row after its error line when other sessions are busy: before this
// was handled, a good share of the creates below lost their id, and about as
// many handed a stray row to the command after them. Idle, it is rare, so the
// load is part of the test. Whatever the ordering, every create has its own id
// and the command after it is given no row that is not its own.
func TestQueryLateRows_CreateKeepsItsRowAndTheNextCommandNeverGetsIt(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport == "web" {
			t.Skip("WebQuery answers each command whole, so there is no ordering to test")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		defer cancel()
		stamp := uniqueStamp()

		stop := make(chan struct{})
		var loads sync.WaitGroup
		for k := range 2 {
			d, opts, _ := dialerFor(t, transport)
			other, err := serverquery.New(d, append(opts, serverquery.WithServer(1))...)
			if err != nil {
				t.Fatalf("New (load): %v", err)
			}
			open(t, other)
			loads.Go(func() { churnChannels(ctx, other, stop, fmt.Sprintf("%s-%d", stamp, k)) })
		}
		defer func() {
			close(stop)
			loads.Wait()
		}()

		missing := 0
		for i := range 150 {
			if !createThenAsk(ctx, t, c, fmt.Sprintf("late-%s-%d", stamp, i)) {
				missing++
			}
			time.Sleep(60 * time.Millisecond)
		}
		if missing != 0 {
			t.Errorf("%d creates over %s were answered without their id", missing, transport)
		}
	})
}

// churnChannels creates and deletes channels until stop is closed, to keep the
// server busy for the session under test.
func churnChannels(ctx context.Context, c *serverquery.Client, stop <-chan struct{}, tag string) {
	for n := 0; ; n++ {
		select {
		case <-stop:
			return
		default:
		}
		made, err := c.Exec(ctx, fmt.Sprintf("channelcreate channel_name=churn-%s-%d", tag, n))
		if err == nil && len(made) > 0 && made[0]["cid"] != "" {
			_, _ = c.Exec(ctx, "channeldelete cid="+made[0]["cid"]+" force=1")
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// createThenAsk creates a channel and asks whoami straight after, failing the
// test when whoami is given a row that is not its own. It deletes the channel
// and reports whether the create's answer carried its id.
func createThenAsk(ctx context.Context, t *testing.T, c *serverquery.Client, name string) bool {
	t.Helper()
	made, err := c.Exec(ctx, "channelcreate channel_name="+name)
	if err != nil {
		t.Fatalf("channelcreate: %v", err)
	}
	next, err := c.Exec(ctx, "whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if len(next) != 1 || next[0]["cid"] != "" {
		t.Fatalf("whoami after the create of %s = %v, want its own single row", name, next)
	}
	if len(made) == 0 || made[0]["cid"] == "" {
		return false
	}
	_, err = c.Exec(ctx, "channeldelete cid="+made[0]["cid"]+" force=1")
	if err != nil {
		t.Fatalf("channeldelete: %v", err)
	}

	return true
}

// dialerFor is the dialer of the named transport.
func dialerFor(t *testing.T, transport string) (serverquery.Dialer, []serverquery.Option, account) {
	t.Helper()
	if transport == "tcp" {
		return tcpDialer(t)
	}

	return sshDialer(t)
}
