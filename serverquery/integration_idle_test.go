//go:build integration && integration_idle

package serverquery_test

import (
	"context"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// The facts docs/flood-control.md gives for a ServerQuery session left idle,
// on every transport that has a session: the server closes one that sends no
// command for 300 seconds, a notification received does not count, and one that
// sends a command every 200 seconds stays open. Three sessions run at once, and
// the transports run side by side, so the test takes about as long as one: A
// is idle with events registered while C keeps a text message coming to it,
// and B sends `version` every 200 seconds.
//
// It takes over five minutes a transport, so it runs in a step of its own with
// its own timeout (the integration_idle tag).
func TestQuerySessionIdle_ClosesAtThreeHundredSecondsUnlessACommandIsSent(t *testing.T) {
	for name, dialer := range map[string]func(t *testing.T) (serverquery.Dialer, []serverquery.Option, account){
		"tcp": tcpDialer, "ssh": sshDialer,
	} {
		t.Run(name, func(t *testing.T) {
			// The transports run side by side: one takes over five minutes.
			t.Parallel()
			assertIdleSessions(t, dialer)
		})
	}
}

// idleWindow is when the server may close an idle session, and how long the
// test watches.
const (
	idleCloseEarliest = 290 * time.Second
	idleCloseLatest   = 330 * time.Second
	idleObserveFor    = 340 * time.Second
)

// connectIdle opens a query client on dialer's transport and server 1.
func connectIdle(t *testing.T, dialer func(t *testing.T) (serverquery.Dialer, []serverquery.Option, account),
	opts ...serverquery.Option,
) *serverquery.Client {
	t.Helper()
	d, base, _ := dialer(t)
	waitForOtherSuites()
	c, err := serverquery.New(d, append(append(base, serverquery.WithServer(1)), opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	return c
}

// sendEvery runs send every d until ctx ends, failing the test if it fails.
func sendEvery(ctx context.Context, t *testing.T, wg *sync.WaitGroup, d time.Duration, send func() error) {
	wg.Go(func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := send()
				if err != nil && ctx.Err() == nil {
					t.Errorf("a command of a session that should stay open failed: %v", err)

					return
				}
			}
		}
	})
}

func assertIdleSessions(t *testing.T, dialer func(t *testing.T) (serverquery.Dialer, []serverquery.Option, account)) {
	t.Helper()
	a := connectIdle(t, dialer, fiveEvents())
	b := connectIdle(t, dialer)
	c := connectIdle(t, dialer)
	start := time.Now()

	var (
		mu       sync.Mutex
		closedAt time.Duration
		heard    int
	)
	a.OnDisconnected(func(teamspeak.DisconnectedEvent) {
		mu.Lock()
		defer mu.Unlock()
		if closedAt == 0 {
			closedAt = time.Since(start)
		}
	})
	a.OnTextMessage(func(teamspeak.TextMessageEvent) {
		mu.Lock()
		heard++
		mu.Unlock()
	})

	// C and B only send; they run until the observation ends.
	ctx, cancel := context.WithTimeout(t.Context(), idleObserveFor)
	defer cancel()
	var wg sync.WaitGroup
	sendEvery(ctx, t, &wg, 60*time.Second, func() error { return c.SendServerMessage(ctx, "idle-test") })
	sendEvery(ctx, t, &wg, 200*time.Second, func() error {
		_, err := b.Exec(ctx, "version")

		return err
	})
	<-ctx.Done()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if closedAt < idleCloseEarliest || closedAt > idleCloseLatest {
		t.Errorf("the idle session was closed at %v, want between %v and %v (heard %d messages meanwhile)",
			closedAt, idleCloseEarliest, idleCloseLatest, heard)
	}
	if heard == 0 {
		t.Error("the idle session heard none of the messages, so the test did not show that notifications do not count")
	}
	if got := b.Status(); got != teamspeak.StatusConnected {
		t.Errorf("the session that sent a command every 200 s is %v, want connected", got)
	}
	if got := a.Status(); got == teamspeak.StatusConnected {
		t.Errorf("the idle session is still %v after %v", got, idleObserveFor)
	}
}
