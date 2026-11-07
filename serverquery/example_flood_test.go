package serverquery_test

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// The recipes below are the code behind docs/flood-control.md. The intervals
// are the ones measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0-beta13.1:
// a raw TCP or SSH session that sends no command for 300 seconds is closed, and
// one that sends a command every 200 seconds stays open.

// idleKeeper sends `version` on a session that has sent no command for a while.
// Notifications received do not count as activity to the server, so only the
// commands sent are noted.
type idleKeeper struct {
	lastSent time.Time
	mu       sync.Mutex
}

// middleware notes every line on its way out.
func (k *idleKeeper) middleware(next teamspeak.LineSender) teamspeak.LineSender {
	return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
		k.mu.Lock()
		k.lastSent = time.Now()
		k.mu.Unlock()

		return next(ctx, line)
	}
}

// run sends version whenever idle has passed since the last command, until ctx
// ends. A failed send is the connection dropping, which OnDisconnected reports.
func (k *idleKeeper) run(ctx context.Context, c *serverquery.Client, idle time.Duration) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		k.mu.Lock()
		wait := idle - time.Since(k.lastSent)
		k.mu.Unlock()
		if wait <= 0 {
			_, _ = c.Exec(ctx, "version")
			wait = idle
		}
		timer.Reset(wait)
	}
}

// Keep a raw TCP or SSH session open by sending `version` when no command has
// gone out for two minutes. WebQuery has no session to keep.
func ExampleWithLineMiddleware_keepAlive() { //nolint:testableexamples // needs a server, so it is compiled, not run
	ctx := context.Background()
	keeper := &idleKeeper{lastSent: time.Now()}
	c, err := serverquery.New(
		serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", os.Getenv("QUERY_PASSWORD")),
		serverquery.WithServer(1),
		serverquery.WithLineMiddleware(keeper.middleware),
	)
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()

	keepCtx, stop := context.WithCancel(ctx)
	defer stop()
	go keeper.run(keepCtx, c, 2*time.Minute)
}

// Name the notification categories to register: nothing is registered
// otherwise. Raw TCP and SSH accept server, channel, textserver, textchannel
// and textprivate; bans only where the server knows it (TeamSpeak 6); WebQuery
// accepts none and refuses WithEvents.
func ExampleWithEvents() { //nolint:testableexamples // needs a server, so it is compiled, not run
	c, err := serverquery.New(
		serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", os.Getenv("QUERY_PASSWORD")),
		serverquery.WithServer(1),
		serverquery.WithEvents(
			serverquery.CategoryServer,
			serverquery.CategoryChannel,
			serverquery.CategoryTextServer,
			serverquery.CategoryTextChannel,
			serverquery.CategoryTextPrivate,
		),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = c
}
