package client_test

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/prop"
)

// The recipes below are the code behind docs/flood-control.md. The values are a
// starting point, not a measured optimum: they are what the client's former
// built-in limiter used.

// bucket is a token bucket that every line waits on, with a pause that holds
// them all. Lines are not released in arrival order.
type bucket struct {
	last   time.Time
	paused time.Time
	tokens float64
	rate   float64
	burst  float64
	mu     sync.Mutex
}

// newBucket returns a bucket that lets burst lines through, then rate a
// second, starting with initial tokens.
func newBucket(rate, burst, initial float64) *bucket {
	return &bucket{tokens: initial, rate: rate, burst: burst, last: time.Now()}
}

// pause holds every line for d.
func (b *bucket) pause(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if until := time.Now().Add(d); until.After(b.paused) {
		b.paused = until
	}
	b.tokens = 0
	b.last = b.paused
}

// take waits until the line costs tokens, or ctx ends.
func (b *bucket) take(ctx context.Context, cost float64) error {
	for {
		b.mu.Lock()
		now := time.Now()
		var wait time.Duration
		if now.Before(b.paused) {
			wait = b.paused.Sub(now)
		} else {
			b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*b.rate, b.burst)
			b.last = now
			if b.tokens >= cost {
				b.tokens -= cost
				b.mu.Unlock()

				return nil
			}
			wait = time.Duration((cost - b.tokens) / b.rate * float64(time.Second))
		}
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// pace is a line middleware that spends one token per line.
func (b *bucket) pace() client.LineMiddleware {
	return func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			err := b.take(ctx, 1)
			if err != nil {
				return nil, err
			}

			return next(ctx, line)
		}
	}
}

// resendOnFlood is a line middleware that sends a line again, up to three
// times, after twice the wait the server named for error 524, and tells b to
// hold every other line meanwhile. Put it outside the bucket's own middleware,
// so the resend waits on it too.
func resendOnFlood(b *bucket) client.LineMiddleware {
	return func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			for attempt := 0; ; attempt++ {
				rows, err := next(ctx, line)
				wait, flooded := teamspeak.FloodWait(err)
				if !flooded || attempt == 3 {
					return rows, err
				}
				b.pause(2 * wait)
			}
		}
	}
}

// A token bucket in front of every line: four a second after a burst of eight.
func ExampleWithLineMiddleware_tokenBucket() { //nolint:testableexamples // needs a server, so it is compiled, not run
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	pacer := newBucket(4, 8, 5)
	c, err := client.New(id, "ts.example.com", "bot", client.WithLineMiddleware(pacer.pace()))
	if err != nil {
		log.Fatal(err)
	}
	_ = c
}

// Send a refused line again after the wait the server named, with the bucket
// holding every other line meanwhile. FloodWait reads the wait from the error.
func ExampleWithLineMiddleware_resendOnFlood() { //nolint:testableexamples // needs a server, so it is compiled, not run
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	pacer := newBucket(4, 8, 5)
	c, err := client.New(id, "ts.example.com", "bot",
		client.WithLineMiddleware(resendOnFlood(pacer), pacer.pace()))
	if err != nil {
		log.Fatal(err)
	}
	_ = c
}

// costs are the antiflood points a command cost on TeamSpeak 3 3.13.8 and
// TeamSpeak 6 6.0.0-beta13.1, as measured by the live test. A command not
// listed is charged 15, the dearest measured here; some cost more on the
// third-party list that docs/flood-control.md links.
var costs = map[string]float64{
	"servergetvariables": 0,
	"permget":            5,
	"channellist":        5,
	"clientupdate":       15,
	"sendtextmessage":    15,
}

// weighted is a line middleware that charges a command its antiflood cost.
func (b *bucket) weighted() client.LineMiddleware {
	return func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			cost, known := costs[line.Name]
			if !known {
				cost = 15
			}
			err := b.take(ctx, cost)
			if err != nil {
				return nil, err
			}

			return next(ctx, line)
		}
	}
}

// A bucket in antiflood points, its rate and burst read from the server's own
// settings with servergetvariables, which costs nothing and a guest may run.
// The server takes tick_reduce points off a client's count every tick. A tick
// is taken as a second here, so the rate is tick_reduce points a second: that
// was not measured here, a third-party list says half a second, and one second
// errs on the slow side. The burst is 80% of command_block.
func ExampleWithLineMiddleware_costWeighted() { //nolint:testableexamples // needs a server, so it is compiled, not run
	ctx := context.Background()
	id, err := identity.Generate(ctx, 8)
	if err != nil {
		log.Fatal(err)
	}
	// Until the limits are read: 5 points a second, with a burst of 50.
	pacer := newBucket(5, 50, 50)
	c, err := client.New(id, "ts.example.com", "bot", client.WithLineMiddleware(pacer.weighted()))
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()

	rows, err := c.Exec(ctx, "servergetvariables")
	if err != nil || len(rows) == 0 {
		log.Print(err)

		return
	}
	reduce, _ := strconv.ParseFloat(rows[0][prop.VirtualServerAntiFloodPointsTickReduce], 64)
	block, _ := strconv.ParseFloat(rows[0][prop.VirtualServerAntiFloodPointsNeededCommandBlock], 64)
	pacer.mu.Lock()
	pacer.rate = reduce
	pacer.burst = block * 0.8
	pacer.mu.Unlock()
	fmt.Println("points a second:", reduce, "burst:", block*0.8)
}
