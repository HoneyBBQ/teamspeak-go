# Flood control

The SDK never paces your commands, never sends one again, and never keeps a
ServerQuery session alive. How fast to send, what to do about a refusal and
whether to hold a session open are yours to decide, and the package gives you
the places to do it: a line middleware, and the server's own statement of how
long to wait. This page says what the server enforces and how it behaves, and
gives recipes to copy. The recipes are code you own: their values are a
starting point, not a measured optimum.

## What the SDK does

- Every command line the client sends passes your line middleware
  (`client.WithLineMiddleware`, `serverquery.WithLineMiddleware`): typed
  commands, raw `Exec` and `ExecNoWait`, and the commands the SDK sends on its
  own, such as the answer to a connection info request on the voice protocol or
  the login, `use` and `version` of a ServerQuery connection.
- Two kinds of line do not: the voice handshake's own lines (`clientinitiv`,
  `clientek`, `clientinit`), which are sent before a session exists, and the
  goodbye (`clientdisconnect` of `Disconnect`, `quit` of a closing ServerQuery
  client). The goodbye must leave at once, or the server keeps a session for a
  client that has gone and refuses the next connection as a clone (error 521).
- A command the server refuses for flooding returns error 524, as any server
  error. `teamspeak.FloodWait(err)` reads the wait the server named in it
  (`retry in 1985ms` on the voice protocol, `please wait 2 seconds` on
  ServerQuery) and reports false for any other error.
- The command's deadline starts when the call starts and bounds the middleware's
  waits too. The context a middleware receives is also cancelled when the client
  disconnects, and a line handed on after that is not written: the call returns
  `teamspeak.ErrNotConnected`.
- Calling `next` more than once sends the line more than once, each time under a
  return code of its own: that is how a middleware resends.
- On ServerQuery the chain runs inside the serial queue's turn, so a middleware
  that waits holds every later command, in order. On the voice protocol there is
  no queue: concurrent calls run their chains concurrently.

With no middleware a line goes out at once.

```go
c, err := client.New(id, "ts.example.com", "bot",
	client.WithLineMiddleware(pacer.pace()))
```

## The voice protocol's antiflood

The server counts points per client: each command adds its cost, and
`virtualserver_antiflood_points_tick_reduce` points come off every tick. These
settings are the server's:

- `virtualserver_antiflood_points_tick_reduce`: points removed from a client's
  count every tick.
- `virtualserver_antiflood_points_needed_command_block`: the count at which the
  server stops running a client's commands.
- `virtualserver_antiflood_points_needed_ip_block`: anti-flood points needed to
  block incoming connections from the client, in the words of the server's own
  `serveredit` help.
- `virtualserver_antiflood_points_needed_plugin_block`: the count at which the
  server stops running a client's plugin commands.

`servergetvariables` reads them, which a fresh guest identity may do, and it
costs 0 points (measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0-beta13.1).
They are not in `initserver`.

Measured on both servers, with the limit set to 200 and then 600 points and a
fresh client sending one command until refused: `servergetvariables` costs 0,
`permget` 5, `channellist` 5, `clientupdate client_away=0` 15 and a channel
`sendtextmessage` 15. Past the command block the server answers 524 with
`retry in Nms` and does not run the command. The live test is
`TestIntegration_VoiceAntifloodCostsAndThresholds`.

Someone else keeps a fuller list, per command:
[yat.qa](https://yat.qa/ressourcen/voice-client-anti-flood/) (a tick is half a
second there). It is theirs, not ours, and not measured by this module.

On a server you run, the complete fix is the permission `b_client_ignore_antiflood`
("Ignore antiflood measurements"): grant it to the group your bot is in, and
the points are not counted.

## ServerQuery's flood limit

A ServerQuery session may send `serverinstance_serverquery_flood_commands`
commands per `serverinstance_serverquery_flood_time` before the server refuses
the next one with error 524 and `please wait N seconds`. Both are readable with
`instanceinfo`, which `serveradmin` may run and a guest may not (error 2568).
`teamspeak.FloodWait` reads the N.

## Recipes

Copy these and change them. They are compiled by `go vet` and `go test` as the
examples of the `client` and `serverquery` packages.

### Token bucket

The SDK's former built-in limiter: four commands a second after a burst of
eight, starting with five tokens, with a pause that holds every line.

```go
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
			if err := b.take(ctx, 1); err != nil {
				return nil, err
			}

			return next(ctx, line)
		}
	}
}

// A token bucket in front of every line: four a second after a burst of eight.
func ExampleWithLineMiddleware_tokenBucket() {
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
```

### Resend on 524

Wait twice the wait the server named, at most three times, within the command's
context, and have the bucket hold every other line meanwhile. Put it outside the
bucket's middleware, so the resend waits on the bucket too.

```go
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

// Send a refused line again after the wait the server named, with the bucket
// holding every other line meanwhile. FloodWait reads the wait from the error.
func ExampleWithLineMiddleware_resendOnFlood() {
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
```

### A bucket weighted by cost

Charge each command what it costs, and read the rate and the burst from the
server's own settings with `servergetvariables`: tick_reduce points a second,
and a burst of 80% of command_block. A tick is taken as a second here, which
was not measured here; the third-party list below says half a second, so one
second errs on the slow side. A command not in the table is charged 15, the
dearest measured here; some cost more on the third-party list. Until the limits
are read the bucket starts at 5 points a second with a burst of 50.

```go
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
			if err := b.take(ctx, cost); err != nil {
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
func ExampleWithLineMiddleware_costWeighted() {
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
		log.Fatal(err)
	}
	reduce, _ := strconv.ParseFloat(rows[0][prop.VirtualServerAntiFloodPointsTickReduce], 64)
	block, _ := strconv.ParseFloat(rows[0][prop.VirtualServerAntiFloodPointsNeededCommandBlock], 64)
	pacer.mu.Lock()
	pacer.rate = reduce
	pacer.burst = block * 0.8
	pacer.mu.Unlock()
	fmt.Println("points a second:", reduce, "burst:", block*0.8)
}
```

### Keep a ServerQuery session open

Measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0-beta13.1: a raw TCP or SSH
session that sends no command for 300 seconds is closed, and one that sends a
command every 200 seconds stays open. Notifications received do not count.
WebQuery has no session. The live test is
`TestQuerySessionIdle_ClosesAtThreeHundredSecondsUnlessACommandIsSent`.

```go
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
func ExampleWithLineMiddleware_keepAlive() {
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
func ExampleWithEvents() {
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
```

### ServerQuery events

Nothing is registered unless you name the categories. Raw TCP and SSH accept
`server`, `channel`, `textserver`, `textchannel` and `textprivate`; `bans` only
where the server knows it (TeamSpeak 6, not TeamSpeak 3, which refuses it with
1539); WebQuery accepts none, and `WithEvents` over it is refused with
`ErrInvalidConfig`.

```go
// Name the notification categories to register: nothing is registered
// otherwise. Raw TCP and SSH accept server, channel, textserver, textchannel
// and textprivate; bans only where the server knows it (TeamSpeak 6); WebQuery
// accepts none and refuses WithEvents.
func ExampleWithEvents() {
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
```
