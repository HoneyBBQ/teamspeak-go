package client

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
)

// traceRecorder collects what a ConnectTrace reports, in order.
type traceRecorder struct {
	resolveStart       []ResolveStartInfo
	resolveDone        []ResolveDoneInfo
	connectStart       []ConnectStartInfo
	handshakeDone      []HandshakeDoneInfo
	sessionStart       []SessionStartInfo
	welcomeDone        []WelcomeDoneInfo
	attemptFailed      []AttemptFailedInfo
	reconnectScheduled []ReconnectScheduledInfo
	order              []string
	mu                 sync.Mutex
}

func (r *traceRecorder) note(name string) { r.order = append(r.order, name) }

func (r *traceRecorder) trace() *ConnectTrace {
	return &ConnectTrace{
		ResolveStart: func(i ResolveStartInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ResolveStart")
			r.resolveStart = append(r.resolveStart, i)
		},
		ResolveDone: func(i ResolveDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ResolveDone")
			r.resolveDone = append(r.resolveDone, i)
		},
		ConnectStart: func(i ConnectStartInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ConnectStart")
			r.connectStart = append(r.connectStart, i)
		},
		HandshakeDone: func(i HandshakeDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("HandshakeDone")
			r.handshakeDone = append(r.handshakeDone, i)
		},
		SessionStart: func(i SessionStartInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("SessionStart")
			r.sessionStart = append(r.sessionStart, i)
		},
		WelcomeDone: func(i WelcomeDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("WelcomeDone")
			r.welcomeDone = append(r.welcomeDone, i)
		},
		AttemptFailed: func(i AttemptFailedInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("AttemptFailed")
			r.attemptFailed = append(r.attemptFailed, i)
		},
		ReconnectScheduled: func(i ReconnectScheduledInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ReconnectScheduled")
			r.reconnectScheduled = append(r.reconnectScheduled, i)
		},
	}
}

func (r *traceRecorder) sequence() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.order)
}

func (r *traceRecorder) count(name string) int {
	n := 0
	for _, s := range r.sequence() {
		if s == name {
			n++
		}
	}

	return n
}

// traceClient is a client that connects to a socket that never answers, so a
// test plays the server by feeding the handshake to the client itself.
func traceClient(t *testing.T, options ...Option) *Client {
	t.Helper()
	silent, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	options = append([]Option{WithResolver(fixedResolver(silent.LocalAddr().String()))}, options...)
	c := mustNew(t, id, "TestBot", options...)
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	return c
}

// startConnect runs Connect in the background and returns once the socket is
// open and the handshake is under way.
func startConnect(ctx context.Context, t *testing.T, c *Client) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- c.Connect(ctx) }()
	waitUntil(t, "the handshake to begin", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.attempt.opened
	})

	return result
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return")

		return nil
	}
}

// serverKeyExchange feeds the client the legacy key exchange, which derives
// the shared secret.
func serverKeyExchange(c *Client) {
	h := c.currentHandler()
	omega := h.TsCrypt.Identity.PublicKey()
	c.handleCommand(h, "clientinitiv alpha=AAAAAAAAAAAAAA== beta=AAAAAAAAAAAAAA== omega="+omega)
}

func serverInitServer(c *Client) {
	c.handleCommand(c.currentHandler(), "initserver aclid=7 virtualserver_name=Test virtualserver_version=3.13.7")
}

func serverWelcomeDone(c *Client) {
	c.handleCommand(c.currentHandler(), "channellistfinished")
}

// connectThrough runs a whole successful attempt and returns Connect's result.
func connectThrough(t *testing.T, c *Client) error {
	t.Helper()
	result := startConnect(t.Context(), t, c)
	serverKeyExchange(c)
	serverInitServer(c)
	err := waitResult(t, result)
	serverWelcomeDone(c)

	return err
}

func TestTrace_SuccessfulConnectCallsEveryHookInOrder(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithConnectTrace(rec.trace()))
	var sawBeforeReturn bool
	c.trace.SessionStart = func(i SessionStartInfo) {
		rec.trace().SessionStart(i)
		sawBeforeReturn = c.attempt.finished() // no lock needed: only this goroutine closes it, after the hook
	}

	err := connectThrough(t, c)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	want := []string{"ResolveStart", "ResolveDone", "ConnectStart", "HandshakeDone", "SessionStart", "WelcomeDone"}
	if got := rec.sequence(); !slices.Equal(got, want) {
		t.Fatalf("hooks = %v, want %v", got, want)
	}
	if sawBeforeReturn {
		t.Error("SessionStart ran after Connect was released")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.sessionStart[0].ClientID; got != c.ClientID() || got != 7 {
		t.Errorf("SessionStart.ClientID = %d, ClientID() = %d, want 7", got, c.ClientID())
	}
	if rec.sessionStart[0].Capabilities.Version == "" {
		t.Error("SessionStart.Capabilities is empty")
	}
	rs, rd := rec.resolveStart[0], rec.resolveDone[0]
	if rs.Attempt != 1 || rs.Reconnect || rs.Addr != "127.0.0.1:9987" {
		t.Errorf("ResolveStart = %+v", rs)
	}
	if rd.Source != "test" || rd.Err != nil || rd.Target != rec.connectStart[0].Target || rd.Addr != rs.Addr {
		t.Errorf("ResolveDone = %+v, ConnectStart = %+v", rd, rec.connectStart[0])
	}
	if rec.handshakeDone[0].Duration <= 0 || rec.sessionStart[0].Duration < rec.handshakeDone[0].Duration ||
		rec.welcomeDone[0].Duration < rec.sessionStart[0].Duration {
		t.Errorf("durations do not grow: %v %v %v",
			rec.handshakeDone[0].Duration, rec.sessionStart[0].Duration, rec.welcomeDone[0].Duration)
	}
}

func TestTrace_WelcomeDoneIsOncePerAttemptAndOnlyAfterSessionStart(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithConnectTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	serverKeyExchange(c)
	serverWelcomeDone(c) // before initserver
	serverInitServer(c)
	_ = waitResult(t, result)
	serverWelcomeDone(c)
	serverWelcomeDone(c)

	if got := rec.count("WelcomeDone"); got != 1 {
		t.Errorf("WelcomeDone called %d times, want 1 (sequence %v)", got, rec.sequence())
	}
}

// Each way an attempt can end without a session is reported once, with the
// phase it was in, and never as a session.
//
//nolint:funlen // a table of cases
func TestTrace_EveryFailureIsOneAttemptFailedWithItsPhase(t *testing.T) {
	cases := []struct {
		drive func(t *testing.T, c *Client, result <-chan error)
		want  error
		name  string
		phase ConnectPhase
	}{
		{
			name:  "server error before the key exchange",
			phase: ConnectPhaseHandshake,
			drive: func(_ *testing.T, c *Client, _ <-chan error) {
				c.handleCommand(c.currentHandler(), "error id=1024 msg=nope")
			},
		},
		{
			name:  "handshake step that cannot go on",
			phase: ConnectPhaseHandshake,
			want:  ErrHandshake,
			drive: func(_ *testing.T, c *Client, _ <-chan error) {
				h := c.currentHandler()
				h.TsCrypt.AlphaTmp = make([]byte, 10)
				c.handleCommand(h, "initivexpand2 l=AQ== beta=AAAA omega=AAAA proof=AAAA")
			},
		},
		{
			name:  "transport closed during the handshake",
			phase: ConnectPhaseHandshake,
			want:  errClosedDuringHandshake,
			drive: func(t *testing.T, c *Client, _ <-chan error) {
				t.Helper()
				_ = c.DropConnectionForTest()
			},
		},
		{
			name:  "server refusal after the key exchange",
			phase: ConnectPhaseJoin,
			drive: func(_ *testing.T, c *Client, _ <-chan error) {
				serverKeyExchange(c)
				c.handleCommand(c.currentHandler(), "error id=1028 msg=invalid\\sserver\\spassword")
			},
		},
		{
			name:  "Disconnect during the handshake",
			phase: ConnectPhaseHandshake,
			want:  teamspeak.ErrNotConnected,
			drive: func(t *testing.T, c *Client, _ <-chan error) {
				t.Helper()
				_ = c.Disconnect(t.Context())
			},
		},
		{
			name:  "Disconnect while joining",
			phase: ConnectPhaseJoin,
			want:  teamspeak.ErrNotConnected,
			drive: func(t *testing.T, c *Client, _ <-chan error) {
				t.Helper()
				serverKeyExchange(c)
				_ = c.Disconnect(t.Context())
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &traceRecorder{}
			c := traceClient(t, WithConnectTrace(rec.trace()))
			result := startConnect(t.Context(), t, c)

			tc.drive(t, c, result)
			err := waitResult(t, result)

			// A late initserver must not turn the ended attempt into a session.
			serverInitServer(c)
			if err == nil {
				t.Fatal("Connect succeeded")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Connect = %v, want %v", err, tc.want)
			}
			if rec.count("AttemptFailed") != 1 || rec.count("SessionStart") != 0 {
				t.Fatalf("hooks = %v, want exactly one AttemptFailed and no SessionStart", rec.sequence())
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			got := rec.attemptFailed[0]
			if got.Phase != tc.phase {
				t.Errorf("Phase = %v, want %v", got.Phase, tc.phase)
			}
			if !errors.Is(got.Err, err) && got.Err.Error() != err.Error() {
				t.Errorf("AttemptFailed.Err = %v, Connect returned %v", got.Err, err)
			}
			if got.Attempt != 1 || got.Reconnect || got.Duration <= 0 {
				t.Errorf("AttemptFailed = %+v", got)
			}
		})
	}
}

func TestTrace_CtxDoneIsAnAttemptFailedInTheHandshake(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithConnectTrace(rec.trace()))

	err := c.Connect(ctxWithin(t, 100*time.Millisecond))

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect = %v", err)
	}
	if rec.count("AttemptFailed") != 1 || rec.count("SessionStart") != 0 {
		t.Fatalf("hooks = %v", rec.sequence())
	}
	if got := rec.attemptFailed[0]; got.Phase != ConnectPhaseHandshake || !errors.Is(got.Err, context.DeadlineExceeded) {
		t.Errorf("AttemptFailed = %+v", got)
	}
}

type fixedBadResolver struct{}

func (fixedBadResolver) Resolve(context.Context, string) ([]ResolvedAddr, error) {
	return []ResolvedAddr{{Addr: "not a host", Source: "test"}}, nil
}

func TestTrace_InvalidResolvedAddressFailsInOpen(t *testing.T) {
	rec := &traceRecorder{}
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNew(t, id, "TestBot", WithResolver(fixedBadResolver{}), WithConnectTrace(rec.trace()))

	err = c.Connect(t.Context())

	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Connect = %v", err)
	}
	want := []string{"ResolveStart", "ResolveDone", "AttemptFailed"}
	if got := rec.sequence(); !slices.Equal(got, want) {
		t.Fatalf("hooks = %v, want %v (no ConnectStart: nothing was opened)", got, want)
	}
	if got := rec.attemptFailed[0]; got.Phase != ConnectPhaseOpen || !errors.Is(got.Err, ErrInvalidAddress) {
		t.Errorf("AttemptFailed = %+v", got)
	}
}

type failingResolver struct{ err error }

func (r failingResolver) Resolve(context.Context, string) ([]ResolvedAddr, error) { return nil, r.err }

func TestTrace_ResolveDoneReportsTheFallbackAndTheResolversError(t *testing.T) {
	rec := &traceRecorder{}
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	boom := errTestDrop
	c := mustNew(t, id, "TestBot", WithResolver(failingResolver{boom}), WithConnectTrace(rec.trace()))
	defer func() { _ = c.Disconnect(context.Background()) }()

	_ = c.Connect(ctxWithin(t, 50*time.Millisecond))

	if len(rec.resolveDone) != 1 {
		t.Fatalf("hooks = %v", rec.sequence())
	}
	if got := rec.resolveDone[0]; !errors.Is(got.Err, boom) || got.Target != "127.0.0.1:9987" {
		t.Errorf("ResolveDone = %+v", got)
	}
}

func TestTrace_ReconnectScheduledAndTheReconnectAttempt(t *testing.T) {
	rec := &traceRecorder{}
	silent, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	c := newTestClient(t, WithConnectTrace(rec.trace()), WithResolver(fixedResolver(silent.LocalAddr().String())))
	withFastReconnect(c, func(error, int) bool { return true })
	c.mu.Lock()
	c.attempt.begin(1, false) // the session being dropped came from an attempt
	c.mu.Unlock()

	_ = c.DropConnectionForTest()
	waitUntil(t, "the reconnect attempt to open", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.attempt.opened
	})

	err = c.Disconnect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.reconnectScheduled) == 0 {
		t.Fatalf("no ReconnectScheduled: %v", rec.order)
	}
	got := rec.reconnectScheduled[0]
	if got.Attempt != 1 || got.Delay <= 0 || got.Delay > time.Millisecond || !errors.Is(got.Cause, errConnectionClosed) {
		t.Errorf("ReconnectScheduled = %+v", got)
	}
	if len(rec.resolveStart) == 0 || rec.resolveStart[0].Attempt != 1 || !rec.resolveStart[0].Reconnect {
		t.Errorf("reconnect attempt's ResolveStart = %+v", rec.resolveStart)
	}
	if rec.order[0] != "ReconnectScheduled" || rec.order[1] != "ResolveStart" {
		t.Errorf("order = %v, want ReconnectScheduled then the attempt", rec.order)
	}
}

func TestTrace_APanickingHookIsLoggedAndTheConnectionCompletes(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	boom := func(string) func() { return func() { panic("hook boom") } }
	panicking := &ConnectTrace{
		ResolveStart:  func(ResolveStartInfo) { boom("")() },
		ResolveDone:   func(ResolveDoneInfo) { boom("")() },
		ConnectStart:  func(ConnectStartInfo) { boom("")() },
		HandshakeDone: func(HandshakeDoneInfo) { boom("")() },
		SessionStart:  func(SessionStartInfo) { boom("")() },
		WelcomeDone:   func(WelcomeDoneInfo) { boom("")() },
	}
	c := traceClient(t, WithConnectTrace(panicking), WithLogger(logger))

	err := connectThrough(t, c)

	if err != nil {
		t.Fatalf("Connect = %v, want success despite panicking hooks", err)
	}
	if got := c.Status(); got != StatusConnected {
		t.Errorf("status = %v", got)
	}
	out := logs.String()
	for _, name := range []string{
		"ResolveStart", "ResolveDone", "ConnectStart", "HandshakeDone", "SessionStart", "WelcomeDone",
	} {
		if !strings.Contains(out, "hook="+name) {
			t.Errorf("no panic log for %s", name)
		}
	}
	if !strings.Contains(out, "hook boom") || !strings.Contains(out, "stack=") || !strings.Contains(out, "level=ERROR") {
		t.Errorf("panic log lacks the value, the stack or Error level:\n%s", out)
	}
}

func TestTrace_APanickingAttemptFailedHookStillReleasesConnect(t *testing.T) {
	c := traceClient(t, WithConnectTrace(&ConnectTrace{
		AttemptFailed: func(AttemptFailedInfo) { panic("boom") },
	}))

	err := c.Connect(ctxWithin(t, 50*time.Millisecond))

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect = %v", err)
	}
}

// A hook may read the client: no lock is held when it runs.
func TestTrace_HooksMayReadTheClient(t *testing.T) {
	var c *Client
	var mu sync.Mutex
	reads := 0
	read := func() {
		_ = c.Status()
		_ = c.ClientID()
		_ = c.String()
		mu.Lock()
		reads++
		mu.Unlock()
	}
	trace := &ConnectTrace{
		ResolveStart:  func(ResolveStartInfo) { read() },
		ResolveDone:   func(ResolveDoneInfo) { read() },
		ConnectStart:  func(ConnectStartInfo) { read() },
		HandshakeDone: func(HandshakeDoneInfo) { read() },
		SessionStart: func(i SessionStartInfo) {
			read()
			if c.ClientID() != i.ClientID {
				t.Errorf("SessionStart.ClientID = %d, ClientID() = %d", i.ClientID, c.ClientID())
			}
			if c.Status() != StatusConnected {
				t.Errorf("status in SessionStart = %v", c.Status())
			}
		},
		WelcomeDone: func(WelcomeDoneInfo) { read() },
	}
	c = traceClient(t, WithConnectTrace(trace))

	done := make(chan error, 1)
	go func() { done <- connectThrough(t, c) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock: a hook reading the client never returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if reads != 6 {
		t.Errorf("hooks that read the client ran %d times, want 6", reads)
	}
}

func TestTrace_AFailedAttemptsHookMayReadTheClient(t *testing.T) {
	var c *Client
	seen := make(chan Status, 1)
	c = traceClient(t, WithConnectTrace(&ConnectTrace{
		AttemptFailed: func(AttemptFailedInfo) { seen <- c.Status() },
	}))

	_ = c.Connect(ctxWithin(t, 50*time.Millisecond))

	select {
	case s := <-seen:
		if s != StatusDisconnected {
			t.Errorf("status seen by AttemptFailed = %v", s)
		}
	case <-time.After(time.Second):
		t.Fatal("AttemptFailed not called")
	}
}

func TestTrace_UnsetHooksAreFine(t *testing.T) {
	cases := map[string][]Option{
		"no trace":       nil,
		"nil trace":      {WithConnectTrace(nil)},
		"empty trace":    {WithConnectTrace(&ConnectTrace{})},
		"only one hook":  {WithConnectTrace(&ConnectTrace{WelcomeDone: func(WelcomeDoneInfo) {}})},
		"only a failure": {WithConnectTrace(&ConnectTrace{AttemptFailed: func(AttemptFailedInfo) {}})},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			c := traceClient(t, options...)
			err := connectThrough(t, c)
			if err != nil {
				t.Fatalf("Connect = %v", err)
			}
			_ = c.Disconnect(t.Context())
			err = c.Connect(ctxWithin(t, 30*time.Millisecond))
			if err == nil {
				t.Fatal("second Connect against a silent server succeeded")
			}
		})
	}
}

func TestTrace_TheClientCopiesTheTrace(t *testing.T) {
	rec := &traceRecorder{}
	trace := rec.trace()
	c := traceClient(t, WithConnectTrace(trace))
	*trace = ConnectTrace{} // too late to matter

	err := connectThrough(t, c)

	if err != nil || rec.count("SessionStart") != 1 {
		t.Fatalf("Connect = %v, hooks = %v", err, rec.sequence())
	}
}

// However many paths end an attempt at once, one of SessionStart and
// AttemptFailed is reported, once.
func TestTrace_AnAttemptEndsWithExactlyOneReport(t *testing.T) {
	for range 200 {
		rec := &traceRecorder{}
		c := traceClient(t, WithConnectTrace(rec.trace()))
		c.mu.Lock()
		c.attempt.begin(1, false)
		c.mu.Unlock()

		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				c.mu.Lock()
				var report func()
				if i%2 == 0 {
					report = c.startSessionLocked()
				} else {
					report = c.endAttemptLocked(errTestDrop)
				}
				c.mu.Unlock()
				report()
			})
		}
		wg.Wait()

		got := rec.count("SessionStart") + rec.count("AttemptFailed")
		if got != 1 || !c.attempt.finished() {
			t.Fatalf("reports = %v, finished = %v; want exactly one", rec.sequence(), c.attempt.finished())
		}
	}
}

// An attempt that never began (refused before resolution) reports nothing.
func TestTrace_RefusedConnectReportsNothing(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithConnectTrace(rec.trace()))
	err := connectThrough(t, c)
	if err != nil {
		t.Fatal(err)
	}
	before := len(rec.sequence())

	err = c.Connect(t.Context())

	if !errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("Connect = %v", err)
	}
	if after := len(rec.sequence()); after != before {
		t.Errorf("a refused Connect reported %v", rec.sequence()[before:])
	}
}

// A hook calling Disconnect is documented as forbidden. It does not deadlock
// (closing a handler does not wait for its reader), and this keeps that true.
// The handlers are run from the test's goroutine, which stands in for the
// receive goroutine: both call them synchronously.
func TestTrace_DisconnectFromAHookDoesNotDeadlock(t *testing.T) {
	for _, hook := range []string{"HandshakeDone", "SessionStart"} {
		t.Run(hook, func(t *testing.T) {
			var c *Client
			returned := make(chan error, 1)
			disconnect := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				returned <- c.Disconnect(ctx)
			}
			trace := &ConnectTrace{}
			if hook == "HandshakeDone" {
				trace.HandshakeDone = func(HandshakeDoneInfo) { disconnect() }
			} else {
				trace.SessionStart = func(SessionStartInfo) { disconnect() }
			}
			c = traceClient(t, WithConnectTrace(trace))
			result := startConnect(t.Context(), t, c)

			finished := make(chan struct{})
			go func() {
				defer close(finished)
				serverKeyExchange(c)
				serverInitServer(c)
			}()
			select {
			case <-finished:
			case <-time.After(8 * time.Second):
				t.Fatal("the receive path is stuck for good")
			}
			select {
			case err := <-returned:
				t.Logf("%s: Disconnect from the hook returned (%v)", hook, err)
			default:
				t.Fatal("hook did not finish")
			}
			_ = waitResult(t, result)
		})
	}
}

func TestConnectPhaseString(t *testing.T) {
	for p, want := range map[ConnectPhase]string{
		ConnectPhaseOpen: "open", ConnectPhaseHandshake: "handshake", ConnectPhaseJoin: "join", ConnectPhase(9): "unknown",
	} {
		if got := p.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", p, got, want)
		}
	}
}
