package client

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
)

// traceRecorder collects what a Trace reports, in order.
type traceRecorder struct {
	resolveStart       []ResolveStartInfo
	resolveDone        []ResolveDoneInfo
	connectStart       []ConnectStartInfo
	handshakeDone      []HandshakeDoneInfo
	sessionStart       []SessionStartInfo
	welcomeDone        []WelcomeDoneInfo
	attemptFailed      []AttemptFailedInfo
	reconnectScheduled []ReconnectScheduledInfo
	connectDone        []ConnectDoneInfo
	disconnectDone     []DisconnectDoneInfo
	sessionEnd         []SessionEndInfo
	reconnectStopped   []ReconnectStoppedInfo
	order              []string
	mu                 sync.Mutex
}

func (r *traceRecorder) note(name string) { r.order = append(r.order, name) }

//nolint:funlen // one hook per milestone
func (r *traceRecorder) trace() *Trace {
	return &Trace{
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
		ConnectDone: func(i ConnectDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ConnectDone")
			r.connectDone = append(r.connectDone, i)
		},
		DisconnectStart: func(DisconnectStartInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("DisconnectStart")
		},
		DisconnectDone: func(i DisconnectDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("DisconnectDone")
			r.disconnectDone = append(r.disconnectDone, i)
		},
		SessionEnd: func(i SessionEndInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("SessionEnd")
			r.sessionEnd = append(r.sessionEnd, i)
		},
		ReconnectStopped: func(i ReconnectStoppedInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.note("ReconnectStopped")
			r.reconnectStopped = append(r.reconnectStopped, i)
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
	c := traceClient(t, WithTrace(rec.trace()))
	var sawBeforeReturn bool
	c.trace.SessionStart = func(i SessionStartInfo) {
		rec.trace().SessionStart(i)
		sawBeforeReturn = c.attempt.finished() // no lock needed: only this goroutine closes it, after the hook
	}

	err := connectThrough(t, c)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	want := []string{
		"ResolveStart", "ResolveDone", "ConnectStart", "ConnectDone", "HandshakeDone", "SessionStart", "WelcomeDone",
	}
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
	if rs.Attempt != 1 || rs.Reconnect || rs.Addr != unitTestServerAddr {
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
	c := traceClient(t, WithTrace(rec.trace()))
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
				h.TsCrypt.FinishPuzzle(nil, nil, make([]byte, 10), 0, 0)
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
			c := traceClient(t, WithTrace(rec.trace()))
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
			if got.WaitingFor == "" {
				t.Errorf("AttemptFailed.WaitingFor is empty")
			}
			if got.Attempt != 1 || got.Reconnect || got.Duration <= 0 {
				t.Errorf("AttemptFailed = %+v", got)
			}
		})
	}
}

func TestTrace_CtxDoneIsAnAttemptFailedInTheHandshake(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))

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
	// The hook carries the same words the error does.
	if got := rec.attemptFailed[0].WaitingFor; got != "the server's first answer to init1" ||
		!strings.Contains(err.Error(), "while waiting for "+got) {
		t.Errorf("WaitingFor = %q, error %q", got, err)
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
	c := mustNew(t, id, "TestBot", WithResolver(fixedBadResolver{}), WithTrace(rec.trace()))

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
	c := mustNew(t, id, "TestBot", WithResolver(failingResolver{boom}), WithTrace(rec.trace()))
	defer func() { _ = c.Disconnect(context.Background()) }()

	_ = c.Connect(ctxWithin(t, 50*time.Millisecond))

	if len(rec.resolveDone) != 1 {
		t.Fatalf("hooks = %v", rec.sequence())
	}
	if got := rec.resolveDone[0]; !errors.Is(got.Err, boom) || got.Target != unitTestServerAddr {
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
	c := newTestClient(t, WithTrace(rec.trace()), WithResolver(fixedResolver(silent.LocalAddr().String())))
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
	panicking := &Trace{
		ResolveStart:  func(ResolveStartInfo) { boom("")() },
		ResolveDone:   func(ResolveDoneInfo) { boom("")() },
		ConnectStart:  func(ConnectStartInfo) { boom("")() },
		ConnectDone:   func(ConnectDoneInfo) { boom("")() },
		SessionEnd:    func(SessionEndInfo) { boom("")() },
		HandshakeDone: func(HandshakeDoneInfo) { boom("")() },
		SessionStart:  func(SessionStartInfo) { boom("")() },
		WelcomeDone:   func(WelcomeDoneInfo) { boom("")() },
	}
	c := traceClient(t, WithTrace(panicking), WithLogger(logger))

	err := connectThrough(t, c)

	if err != nil {
		t.Fatalf("Connect = %v, want success despite panicking hooks", err)
	}
	if got := c.Status(); got != StatusConnected {
		t.Errorf("status = %v", got)
	}
	out := logs.String()
	for _, name := range []string{
		"ResolveStart", "ResolveDone", "ConnectStart", "ConnectDone", "HandshakeDone", "SessionStart", "WelcomeDone",
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
	c := traceClient(t, WithTrace(&Trace{
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
	trace := &Trace{
		ResolveStart:  func(ResolveStartInfo) { read() },
		ResolveDone:   func(ResolveDoneInfo) { read() },
		ConnectStart:  func(ConnectStartInfo) { read() },
		ConnectDone:   func(ConnectDoneInfo) { read() },
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
	c = traceClient(t, WithTrace(trace))

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
	if reads != 7 {
		t.Errorf("hooks that read the client ran %d times, want 7", reads)
	}
}

func TestTrace_AFailedAttemptsHookMayReadTheClient(t *testing.T) {
	var c *Client
	seen := make(chan Status, 1)
	c = traceClient(t, WithTrace(&Trace{
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
		"nil trace":      {WithTrace(nil)},
		"empty trace":    {WithTrace(&Trace{})},
		"only one hook":  {WithTrace(&Trace{WelcomeDone: func(WelcomeDoneInfo) {}})},
		"only a failure": {WithTrace(&Trace{AttemptFailed: func(AttemptFailedInfo) {}})},
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
	c := traceClient(t, WithTrace(trace))
	*trace = Trace{} // too late to matter

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
		c := traceClient(t, WithTrace(rec.trace()))
		c.mu.Lock()
		c.attempt.begin(1, false)
		c.mu.Unlock()

		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				c.mu.Lock()
				var report func()
				if i%2 == 0 {
					report = c.startSessionLocked(nil)
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
	c := traceClient(t, WithTrace(rec.trace()))
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
			trace := &Trace{}
			if hook == "HandshakeDone" {
				trace.HandshakeDone = func(HandshakeDoneInfo) { disconnect() }
			} else {
				trace.SessionStart = func(SessionStartInfo) { disconnect() }
			}
			c = traceClient(t, WithTrace(trace))
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

// serverPuzzle feeds the client the server's fourth Init1 packet, which
// carries an RSA puzzle of the given level.
func serverPuzzle(c *Client, level uint32) {
	data := make([]byte, 1+64+64+4+100)
	data[0] = 3
	data[64] = 5     // x = 5
	data[128] = 0xE1 // n = 225, not zero
	data[129], data[130], data[131], data[132] = byte(level>>24), byte(level>>16), byte(level>>8), byte(level)
	c.handleInit1(c.currentHandler(), data)
}

func TestTrace_HandshakeDoneReportsThePuzzleTheResendsAndTheServerKey(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	// The silent server never answers the first Init1 packet, so it is sent again.
	waitUntil(t, "a resend", func() bool { return c.currentHandler().Resends() >= 1 })
	serverPuzzle(c, 100)
	// The puzzle is solved off the receive loop, and a real server sends its
	// key exchange only after the answer, which is recorded before it is sent.
	waitUntil(t, "the puzzle answered", func() bool {
		level, _ := c.currentHandler().TsCrypt.Puzzle()

		return level != 0
	})
	serverKeyExchange(c)
	serverInitServer(c)
	_ = waitResult(t, result)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.handshakeDone[0]
	if got.PuzzleLevel != 100 || got.PuzzleDuration <= 0 {
		t.Errorf("puzzle = level %d in %v, want level 100 and a duration", got.PuzzleLevel, got.PuzzleDuration)
	}
	if got.Resends < 1 {
		t.Errorf("Resends = %d, want at least the one resent Init1", got.Resends)
	}
	if want := c.handler.TsCrypt.Identity.PublicKey(); got.ServerPublicKey != want {
		t.Errorf("ServerPublicKey = %q, want the omega the server sent (%q)", got.ServerPublicKey, want)
	}
}

func TestTrace_HandshakeDoneWithoutAPuzzleOrResends(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))

	err := connectThrough(t, c)

	if err != nil {
		t.Fatal(err)
	}
	got := rec.handshakeDone[0]
	if got.PuzzleLevel != 0 || got.PuzzleDuration != 0 || got.Resends != 0 {
		t.Errorf("HandshakeDone = %+v, want no puzzle and no resends", got)
	}
}

func TestTrace_ConnectDoneReportsTheLocalAddress(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))

	err := connectThrough(t, c)

	if err != nil {
		t.Fatal(err)
	}
	got, start := rec.connectDone[0], rec.connectStart[0]
	if got.Target != start.Target || got.LocalAddr == "" || got.Duration <= 0 || got.Attempt != 1 {
		t.Errorf("ConnectDone = %+v, ConnectStart = %+v", got, start)
	}
}

func TestTrace_ConnectDoneOverAPacketConnReportsItsAddress(t *testing.T) {
	rec := &traceRecorder{}
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	c := traceClient(t, WithTrace(rec.trace()), WithPacketConn(pc))

	err = connectThrough(t, c)

	if err != nil {
		t.Fatal(err)
	}
	if got := rec.connectDone[0].LocalAddr; got != pc.LocalAddr().String() {
		t.Errorf("LocalAddr = %q, want the PacketConn's %q", got, pc.LocalAddr())
	}
}

func TestTrace_AttemptFailedReportsTheTarget(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	c.handleCommand(c.currentHandler(), "error id=1024 msg=nope")
	_ = waitResult(t, result)

	if got := rec.attemptFailed[0].Target; got != rec.connectStart[0].Target || got == "" {
		t.Errorf("AttemptFailed.Target = %q, want %q", got, rec.connectStart[0].Target)
	}

	// Before ResolveDone there is no target.
	rec = &traceRecorder{}
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c = mustNew(t, id, "TestBot", WithResolver(fixedBadResolver{}), WithTrace(rec.trace()))
	_ = c.Connect(t.Context())
	if got := rec.attemptFailed[0].Target; got != "not a host" {
		t.Errorf("Target after a resolved but invalid address = %q", got)
	}
}

func TestTrace_ResolveDoneListsEveryCandidate(t *testing.T) {
	rec := &traceRecorder{}
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	answers := []ResolvedAddr{{Addr: "not a host", Source: "SRV"}, {Addr: "second.example:9987", Source: "TSDNS"}}
	c := mustNew(t, id, "TestBot", WithResolver(candidateResolver(answers)), WithTrace(rec.trace()))

	_ = c.Connect(t.Context())

	got := rec.resolveDone[0]
	if len(got.Candidates) != 2 || got.Candidates[1] != answers[1] || got.Target != "not a host" || got.Source != "SRV" {
		t.Errorf("ResolveDone = %+v", got)
	}
	// A fallback has none.
	rec = &traceRecorder{}
	c = mustNew(t, id, "TestBot", WithResolver(failingResolver{errTestDrop}), WithTrace(rec.trace()))
	_ = c.Connect(ctxWithin(t, 30*time.Millisecond))
	if got := rec.resolveDone[0]; len(got.Candidates) != 0 || got.Source != "Fallback" {
		t.Errorf("fallback ResolveDone = %+v", got)
	}
}

type candidateResolver []ResolvedAddr

func (r candidateResolver) Resolve(context.Context, string) ([]ResolvedAddr, error) { return r, nil }

func TestTrace_SessionStartReportsTheNicknameTheTalkPowerAndInitServerWithoutSecrets(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	serverKeyExchange(c)
	c.handleCommand(c.currentHandler(), "initserver aclid=7 acn=TestBot1 client_talk_power=75 "+
		"virtualserver_name=My\\sServer virtualserver_id=4 virtualserver_unique_identifier=abc= "+
		"virtualserver_hostmessage=hello virtualserver_hostmessage_mode=2 virtualserver_version=3.13.7 "+
		"client_server_password=pw client_default_channel_password=cp client_default_token=tok "+
		"client_key_offset=99 virtualserver_welcomemessage=hi")
	_ = waitResult(t, result)

	got := rec.sessionStart[0]
	if got.Nickname != "TestBot1" || got.TalkPower != 75 {
		t.Errorf("Nickname = %q, TalkPower = %d", got.Nickname, got.TalkPower)
	}
	if got.InitServer["virtualserver_name"] != "My Server" || got.InitServer["acn"] != "TestBot1" {
		t.Errorf("InitServer = %v, want unescaped values", got.InitServer)
	}
	for _, key := range secretInitServerKeys {
		if v, ok := got.InitServer[key]; ok {
			t.Errorf("InitServer carries %s=%q", key, v)
		}
	}
	caps := got.Capabilities
	if caps.ServerID != 4 || caps.ServerUID != "abc=" || caps.HostMessage != "hello" || caps.HostMessageMode != 2 {
		t.Errorf("Capabilities = %+v", caps)
	}
	if again := c.ServerCapabilities(); again.ServerID != 4 || again.HostMessageMode != 2 {
		t.Errorf("ServerCapabilities() = %+v", again)
	}
	// The hook's map is its own.
	got.InitServer["x"] = "y"
}

func TestTrace_SessionStartNicknameFallsBackToTheRequestedOne(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	serverKeyExchange(c)
	c.handleCommand(c.currentHandler(), "initserver aclid=7")
	_ = waitResult(t, result)

	if got := rec.sessionStart[0]; got.Nickname != "TestBot" || got.TalkPower != 0 {
		t.Errorf("SessionStart = %+v", got)
	}
	if got := c.ServerCapabilities(); got.ServerID != 0 || got.ServerUID != "" || got.HostMessageMode != 0 {
		t.Errorf("capabilities without the fields = %+v", got)
	}
}

func TestTrace_WelcomeDoneReportsWhereTheClientLandedAndWhatArrived(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)
	serverKeyExchange(c)
	serverInitServer(c)
	_ = waitResult(t, result)
	h := c.currentHandler()
	c.handleCommandLines(h,
		"channellist cid=1 pid=0 channel_name=Default|cid=2 pid=0 channel_name=Alpha|cid=3 pid=0 channel_name=Secret")
	c.handleCommand(h, "notifycliententerview clid=7 ctid=3 client_nickname=TestBot client_type=0")
	c.handleCommand(h, "notifycliententerview clid=9 ctid=1 client_nickname=Other client_type=0")
	serverWelcomeDone(c)

	got := rec.welcomeDone[0]
	if got.ChannelID != 3 || got.Channels != 3 || got.Clients != 2 {
		t.Errorf("WelcomeDone = %+v, want channel 3, 3 channels, 2 clients", got)
	}
}

// connectedClient is a client that has completed a handshake against the silent
// server, with the welcome sequence over.
func connectedClient(t *testing.T, rec *traceRecorder) *Client {
	t.Helper()
	c := traceClient(t, WithTrace(rec.trace()))
	err := connectThrough(t, c)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return c
}

// answerGoodbye plays the server acknowledging the clientdisconnect command.
func answerGoodbye(c *Client) {
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			c.cmdTrack.mu.Lock()
			var rc uint32
			for k := range c.cmdTrack.pending {
				rc = k
			}
			c.cmdTrack.mu.Unlock()
			if rc != 0 {
				c.handleCommand(c.currentHandler(), "error id=0 msg=ok return_code="+strconv.FormatUint(uint64(rc), 10))

				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
}

// TeamSpeak 3 and 6 answer clientdisconnect with a notifyclientleftview about
// this client and no error line; waiting for the error line held every
// Disconnect for its full timeout, and the announcement was taken for the
// server removing the client.
func TestTrace_GoodbyeAnsweredByLeftView(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	var removed atomic.Bool
	c.OnDisconnected(func(e DisconnectedEvent) { removed.Store(e.Err != nil) })
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			c.mu.Lock()
			waiting := c.goodbye != nil
			clid := c.clid
			c.mu.Unlock()
			if waiting {
				c.handleCommand(c.currentHandler(),
					"notifyclientleftview cfid=1 ctid=0 reasonid=8 clid="+strconv.FormatUint(uint64(clid), 10))

				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	start := time.Now()
	err := c.Disconnect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took >= disconnectTimeout {
		t.Fatalf("Disconnect took %v, the full goodbye timeout", took)
	}
	rec.mu.Lock()
	done := rec.disconnectDone
	rec.mu.Unlock()
	if len(done) != 1 || !done[0].Acknowledged {
		t.Fatalf("DisconnectDone = %+v, want one, acknowledged", done)
	}
	waitUntil(t, "the disconnected event", func() bool { return rec.count("SessionEnd") == 1 })
	if removed.Load() {
		t.Fatal("the goodbye's answer was reported as the server removing the client")
	}
}

func TestTrace_DisconnectOrderAcknowledged(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	c.OnDisconnected(func(DisconnectedEvent) { rec.mu.Lock(); rec.note("disconnected"); rec.mu.Unlock() })
	answerGoodbye(c)

	err := c.Disconnect(t.Context())

	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the disconnected event", func() bool { return rec.count("disconnected") == 1 })
	seq := rec.sequence()
	want := []string{"DisconnectStart", "DisconnectDone", "SessionEnd", "disconnected"}
	if tail := seq[len(seq)-4:]; !slices.Equal(tail, want) {
		t.Fatalf("sequence = %v, want it to end with %v", seq, want)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.disconnectDone[0]; !got.Acknowledged || got.Duration <= 0 {
		t.Errorf("DisconnectDone = %+v", got)
	}
	end := rec.sessionEnd[0]
	if end.Cause != nil || end.ClientID != 7 || end.Attempt != 1 || end.Reconnect || end.Duration <= 0 {
		t.Errorf("SessionEnd = %+v", end)
	}
}

func TestTrace_DisconnectOrderNotAcknowledged(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)

	err := c.Disconnect(t.Context())

	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.disconnectDone[0]; got.Acknowledged || got.Duration < 900*time.Millisecond {
		t.Errorf("DisconnectDone = %+v, want no acknowledgement after the goodbye timeout", got)
	}
	if rec.order[len(rec.order)-3] != "DisconnectStart" || rec.order[len(rec.order)-1] != "SessionEnd" {
		t.Errorf("order = %v", rec.order)
	}
}

func TestTrace_DisconnectWithoutASessionReportsNothing(t *testing.T) {
	rec := &traceRecorder{}
	c := traceClient(t, WithTrace(rec.trace()))
	result := startConnect(t.Context(), t, c)

	_ = c.Disconnect(t.Context())
	_ = waitResult(t, result)

	for _, name := range []string{"DisconnectStart", "DisconnectDone", "SessionEnd"} {
		if rec.count(name) != 0 {
			t.Errorf("%s reported for a Disconnect with no session: %v", name, rec.sequence())
		}
	}
	// And not on a client that was never connected.
	_ = c.Disconnect(t.Context())
	if rec.count("DisconnectStart") != 0 {
		t.Error("DisconnectStart on a disconnected client")
	}
}

func TestTrace_SessionEndOnADropCarriesTheCauseAndComesBeforeDisconnected(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	c.OnDisconnected(func(DisconnectedEvent) { rec.mu.Lock(); rec.note("disconnected"); rec.mu.Unlock() })
	causes := make(chan error, 1)
	c.OnDisconnected(func(e DisconnectedEvent) { causes <- e.Err })

	_ = c.DropConnectionForTest()
	waitUntil(t, "the disconnected event", func() bool { return rec.count("disconnected") == 1 })

	eventCause := <-causes
	seq := rec.sequence()
	if tail := seq[len(seq)-2:]; !slices.Equal(tail, []string{"SessionEnd", "disconnected"}) {
		t.Fatalf("sequence = %v", seq)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.sessionEnd[0]
	if got.Cause == nil || got.Cause.Error() != eventCause.Error() || got.ClientID != 7 || got.Duration <= 0 {
		t.Errorf("SessionEnd = %+v, disconnected got %v", got, eventCause)
	}
	if rec.count2("DisconnectStart") != 0 {
		t.Error("a drop reported a goodbye")
	}
}

func (r *traceRecorder) count2(name string) int {
	n := 0
	for _, s := range r.order {
		if s == name {
			n++
		}
	}

	return n
}

func TestTrace_ExactlyOneSessionEndPerSession(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)

	_ = c.DropConnectionForTest()
	waitUntil(t, "the drop", func() bool { return rec.count("SessionEnd") == 1 })
	_ = c.Disconnect(t.Context())
	_ = c.DropConnectionForTest()
	time.Sleep(50 * time.Millisecond)

	if got := rec.count("SessionEnd"); got != 1 {
		t.Errorf("SessionEnd reported %d times for one session: %v", got, rec.sequence())
	}
}

func TestTrace_DropWithReconnectGoesSessionEndThenScheduledThenTheNextAttempt(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	withFastReconnect(c, func(error, int) bool { return true })

	_ = c.DropConnectionForTest()
	waitUntil(t, "the reconnect attempt to open", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.attempt.opened && c.attempt.reconnect
	})

	seq := rec.sequence()
	want := []string{"SessionEnd", "ReconnectScheduled", "ResolveStart", "ResolveDone", "ConnectStart"}
	start := slices.Index(seq, "SessionEnd")
	if start < 0 || len(seq) < start+len(want) || !slices.Equal(seq[start:start+len(want)], want) {
		t.Errorf("sequence = %v, want it to contain %v", seq, want)
	}
}

func TestTrace_ReconnectStoppedWhenShouldRetryDeclines(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	withFastReconnect(c, func(error, int) bool { return false })

	_ = c.DropConnectionForTest()
	waitUntil(t, "ReconnectStopped", func() bool { return rec.count("ReconnectStopped") == 1 })

	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.reconnectStopped[0]
	if got.Attempts != 0 || !errors.Is(got.Cause, errConnectionClosed) {
		t.Errorf("ReconnectStopped = %+v, want no attempts and the drop's cause", got)
	}
	if rec.count2("ReconnectScheduled") != 0 {
		t.Error("ReconnectScheduled for a retry that was declined")
	}
}

func TestTrace_ReconnectStoppedWhenDisconnectStopsTheLoop(t *testing.T) {
	rec := &traceRecorder{}
	c := connectedClient(t, rec)
	withFastReconnect(c, func(error, int) bool { return true })

	_ = c.DropConnectionForTest()
	waitUntil(t, "the reconnect attempt to open", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.attempt.opened && c.attempt.reconnect
	})
	_ = c.Disconnect(t.Context())
	waitUntil(t, "ReconnectStopped", func() bool { return rec.count("ReconnectStopped") == 1 })

	rec.mu.Lock()
	defer rec.mu.Unlock()
	got := rec.reconnectStopped[0]
	if got.Attempts != 1 || got.Cause != nil {
		t.Errorf("ReconnectStopped = %+v, want one attempt and no cause", got)
	}
	if rec.count2("AttemptFailed") != 1 || rec.count2("SessionEnd") != 1 {
		t.Errorf("order = %v", rec.order)
	}
}
