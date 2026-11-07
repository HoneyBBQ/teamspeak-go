package client

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

var returnCodeIn = regexp.MustCompile(`return_code=(\d+)`)

// answerEach answers every line the client sends from now on with answer,
// built from the line's own return code, and records the lines.
func answerEach(c *Client, answer func(n int, rc string) string) func() []string {
	var mu sync.Mutex
	var lines []string
	c.wireHook = func(line string) error {
		mu.Lock()
		lines = append(lines, line)
		n := len(lines)
		mu.Unlock()
		if m := returnCodeIn.FindStringSubmatch(line); m != nil {
			go c.handleCommandLines(c.handler, answer(n, m[1]))
		}

		return nil
	}

	return func() []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), lines...)
	}
}

func ok(_ int, rc string) string { return "error id=0 msg=ok return_code=" + rc }

// recordLines is a line middleware that notes the name of every line it sees
// and passes it on.
func recordLines() (LineMiddleware, func() []string) {
	var mu sync.Mutex
	var names []string
	mw := func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			mu.Lock()
			names = append(names, line.Name)
			mu.Unlock()

			return next(ctx, line)
		}
	}

	return mw, func() []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), names...)
	}
}

// holdLines is a line middleware that holds every line until its context ends
// or release is closed, and tells when a line arrives.
func holdLines(release <-chan struct{}) (LineMiddleware, <-chan struct{}) {
	arrived := make(chan struct{}, 64)
	mw := func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			return next(ctx, line)
		}
	}

	return mw, arrived
}

func TestLineMiddleware_SeesTypedRawNoAnswerAndInternalLines(t *testing.T) {
	mw, seen := recordLines()
	c := newTestClient(t, WithLineMiddleware(mw))
	answerEach(c, ok)

	_, err := c.Exec(ctxWithin(t, time.Second), "whoami")
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	err = c.ExecNoWait(ctxWithin(t, time.Second), "clientupdate client_away=1")
	if err != nil {
		t.Fatalf("ExecNoWait = %v", err)
	}
	err = c.PokeClient(ctxWithin(t, time.Second), 5, "hi")
	if err != nil {
		t.Fatalf("typed command = %v", err)
	}
	c.answerConnectionInfoRequest(c.handler)
	c.background.Wait()

	got := strings.Join(seen(), ",")
	want := "whoami,clientupdate,clientpoke,setconnectioninfo"
	if got != want {
		t.Errorf("the middleware saw %s, want %s", got, want)
	}
}

func TestLineMiddleware_GetsTheEscapedLineWithoutAReturnCode(t *testing.T) {
	var got teamspeak.CommandLine
	capture := func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			got = line

			return next(ctx, line)
		}
	}
	c := newTestClient(t, WithLineMiddleware(capture))
	sent := answerEach(c, ok)

	_, err := c.Exec(ctxWithin(t, time.Second), `sendtextmessage msg=a\sb`)
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if got.Name != "sendtextmessage" || got.Text != `sendtextmessage msg=a\sb` {
		t.Errorf("line = %+v", got)
	}
	if lines := sent(); len(lines) != 1 || !strings.Contains(lines[0], "return_code=") {
		t.Errorf("wire = %q, want the line with the client's return_code", lines)
	}
}

func TestLineMiddleware_RunsOutermostFirst(t *testing.T) {
	var order []string
	tag := func(name string) LineMiddleware {
		return func(next teamspeak.LineSender) teamspeak.LineSender {
			return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
				order = append(order, name)

				return next(ctx, line)
			}
		}
	}
	c := newTestClient(t, WithLineMiddleware(tag("a"), tag("b")), WithLineMiddleware(tag("c")))
	answerEach(c, ok)

	_, err := c.Exec(ctxWithin(t, time.Second), "whoami")
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if got := strings.Join(order, ""); got != "abc" {
		t.Errorf("order = %s, want abc", got)
	}
}

func TestLineMiddleware_HandshakeLinesAndTheGoodbyeSkipIt(t *testing.T) {
	mw, seen := recordLines()
	c := newTestClient(t, WithLineMiddleware(mw))
	lines := sentLines(c)

	c.sendClientInit(c.handler)
	_ = c.Disconnect(ctxWithin(t, 300*time.Millisecond))

	if got := seen(); len(got) != 0 {
		t.Errorf("the middleware saw %v, want nothing", got)
	}
	if countPrefix(lines(), "clientdisconnect") != 1 {
		t.Errorf("sent %q, want one clientdisconnect", lines())
	}
}

// The goodbye does not wait behind lines held in a middleware; what is held has
// its context cancelled, is rejected, and is never written.
func TestDisconnect_CancelsLinesHeldInAMiddlewareAndSendsTheGoodbyeAtOnce(t *testing.T) {
	mw, arrived := holdLines(nil)
	c := newTestClient(t, WithLineMiddleware(mw))
	lines := sentLines(c)

	const waiting = 6
	errs := make(chan error, waiting*2)
	for range waiting {
		go func() { errs <- c.ExecNoWait(t.Context(), "clientupdate client_away=1") }()
		go func() {
			_, err := c.Exec(t.Context(), "whoami")
			errs <- err
		}()
	}
	for range waiting * 2 {
		<-arrived
	}

	_ = c.Disconnect(t.Context())

	for range waiting * 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, teamspeak.ErrNotConnected) {
				t.Errorf("a held command returned %v, want ErrNotConnected", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a command is still held after Disconnect")
		}
	}
	got := lines()
	if len(got) != 1 || countPrefix(got, "clientdisconnect") != 1 {
		t.Errorf("sent %q, want the goodbye only", got)
	}
}

// A middleware that ignores its context and hands the line on after Disconnect
// began finds the connection checked again: nothing is written.
func TestLineMiddleware_ALineHandedOnAfterDisconnectIsNotWritten(t *testing.T) {
	release := make(chan struct{})
	late := func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			<-release

			return next(context.WithoutCancel(ctx), line)
		}
	}
	c := newTestClient(t, WithLineMiddleware(late))
	lines := sentLines(c)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Exec(t.Context(), "whoami")
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)

	_ = c.Disconnect(t.Context())
	close(release)

	err := <-errc
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("Exec = %v, want ErrNotConnected", err)
	}
	if countPrefix(lines(), "whoami") != 0 {
		t.Errorf("sent %q, want no whoami", lines())
	}
}

func TestLineMiddleware_TheTimeoutBoundsItsWaits(t *testing.T) {
	mw, _ := holdLines(nil)
	c := newTestClient(t, WithLineMiddleware(mw))
	lines := sentLines(c)

	_, err := c.Exec(ctxWithin(t, 100*time.Millisecond), "whoami")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Exec = %v, want the deadline", err)
	}
	if len(lines()) != 0 {
		t.Errorf("sent %q, want nothing", lines())
	}
}

func TestLineMiddleware_CallingNextTwiceUsesTwoReturnCodes(t *testing.T) {
	twice := func(next teamspeak.LineSender) teamspeak.LineSender {
		return func(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
			_, _ = next(ctx, line)

			return next(ctx, line)
		}
	}
	c := newTestClient(t, WithLineMiddleware(twice))
	sent := answerEach(c, ok)

	_, err := c.Exec(ctxWithin(t, time.Second), "whoami")
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	lines := sent()
	if len(lines) != 2 {
		t.Fatalf("sent %d lines, want 2", len(lines))
	}
	first, second := returnCodeIn.FindString(lines[0]), returnCodeIn.FindString(lines[1])
	if first == second {
		t.Errorf("both sends carried %s", first)
	}
}

// Measured on TeamSpeak 3 and 6: error 524 did not run the command. The client
// no longer sends it again; the refusal is the caller's, and FloodWait reads
// the wait it names.
func TestExec_ASurfacedFloodRefusalIsNotResent(t *testing.T) {
	c := newTestClient(t)
	sent := answerEach(c, func(_ int, rc string) string {
		return `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s200ms return_code=` + rc
	})

	_, err := c.Exec(ctxWithin(t, 2*time.Second), "dummycmd")
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != errcode.ClientIsFlooding {
		t.Fatalf("Exec = %v, want the flooding error", err)
	}
	if wait, ok := teamspeak.FloodWait(err); !ok || wait != 200*time.Millisecond {
		t.Errorf("FloodWait = %v, %v, want 200ms", wait, ok)
	}
	if n := len(sent()); n != 1 {
		t.Errorf("sent %d times, want 1", n)
	}
}

func TestExec_WithoutAMiddlewareACommandBurstGoesOutAtOnce(t *testing.T) {
	c := newTestClient(t)
	sent := answerEach(c, ok)
	start := time.Now()
	for range 30 {
		_, err := c.Exec(ctxWithin(t, time.Second), "whoami")
		if err != nil {
			t.Fatalf("Exec = %v", err)
		}
	}
	if n := len(sent()); n != 30 {
		t.Errorf("sent %d, want 30", n)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("30 commands took %v: something paces them", took)
	}
}
