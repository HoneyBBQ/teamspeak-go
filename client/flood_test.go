package client

import (
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/servererr"
)

var errRetryText = errors.New("retry in 10ms")

var returnCodeIn = regexp.MustCompile(`return_code=(\d+)`)

// answerer answers every line the client sends from now on with answer, built
// from the line's own return code, and records when each went out.
type answerer struct {
	times []time.Time
	mu    sync.Mutex
}

func (a *answerer) sent() []time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]time.Time(nil), a.times...)
}

func answerEach(c *Client, answer func(n int, rc string) string) *answerer {
	a := &answerer{}
	c.wireHook = func(line string) error {
		a.mu.Lock()
		a.times = append(a.times, time.Now())
		n := len(a.times)
		a.mu.Unlock()
		rc := returnCodeIn.FindStringSubmatch(line)[1]
		go c.handleCommandLines(c.handler, answer(n, rc))

		return nil
	}

	return a
}

// Measured on TeamSpeak 3 and 6: error 524 says how long to wait and did not
// run the command, so after the wait it goes out again, under a new return
// code, and everything else waits with it.
func TestExec_ResendsAfterTheWaitAFloodRefusalNames(t *testing.T) {
	c := newTestClient(t)
	a := answerEach(c, func(n int, rc string) string {
		if n == 1 {
			return `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s200ms return_code=` + rc
		}

		return "error id=0 msg=ok return_code=" + rc
	})

	_, err := c.Exec(ctxWithin(t, 3*time.Second), "dummycmd")
	if err != nil {
		t.Fatalf("Exec = %v, want the resend to succeed", err)
	}
	times := a.sent()
	if len(times) != 2 {
		t.Fatalf("sent %d times, want 2", len(times))
	}
	if gap := times[1].Sub(times[0]); gap < 190*time.Millisecond {
		t.Errorf("resent after %v, the server asked for 200ms", gap)
	}
}

func TestExec_PausesOtherCommandsDuringTheWait(t *testing.T) {
	c := newTestClient(t)
	a := answerEach(c, func(n int, rc string) string {
		if n == 1 {
			return `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s300ms return_code=` + rc
		}

		return "error id=0 msg=ok return_code=" + rc
	})
	go func() { _, _ = c.Exec(ctxWithin(t, 3*time.Second), "first") }()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	_, err := c.Exec(ctxWithin(t, 3*time.Second), "second")
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	times := a.sent()
	if len(times) < 3 {
		t.Fatalf("sent %d times, want the refused one, its resend and the other", len(times))
	}
	if first := times[1].Sub(start); first < 150*time.Millisecond {
		t.Errorf("a command went out %v into the server's wait of 300ms", first)
	}
}

func TestExec_GivesUpWithTheServersErrorWhenTheWaitIsMoreThanItCanAfford(t *testing.T) {
	c := newTestClient(t)
	a := answerEach(c, func(_ int, rc string) string {
		return `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s5000ms return_code=` + rc
	})

	_, err := c.Exec(ctxWithin(t, 500*time.Millisecond), "dummycmd")
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != errcode.ClientIsFlooding {
		t.Fatalf("Exec = %v, want the flooding error", err)
	}
	if n := len(a.sent()); n != 1 {
		t.Errorf("sent %d times, want 1", n)
	}
}

func TestExec_DoesNotResendWithoutAWait(t *testing.T) {
	for name, line := range map[string]string{
		"another error":      `error id=1024 msg=x extra_msg=retry\sin\s10ms return_code=`,
		"flooding, no wait":  `error id=524 msg=client\sis\sflooding return_code=`,
		"flooding, odd wait": `error id=524 msg=client\sis\sflooding extra_msg=later return_code=`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t)
			a := answerEach(c, func(_ int, rc string) string { return line + rc })
			_, err := c.Exec(ctxWithin(t, time.Second), "dummycmd")
			if err == nil {
				t.Fatal("Exec succeeded")
			}
			if n := len(a.sent()); n != 1 {
				t.Errorf("sent %d times, want 1", n)
			}
		})
	}
}

// Every resend is refused: it stops after a few, with the server's error.
func TestExec_StopsResendingAfterAFewRefusals(t *testing.T) {
	c := newTestClient(t)
	a := answerEach(c, func(_ int, rc string) string {
		return `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s1ms return_code=` + rc
	})

	_, err := c.Exec(ctxWithin(t, 5*time.Second), "dummycmd")
	if err == nil {
		t.Fatal("Exec succeeded")
	}
	if n := len(a.sent()); n != floodRetries+1 {
		t.Errorf("sent %d times, want %d", n, floodRetries+1)
	}
}

func TestFloodRetryDelay(t *testing.T) {
	flood := func(extra string) error {
		return &teamspeak.ServerError{Code: errcode.ClientIsFlooding, ExtraMessage: extra}
	}
	for extra, want := range map[string]time.Duration{
		"retry in 1985ms": 1985 * time.Millisecond,
		"retry in 0ms":    0,
	} {
		got, ok := servererr.FloodRetryDelay(flood(extra))
		if !ok || got != want {
			t.Errorf("FloodRetryDelay(%q) = %v, %v, want %v", extra, got, ok, want)
		}
	}
	for _, err := range []error{
		flood(""), flood("retry in 5 seconds"), flood("retry in 99999999999ms"),
		&teamspeak.ServerError{Code: errcode.Code(1024), ExtraMessage: "retry in 10ms"},
		errRetryText, nil,
	} {
		if d, ok := servererr.FloodRetryDelay(err); ok {
			t.Errorf("FloodRetryDelay(%v) = %v, want none", err, d)
		}
	}
}

func TestCommandThrottle_HoldReleasesNothingForThePauseAndSavesNoBurst(t *testing.T) {
	th := newCommandThrottle()
	th.hold(300 * time.Millisecond)
	start := time.Now()
	released := make(chan time.Duration, 3)
	for range 3 {
		go func() {
			err := th.wait(t.Context())
			if err == nil {
				released <- time.Since(start)
			}
		}()
	}
	var got []time.Duration
	for range 3 {
		select {
		case d := <-released:
			got = append(got, d)
		case <-time.After(3 * time.Second):
			t.Fatal("waiters were never released")
		}
	}
	for i, d := range got {
		// The first a quarter second after the pause, the rest at the usual rate.
		if earliest := 300*time.Millisecond + time.Duration(i)*200*time.Millisecond; d < earliest {
			t.Errorf("release %d after %v, want at least %v", i, d, earliest)
		}
	}
}
