package serverquery_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/serverquery"
)

var errReset = errors.New("connection reset")

// fakeTransport records what is sent and lets the test answer.
type fakeTransport struct {
	lines  chan string
	closed chan struct{}
	// sentCh carries each line as it is sent.
	sentCh    chan string
	closeErr  error
	sent      []string
	mu        sync.Mutex
	closeOnce sync.Once
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		lines:  make(chan string, 64),
		closed: make(chan struct{}),
		sentCh: make(chan string, 64),
	}
}

func (f *fakeTransport) WriteLine(_ context.Context, line string) error {
	f.mu.Lock()
	f.sent = append(f.sent, line)
	f.mu.Unlock()
	f.sentCh <- line

	return nil
}

func (f *fakeTransport) ReadLine() (string, error) {
	select {
	case line := <-f.lines:
		return line, nil
	case <-f.closed:
		if f.closeErr != nil {
			return "", f.closeErr
		}

		return "", io.EOF
	}
}

func (f *fakeTransport) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })

	return nil
}

// drop ends the connection from the server's side.
func (f *fakeTransport) drop(err error) {
	f.closeErr = err
	_ = f.Close()
}

func (f *fakeTransport) receive(lines ...string) {
	for _, line := range lines {
		f.lines <- line
	}
}

// next waits for the next line the client sends.
func (f *fakeTransport) next(t *testing.T) string {
	t.Helper()
	select {
	case line := <-f.sentCh:
		return line
	case <-time.After(time.Second):
		t.Fatal("nothing sent")

		return ""
	}
}

func (f *fakeTransport) sentLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.sent...)
}

type answer[T any] struct {
	err   error
	value T
}

// run calls fn on a goroutine of its own, so the test can answer it.
func run[T any](fn func() (T, error)) <-chan answer[T] {
	ch := make(chan answer[T], 1)
	go func() {
		value, err := fn()
		ch <- answer[T]{value: value, err: err}
	}()

	return ch
}

func await[T any](t *testing.T, ch <-chan answer[T]) answer[T] {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(2 * time.Second):
		t.Fatal("no answer")

		return answer[T]{}
	}
}

func newClient(t *testing.T) (*serverquery.Client, *fakeTransport) {
	t.Helper()
	transport := newFakeTransport()
	c := serverquery.New(transport)
	t.Cleanup(func() { _ = c.Close() })

	return c, transport
}

func TestClient_RunsTheTypedCommands(t *testing.T) {
	c, transport := newClient(t)
	cmds := teamspeak.NewCommands(c)

	channels := run(func() ([]teamspeak.Channel, error) {
		return cmds.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
	})
	if sent := transport.next(t); !strings.HasPrefix(sent, "channellist") {
		t.Errorf("sent %q, want channellist", sent)
	}
	transport.receive(
		`cid=1 pid=0 channel_order=0 channel_name=Lobby|cid=2 pid=0 channel_order=1 channel_name=Two\sRooms`,
		"error id=0 msg=ok",
	)

	got := await(t, channels)
	if got.err != nil {
		t.Fatalf("ListChannels: %v", got.err)
	}
	names := make([]string, 0, len(got.value))
	for _, ch := range got.value {
		names = append(names, ch.Name)
	}
	if !reflect.DeepEqual(names, []string{"Lobby", "Two Rooms"}) {
		t.Errorf("channels = %v, want [Lobby Two Rooms]", names)
	}
}

// ServerQuery takes the password itself; the voice protocol wants the hash.
func TestClient_SendsAChannelPasswordAsItIs(t *testing.T) {
	c, transport := newClient(t)
	cmds := teamspeak.NewCommands(c)

	password := "hunter2"
	created := run(func() (teamspeak.ChannelID, error) {
		return cmds.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
			Name: "Room", Password: &password,
		})
	})
	sent := transport.next(t)
	transport.receive("cid=7", "error id=0 msg=ok")

	got := await(t, created)
	if got.err != nil || got.value != 7 {
		t.Fatalf("CreateChannel = %d, %v; want 7", got.value, got.err)
	}
	if !strings.Contains(sent, "channel_password=hunter2") {
		t.Errorf("sent %q, want the password as it is", sent)
	}
}

func TestClient_WalksAPagedCommandUntilTheEnd(t *testing.T) {
	c, transport := newClient(t)
	cmds := teamspeak.NewCommands(c)

	walk := run(func() ([]teamspeak.ClientDBID, error) {
		var seen []teamspeak.ClientDBID
		for entry, err := range cmds.IterateClientDatabase(t.Context(), teamspeak.PagingOptions{}) {
			if err != nil {
				return seen, err
			}
			seen = append(seen, entry.DatabaseID)
		}

		return seen, nil
	})
	first := transport.next(t)
	transport.receive("cldbid=1 client_nickname=a|cldbid=2 client_nickname=b", "error id=0 msg=ok")
	second := transport.next(t)
	transport.receive(`error id=1281 msg=database\sempty\sresult\sset`)

	got := await(t, walk)
	if got.err != nil {
		t.Fatalf("ClientDatabase: %v", got.err)
	}
	if !reflect.DeepEqual(got.value, []teamspeak.ClientDBID{1, 2}) {
		t.Errorf("walked %v, want [1 2]", got.value)
	}
	if !strings.Contains(first, "start=0") || !strings.Contains(second, "start=2") {
		t.Errorf("sent %q then %q, want pages from 0 and 2", first, second)
	}
}

// The server answers an empty list with 1281 rather than with no rows.
func TestClient_ReadsAnEmptyListAsEmpty(t *testing.T) {
	c, transport := newClient(t)
	cmds := teamspeak.NewCommands(c)

	bans := run(func() ([]teamspeak.BanEntry, error) { return cmds.ListBans(t.Context(), teamspeak.BanListOptions{}) })
	transport.next(t)
	transport.receive(`error id=1281 msg=database\sempty\sresult\sset`)

	if got := await(t, bans); got.err != nil || len(got.value) != 0 {
		t.Errorf("ListBans = %v, %v; want nothing", got.value, got.err)
	}
}

func TestClient_ReturnsTheServersError(t *testing.T) {
	c, transport := newClient(t)

	answered := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "channeldelete cid=9") })
	transport.next(t)
	transport.receive(`error id=768 msg=invalid\schannelID`)

	err := await(t, answered).err
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || !errors.Is(err, errcode.ChannelInvalidID) {
		t.Fatalf("err = %v, want a ServerError for 768", err)
	}
	if serverErr.Message != "invalid channelID" {
		t.Errorf("message = %q", serverErr.Message)
	}
}

func TestClient_SendsOneCommandAtATime(t *testing.T) {
	c, transport := newClient(t)

	first := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "first") })
	if sent := transport.next(t); sent != "first" {
		t.Fatalf("sent %q, want first", sent)
	}
	second := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "second") })

	select {
	case line := <-transport.sentCh:
		t.Fatalf("sent %q before first was answered", line)
	case <-time.After(50 * time.Millisecond):
	}

	transport.receive("a=1", "error id=0 msg=ok")
	if sent := transport.next(t); sent != "second" {
		t.Fatalf("sent %q, want second", sent)
	}
	transport.receive("b=2", "error id=0 msg=ok")

	if got := await(t, first); !reflect.DeepEqual(got.value, []map[string]string{{"a": "1"}}) {
		t.Errorf("first = %v, %v", got.value, got.err)
	}
	if got := await(t, second); !reflect.DeepEqual(got.value, []map[string]string{{"b": "2"}}) {
		t.Errorf("second = %v, %v", got.value, got.err)
	}
}

// With no return_code, a late answer would otherwise be taken for the next
// command's.
func TestClient_DiscardsTheAnswerOfACommandThatGaveUp(t *testing.T) {
	c, transport := newClient(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	slow := run(func() ([]map[string]string, error) { return c.Exec(ctx, "slow") })
	transport.next(t)
	err := await(t, slow).err
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow: err = %v, want context.DeadlineExceeded", err)
	}

	next := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "next") })
	transport.next(t)
	transport.receive("late=1", "error id=0 msg=ok", "mine=1", "error id=0 msg=ok")

	if got := await(t, next); !reflect.DeepEqual(got.value, []map[string]string{{"mine": "1"}}) {
		t.Errorf("next = %v, %v; want only its own answer", got.value, got.err)
	}
}

func TestClient_DoesNotMistakeANotificationForAnAnswer(t *testing.T) {
	c, transport := newClient(t)

	answered := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "whoami") })
	transport.next(t)
	transport.receive("notifytextmessage targetmode=3 msg=hi", "client_id=1", "error id=0 msg=ok")

	if got := await(t, answered); !reflect.DeepEqual(got.value, []map[string]string{{"client_id": "1"}}) {
		t.Errorf("whoami = %v, %v", got.value, got.err)
	}
}

func TestClient_FailsWhatIsWaitingWhenTheConnectionEnds(t *testing.T) {
	c, transport := newClient(t)

	answered := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "whoami") })
	queued := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "version") })
	transport.next(t)
	transport.drop(errReset)

	for _, ch := range []<-chan answer[[]map[string]string]{answered, queued} {
		err := await(t, ch).err
		if !errors.Is(err, teamspeak.ErrNotConnected) || !errors.Is(err, errReset) {
			t.Errorf("err = %v, want ErrNotConnected carrying the cause", err)
		}
	}
	_, err := c.Exec(t.Context(), "whoami")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("after the drop: err = %v, want ErrNotConnected", err)
	}
}

func TestClient_CloseFailsWhatIsWaiting(t *testing.T) {
	c, transport := newClient(t)

	answered := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "whoami") })
	transport.next(t)
	err := c.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = await(t, answered).err
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
	_, err = c.Exec(t.Context(), "whoami")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("after Close: err = %v, want ErrNotConnected", err)
	}
	if sent := transport.sentLines(); len(sent) != 1 {
		t.Errorf("sent %v, want nothing after Close", sent)
	}
}

// nudgingTransport is a fakeTransport that is a Nudger, as the SSH one is.
type nudgingTransport struct {
	*fakeTransport

	nudges atomic.Int32
}

func (n *nudgingTransport) Nudge() error {
	n.nudges.Add(1)

	return nil
}

// nudgeFixture runs body in a bubble of fake time, with a client over a
// nudging transport that is closed afterwards.
func nudgeFixture(t *testing.T, body func(t *testing.T, c *serverquery.Client, tr *nudgingTransport)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		tr := &nudgingTransport{fakeTransport: newFakeTransport()}
		c := serverquery.New(tr)
		defer func() { _ = c.Close() }()
		body(t, c, tr)
	})
}

func TestClient_NudgesNothingForACommandAnsweredInTime(t *testing.T) {
	nudgeFixture(t, func(t *testing.T, c *serverquery.Client, tr *nudgingTransport) {
		t.Helper()
		done := run(func() ([]map[string]string, error) { return c.Exec(t.Context(), "version") })
		time.Sleep(1900 * time.Millisecond)
		tr.receive("version=1", "error id=0 msg=ok")
		if a := await(t, done); a.err != nil {
			t.Fatal(a.err)
		}
		time.Sleep(10 * time.Second)
		if n := tr.nudges.Load(); n != 0 {
			t.Fatalf("nudges = %d, want 0", n)
		}
	})
}

func TestClient_NudgesAnUnansweredCommandUntilItsErrorLine(t *testing.T) {
	nudgeFixture(t, func(t *testing.T, c *serverquery.Client, tr *nudgingTransport) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		done := run(func() ([]map[string]string, error) { return c.Exec(ctx, "version") })
		time.Sleep(1999 * time.Millisecond)
		if n := tr.nudges.Load(); n != 0 {
			t.Fatalf("nudges at 1.999s = %d, want 0", n)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if n := tr.nudges.Load(); n != 1 {
			t.Fatalf("nudges at 2s = %d, want 1", n)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if n := tr.nudges.Load(); n != 3 {
			t.Fatalf("nudges at 4s = %d, want 3", n)
		}
		// A data row arrived on time and the terminator was held: the nudge
		// released it and the command resolves with the row.
		tr.receive("version=1", "error id=0 msg=ok")
		a := await(t, done)
		if a.err != nil || !reflect.DeepEqual(a.value, []map[string]string{{"version": "1"}}) {
			t.Fatalf("got %v, %v", a.value, a.err)
		}
		time.Sleep(10 * time.Second)
		if n := tr.nudges.Load(); n != 3 {
			t.Fatalf("nudges after the answer = %d, want 3", n)
		}
	})
}

func TestClient_StopsNudgingWhenACommandTimesOutIsCancelledOrClosed(t *testing.T) {
	nudgeFixture(t, func(t *testing.T, c *serverquery.Client, tr *nudgingTransport) {
		t.Helper()
		// Times out at 3.5s, after nudges at 2s and 3s.
		ctx, cancel := context.WithTimeout(t.Context(), 3500*time.Millisecond)
		defer cancel()
		// Read the channel itself: await gives up at 2s, before this deadline.
		if a := <-run(func() ([]map[string]string, error) { return c.Exec(ctx, "version") }); a.err == nil {
			t.Fatal("expected a timeout")
		}
		time.Sleep(10 * time.Second)
		if n := tr.nudges.Load(); n != 2 {
			t.Fatalf("nudges after a timeout = %d, want 2", n)
		}
		// Its error line is still due.
		tr.receive("error id=0 msg=ok")

		// Cancelled at 2.5s.
		cctx, ccancel := context.WithCancel(t.Context())
		done := run(func() ([]map[string]string, error) { return c.Exec(cctx, "version") })
		time.Sleep(2500 * time.Millisecond)
		ccancel()
		await(t, done)
		time.Sleep(10 * time.Second)
		if n := tr.nudges.Load(); n != 3 {
			t.Fatalf("nudges after a cancel = %d, want 3", n)
		}
		tr.receive("error id=0 msg=ok")

		// Closed at 2.5s.
		lctx, lcancel := context.WithTimeout(t.Context(), time.Minute)
		defer lcancel()
		done = run(func() ([]map[string]string, error) { return c.Exec(lctx, "version") })
		time.Sleep(2500 * time.Millisecond)
		_ = c.Close()
		await(t, done)
		time.Sleep(10 * time.Second)
		if n := tr.nudges.Load(); n != 4 {
			t.Fatalf("nudges after close = %d, want 4", n)
		}
	})
}

func TestClient_NudgesTheCommandOnTheWireNotTheQueue(t *testing.T) {
	nudgeFixture(t, func(t *testing.T, c *serverquery.Client, tr *nudgingTransport) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		first := run(func() ([]map[string]string, error) { return c.Exec(ctx, "version") })
		synctest.Wait()
		second := run(func() ([]map[string]string, error) { return c.Exec(ctx, "whoami") })
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()
		if got := tr.sentLines(); len(got) != 1 {
			t.Fatalf("sent %q, want one command", got)
		}
		if n := tr.nudges.Load(); n != 1 {
			t.Fatalf("nudges = %d, want 1", n)
		}
		tr.receive("error id=0 msg=ok")
		await(t, first)
		synctest.Wait()
		if got := tr.sentLines(); len(got) != 2 {
			t.Fatalf("sent %q, want two commands", got)
		}
		// The first command's schedule would nudge at 3s; the second counts
		// from its own send.
		time.Sleep(1999 * time.Millisecond)
		if n := tr.nudges.Load(); n != 1 {
			t.Fatalf("nudges = %d, want 1", n)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if n := tr.nudges.Load(); n != 2 {
			t.Fatalf("nudges = %d, want 2", n)
		}
		tr.receive("error id=0 msg=ok")
		await(t, second)
	})
}

func TestClient_DoesNotNudgeATransportThatIsNotANudger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, tr := newClient(t)
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		done := run(func() ([]map[string]string, error) { return c.Exec(ctx, "version") })
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if got := tr.sentLines(); len(got) != 1 {
			t.Fatalf("sent %q, want only the command", got)
		}
		tr.receive("error id=0 msg=ok")
		await(t, done)
		_ = c.Close()
	})
}
