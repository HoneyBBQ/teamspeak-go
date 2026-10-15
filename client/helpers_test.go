package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

func TestIsAutoNicknameMatch_ExactMatch(t *testing.T) {
	if !isAutoNicknameMatch("Bot", "Bot") {
		t.Error("exact match should return true")
	}
}

func TestIsAutoNicknameMatch_NumericSuffix(t *testing.T) {
	if !isAutoNicknameMatch("Bot", "Bot123") {
		t.Error("numeric suffix should match")
	}
	if !isAutoNicknameMatch("Bot", "Bot1") {
		t.Error("single digit suffix should match")
	}
}

func TestIsAutoNicknameMatch_NonNumericSuffix(t *testing.T) {
	if isAutoNicknameMatch("Bot", "BotX") {
		t.Error("non-numeric suffix should not match")
	}
	if isAutoNicknameMatch("Bot", "Bot1a") {
		t.Error("alphanumeric suffix should not match")
	}
}

func TestIsAutoNicknameMatch_NoPrefixMatch(t *testing.T) {
	if isAutoNicknameMatch("Bot", "OtherBot") {
		t.Error("different prefix should not match")
	}
	if isAutoNicknameMatch("Bot", "") {
		t.Error("empty string should not match")
	}
}

func TestCommandTracker_RegisterAndResolve(t *testing.T) {
	tr := newReadyCommandTracker()

	rc, ch := tr.register(nil, "", false)
	if rc == 0 {
		t.Error("expected non-zero rc")
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		tr.resolve(rc, nil, 0)
	}()

	select {
	case result := <-ch:
		if result.Err != nil {
			t.Errorf("unexpected error: %v", result.Err)
		}
	case <-time.After(time.Second):
		t.Error("resolve timed out")
	}
}

func TestCommandTracker_CollectAndResolveWithData(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, ch := tr.register(nil, "", false)

	tr.collect(map[string]string{"k": "v"}, "")
	tr.resolve(rc, nil, 0)

	result := <-ch
	if len(result.Data) != 1 || result.Data[0]["k"] != "v" {
		t.Errorf("unexpected data: %v", result.Data)
	}
}

func TestCommandTracker_UnregisterPreventsFire(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, ch := tr.register(nil, "", false)
	tr.unregister(rc)
	// Resolving after unregister should be a no-op.
	tr.resolve(rc, nil, 0)

	select {
	case <-ch:
		t.Error("channel should not receive after unregister")
	case <-time.After(50 * time.Millisecond):
	}
}

// Dropping in-flight commands silently left each caller waiting out its full
// timeout for an answer that could no longer come.
func TestCommandTracker_ResetFailsInFlightCommands(t *testing.T) {
	tr := newReadyCommandTracker()
	_, first := tr.register(nil, "", false)
	_, second := tr.register(nil, "", false)
	tr.reset(teamspeak.ErrNotConnected)

	for _, ch := range []<-chan commandResult{first, second} {
		select {
		case res := <-ch:
			if !errors.Is(res.Err, teamspeak.ErrNotConnected) {
				t.Errorf("err = %v, want ErrNotConnected", res.Err)
			}
		case <-time.After(time.Second):
			t.Fatal("reset did not fail an in-flight command")
		}
	}
}

func TestCommandTracker_RCMonotoneIncreasing(t *testing.T) {
	tr := newReadyCommandTracker()
	rc1, _ := tr.register(nil, "", false)
	rc2, _ := tr.register(nil, "", false)
	if rc2 <= rc1 {
		t.Errorf("expected rc2 > rc1, got rc1=%d rc2=%d", rc1, rc2)
	}
}

func TestCommandThrottle_InitialTokensAllowImmediate(t *testing.T) {
	th := newCommandThrottle()
	// Should not block with fresh tokens.
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		_ = th.wait(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("wait blocked unexpectedly on fresh throttle")
	}
}

func TestCommandThrottle_ContextCancelUnblocks(t *testing.T) {
	th := newCommandThrottle()
	// Drain all tokens (default 5, max 8).
	ctx := context.Background()
	for range 8 {
		_ = th.wait(ctx)
	}

	// Now tokens are exhausted; cancel should unblock.
	cancelCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- th.wait(cancelCtx)
	}()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Error("wait did not unblock after context cancel")
	}
}

func TestCommandThrottle_Concurrent(t *testing.T) {
	th := newCommandThrottle()
	var count atomic.Int32
	ctx := context.Background()
	start := make(chan struct{})

	const goroutines = 5
	done := make(chan struct{}, goroutines)
	for range goroutines {
		go func() {
			<-start
			_ = th.wait(ctx)
			count.Add(1)
			done <- struct{}{}
		}()
	}
	close(start)

	for range goroutines {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("throttle wait did not complete (got %d/%d)", count.Load(), goroutines)

			return
		}
	}
	if count.Load() != goroutines {
		t.Errorf("expected %d completions, got %d", goroutines, count.Load())
	}
}

// Reading a channel id and a plain uint64 moved to internal/servernotify with
// the rest of the notification parsing, so their tests went with them.

// Waiters are released in the order they arrived, and one that gives up
// leaves its place to the next.
func TestCommandThrottle_ReleasesInArrivalOrder(t *testing.T) {
	th := newCommandThrottle()
	th.mu.Lock()
	th.tokens = 0
	th.lastUpdate = time.Now()
	th.mu.Unlock()

	const waiters = 6
	order := make(chan int, waiters)
	cancelled, cancel := context.WithCancel(t.Context())
	for i := range waiters {
		ctx := t.Context()
		if i == 2 {
			ctx = cancelled
		}
		go func() {
			if th.wait(ctx) == nil {
				order <- i
			}
		}()
		// Let each one join the queue before the next arrives.
		for deadline := time.Now().Add(time.Second); ; {
			th.mu.Lock()
			queued := len(th.queue)
			th.mu.Unlock()
			if queued == i+1 || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	cancel()

	for want := range waiters {
		if want == 2 {
			continue
		}
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("released waiter %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d was not released", want)
		}
	}
}

// waitDelivered returns once every event queued so far has been delivered:
// events run in order, so a marker queued now runs after them.
func waitDelivered(t *testing.T, c *Client) {
	t.Helper()
	delivered := make(chan struct{})
	c.events.Push(func() { close(delivered) })
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("the queued events were not delivered")
	}
}
