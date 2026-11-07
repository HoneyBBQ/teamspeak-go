package client

import (
	"errors"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

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
