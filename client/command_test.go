package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
)

func TestHandleCommandLines_Empty(t *testing.T) {
	c := newTestClient(t)
	// Must not panic.
	c.handleCommandLines("")
}

func TestHandleCommandLines_NewlineSeparated(t *testing.T) {
	c := newTestClient(t)
	// Two lines: an error line with a return_code + one notify.
	// We only care that neither path panics and notify fires.
	entered := make(chan struct{}, 2)
	c.OnClientEnter(func(_ teamspeak.ClientInfo) { entered <- struct{}{} })
	c.rebuildMiddlewareChains()

	line1 := "notifycliententerview clid=1 client_nickname=A" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x"
	line2 := "notifycliententerview clid=2 client_nickname=B" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=y"
	c.handleCommandLines(line1 + "\n" + line2)

	for i := range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Errorf("notify not fired for line %d", i)
		}
	}
}

func TestHandleCommandLines_NullByteSeparated(t *testing.T) {
	c := newTestClient(t)
	entered := make(chan struct{}, 1)
	c.OnClientEnter(func(_ teamspeak.ClientInfo) { entered <- struct{}{} })
	c.rebuildMiddlewareChains()

	line := "notifycliententerview clid=3 client_nickname=C" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=z"
	c.handleCommandLines(line + "\x00")

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Error("notify not fired")
	}
}

func TestHandleCommand_Notify_Routed(t *testing.T) {
	c := newTestClient(t)
	entered := make(chan struct{}, 1)
	c.OnClientEnter(func(_ teamspeak.ClientInfo) { entered <- struct{}{} })
	c.rebuildMiddlewareChains()

	line := "notifycliententerview clid=4 client_nickname=D" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=d"
	c.handleCommand(line)

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Error("notification not routed")
	}
}

func TestHandleCommand_Error_NoReturnCode_NoResolve(t *testing.T) {
	c := newTestClient(t)
	rc, ch := c.cmdTrack.register(nil, "", false)

	// error without a matching return_code should not resolve our tracker.
	c.handleCommand("error id=1 msg=fail")

	select {
	case <-ch:
		t.Error("should not resolve for error without matching return_code")
	case <-time.After(50 * time.Millisecond):
	}
	c.cmdTrack.unregister(rc)
}

func TestHandleCommand_Error_WithReturnCode_Resolves(t *testing.T) {
	c := newTestClient(t)
	rc, ch := c.cmdTrack.register(nil, "", false)

	c.handleCommand("error id=0 msg=ok return_code=" + mustUint32Str(rc))

	select {
	case result := <-ch:
		if result.Err != nil {
			t.Errorf("expected nil error, got %v", result.Err)
		}
	case <-time.After(time.Second):
		t.Error("command not resolved")
	}
}

func TestHandleCommand_Error_NonZeroID_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	rc, ch := c.cmdTrack.register(nil, "", false)

	c.handleCommand("error id=256 msg=notfound return_code=" + mustUint32Str(rc))

	select {
	case result := <-ch:
		if result.Err == nil {
			t.Error("expected non-nil error for id=256")
		}
		if !strings.Contains(result.Err.Error(), "notfound") {
			t.Errorf("unexpected error: %v", result.Err)
		}
	case <-time.After(time.Second):
		t.Error("command not resolved")
	}
}

func TestHandleCommand_DataCollectedBeforeError(t *testing.T) {
	c := newTestClient(t)
	rc, ch := c.cmdTrack.register(nil, "", false)

	// In the real TeamSpeak flow, nameless data rows arrive before the "error"
	// response.
	c.handleCommand("key=val")
	c.handleCommand("error id=0 msg=ok return_code=" + mustUint32Str(rc))

	select {
	case result := <-ch:
		if len(result.Data) != 1 || result.Data[0]["key"] != "val" {
			t.Errorf("unexpected data: %v", result.Data)
		}
	case <-time.After(time.Second):
		t.Error("not resolved")
	}
}

// A named line answers a command only if the command declared it; arriving
// while the command is in flight is not enough.
func TestHandleCommand_UndeclaredNamedCommand_IsNotData(t *testing.T) {
	c := newTestClient(t)
	rc, ch := c.cmdTrack.register(nil, "", false)

	c.handleCommand("unknowncmd foo=bar baz=qux")
	c.handleCommand("error id=0 msg=ok return_code=" + mustUint32Str(rc))

	select {
	case result := <-ch:
		if len(result.Data) != 0 {
			t.Fatalf("data = %v, want none", result.Data)
		}
	case <-time.After(time.Second):
		t.Error("not resolved")
	}
}

func TestExec_Success(t *testing.T) {
	c := newTestClient(t)

	go func() {
		time.Sleep(20 * time.Millisecond)
		// The command Exec sends contains "return_code=N".
		// Simulate server data row then ok error line with matching return_code.
		c.handleCommandLines("somekey=someval\nerror id=0 msg=ok return_code=1")
	}()

	data, err := c.Exec(ctxWithin(t, 2*time.Second), "dummycmd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 1 || data[0]["somekey"] != "someval" {
		t.Errorf("unexpected data: %v", data)
	}
}

func TestExec_Timeout(t *testing.T) {
	c := newTestClient(t)

	start := time.Now()
	_, err := c.Exec(ctxWithin(t, 50*time.Millisecond), "dummycmd")
	elapsed := time.Since(start)

	// The context's own error, so the caller tells its deadline from its
	// cancellation the usual way.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Exec = %v, want context.DeadlineExceeded", err)
	}
	if elapsed < 40*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("unexpected elapsed time: %v", elapsed)
	}
}

func TestExec_ServerError(t *testing.T) {
	c := newTestClient(t)

	go func() {
		time.Sleep(20 * time.Millisecond)
		c.handleCommandLines("error id=512 msg=invalid_size return_code=1")
	}()

	_, err := c.Exec(ctxWithin(t, 2*time.Second), "dummycmd")
	if err == nil {
		t.Error("expected error from server")
	}
	if !strings.Contains(err.Error(), "invalid_size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func mustUint32Str(rc uint32) string {
	return commands.ParseCommand("x return_code=" + itoa(rc)).Params["return_code"]
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}

	return string(buf)
}
