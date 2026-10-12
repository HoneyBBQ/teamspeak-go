package client

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/wire"
)

func TestHandleClientEnterView_AddsToClients(t *testing.T) {
	c := newTestClient(t)

	const enterCmd = "notifycliententerview clid=5 client_nickname=Alice" +
		" ctid=10 client_type=0 client_servergroups= client_unique_identifier=uid123"
	c.handleClientEnterView(c.handler, wire.ParseCommand(enterCmd))

	c.mu.Lock()
	info, ok := c.clients[5]
	c.mu.Unlock()

	if !ok {
		t.Fatal("expected client 5 to be in clients map")
	}
	if info.Nickname != "Alice" {
		t.Errorf("expected nickname 'Alice', got %q", info.Nickname)
	}
	if info.ChannelID != 10 {
		t.Errorf("expected channelID 10, got %d", info.ChannelID)
	}
	if info.UID != "uid123" {
		t.Errorf("expected uid 'uid123', got %q", info.UID)
	}
}

func TestHandleClientEnterView_TriggersCallback(t *testing.T) {
	c := newTestClient(t)

	entered := make(chan ClientEnterEvent, 1)
	c.OnClientEnter(func(ci ClientEnterEvent) { entered <- ci })

	const enterCmd2 = "notifycliententerview clid=5 client_nickname=Alice" +
		" ctid=10 client_type=0 client_servergroups= client_unique_identifier=uid123"
	c.handleClientEnterView(c.handler, wire.ParseCommand(enterCmd2))

	select {
	case ci := <-entered:
		if ci.ID != 5 {
			t.Errorf("expected ID 5, got %d", ci.ID)
		}
	case <-time.After(time.Second):
		t.Error("OnClientEnter callback not called")
	}
}

func TestHandleClientEnterView_SetsOwnClidOnNicknameMatch(t *testing.T) {
	c := newTestClient(t)

	const enterSelf = "notifycliententerview clid=7 client_nickname=TestBot" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x"
	c.handleClientEnterView(c.handler, wire.ParseCommand(enterSelf))

	c.mu.Lock()
	clid := c.clid
	c.mu.Unlock()

	if clid != 7 {
		t.Errorf("expected own clid=7 after nickname match, got %d", clid)
	}
}

func TestHandleClientEnterView_LookalikeDoesNotHijackClid(t *testing.T) {
	// The server renames a client whose nickname is taken to "<nick><digits>",
	// so a lookalike is indistinguishable from us by nickname. Adopting its
	// clid would put a foreign clientID on every outgoing packet.
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 5 // assigned by initserver's aclid
	c.mu.Unlock()

	const lookalike = "notifycliententerview clid=9 client_nickname=TestBot2" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x"
	c.handleClientEnterView(c.handler, wire.ParseCommand(lookalike))

	c.mu.Lock()
	clid, nick := c.clid, c.nickname
	c.mu.Unlock()
	if clid != 5 || nick != "TestBot" {
		t.Errorf("after lookalike enter: clid=%d nickname=%q, want 5 and TestBot", clid, nick)
	}
}

func TestHandleClientEnterView_OwnEnterTracksServerRename(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 5
	c.mu.Unlock()

	const ownRenamed = "notifycliententerview clid=5 client_nickname=TestBot2" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x"
	c.handleClientEnterView(c.handler, wire.ParseCommand(ownRenamed))

	c.mu.Lock()
	clid, nick := c.clid, c.nickname
	c.mu.Unlock()
	if clid != 5 || nick != "TestBot2" {
		t.Errorf("after own enter: clid=%d nickname=%q, want 5 and TestBot2", clid, nick)
	}
}

func TestHandleClientEnterView_InvalidClidIgnored(t *testing.T) {
	c := newTestClient(t)
	const enterZero = "notifycliententerview clid=0 client_nickname=X" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x"
	c.handleClientEnterView(c.handler, wire.ParseCommand(enterZero))

	c.mu.Lock()
	_, ok := c.clients[0]
	c.mu.Unlock()

	if ok {
		t.Error("client with clid=0 should be ignored")
	}
}

func TestHandleClientLeftView_RemovesFromClients(t *testing.T) {
	c := newTestClient(t)
	c.clients[5] = teamspeak.ClientInfo{ID: 5, Nickname: "Alice"}

	cmd := wire.ParseCommand("notifyclientleftview clid=5 reasonid=8 reasonmsg=")
	c.handleClientLeftView(c.handler, cmd)

	c.mu.Lock()
	_, ok := c.clients[5]
	c.mu.Unlock()

	if ok {
		t.Error("expected client 5 to be removed")
	}
}

// connectedTestClient is a test client in a live session as clid 5.
func connectedTestClient(t *testing.T) *Client {
	t.Helper()
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusConnected
	c.clid = 5
	c.clients[5] = teamspeak.ClientInfo{ID: 5}
	c.mu.Unlock()

	return c
}

func TestHandleClientLeftView_KickSelf_TriggersKickedAndEndsTheSession(t *testing.T) {
	c := connectedTestClient(t)
	kicked := make(chan KickedEvent, 1)
	c.OnKicked(func(e KickedEvent) { kicked <- e })
	disconnected := make(chan error, 1)
	c.OnDisconnected(func(err error) { disconnected <- err })

	c.handleClientLeftView(c.handler, wire.ParseCommand(
		`notifyclientleftview clid=5 reasonid=5 reasonmsg=behave invokerid=1 invokername=Admin`))

	if e := receive(t, kicked); e.Message != "behave" || e.InvokerName != "Admin" ||
		e.Reason != teamspeak.ReasonKickServer {
		t.Errorf("kicked event = %+v", e)
	}
	// Reported at once, with its cause, rather than a minute later as a
	// timeout with none.
	removed, ok := errors.AsType[*RemovedError](receive(t, disconnected))
	if !ok || removed.Reason != teamspeak.ReasonKickServer {
		t.Errorf("disconnected with %v, want a *RemovedError for the kick", removed)
	}
	if c.Status() != StatusDisconnected {
		t.Errorf("status = %v, want StatusDisconnected", c.Status())
	}
	if DefaultShouldRetry(removed, 1) {
		t.Error("the default policy retries a server kick")
	}
}

func TestHandleClientLeftView_ServerStop_EndsTheSessionAndIsRetried(t *testing.T) {
	c := connectedTestClient(t)
	kicked := make(chan KickedEvent, 1)
	c.OnKicked(func(e KickedEvent) { kicked <- e })
	disconnected := make(chan error, 1)
	c.OnDisconnected(func(err error) { disconnected <- err })

	c.handleClientLeftView(c.handler, wire.ParseCommand(`notifyclientleftview clid=5 reasonid=11 reasonmsg=restart`))

	err := receive(t, disconnected)
	if !DefaultShouldRetry(err, 1) {
		t.Errorf("the default policy gives up on %v; a stopped server comes back", err)
	}
	settle(t, c)
	select {
	case e := <-kicked:
		t.Errorf("a server shutdown reported as a kick: %+v", e)
	default:
	}
}

func TestHandleClientMoved_ChannelKickOfSelf_TriggersKicked(t *testing.T) {
	c := connectedTestClient(t)
	kicked := make(chan KickedEvent, 1)
	c.OnKicked(func(e KickedEvent) { kicked <- e })

	c.handleClientMoved(wire.ParseCommand(
		`notifyclientmoved clid=5 ctid=1 reasonid=4 reasonmsg=out invokerid=1 invokername=Admin`))

	if e := receive(t, kicked); e.Reason != teamspeak.ReasonKickChannel || e.Message != "out" {
		t.Errorf("kicked event = %+v", e)
	}
	if c.Status() != StatusConnected {
		t.Errorf("status = %v; a channel kick does not end the session", c.Status())
	}
}

func TestHandleClientLeftView_OthersLeaving_NoKickedCallback(t *testing.T) {
	c := connectedTestClient(t)
	kicked := make(chan KickedEvent, 1)
	c.OnKicked(func(e KickedEvent) { kicked <- e })

	c.handleClientLeftView(c.handler, wire.ParseCommand("notifyclientleftview clid=6 reasonid=5 reasonmsg="))
	settle(t, c)

	select {
	case <-kicked:
		t.Error("another client's kick reported as ours")
	default:
	}
	if c.Status() != StatusConnected {
		t.Errorf("status = %v after another client left", c.Status())
	}
}

func TestHandleClientMoved_UpdatesChannelID(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clients[3] = teamspeak.ClientInfo{ID: 3, ChannelID: 10}
	c.mu.Unlock()

	const moveCmd = "notifyclientmoved clid=3 ctid=20 reasonid=0" +
		" invokerid=1 invokername=Admin invokeruid=admin"
	c.handleClientMoved(wire.ParseCommand(moveCmd))

	c.mu.Lock()
	info := c.clients[3]
	c.mu.Unlock()

	if info.ChannelID != 20 {
		t.Errorf("expected channelID=20, got %d", info.ChannelID)
	}
}

func TestHandleClientMoved_TriggersCallback(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clients[3] = teamspeak.ClientInfo{ID: 3}
	c.mu.Unlock()

	moved := make(chan ClientMovedEvent, 1)
	c.OnClientMoved(func(e ClientMovedEvent) { moved <- e })

	const moveCmd2 = "notifyclientmoved clid=3 ctid=20 reasonid=0" +
		" invokerid=1 invokername=Admin invokeruid=admin"
	c.handleClientMoved(wire.ParseCommand(moveCmd2))

	select {
	case e := <-moved:
		if e.ClientID != 3 || e.TargetChannelID != 20 {
			t.Errorf("unexpected event: %+v", e)
		}
	case <-time.After(time.Second):
		t.Error("OnClientMoved callback not called")
	}
}

func TestHandleTextMessage_CallsCallback(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clients[2] = teamspeak.ClientInfo{ID: 2, UID: "invokeruid"}
	c.mu.Unlock()

	msgs := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { msgs <- m })

	cmd := wire.ParseCommand(
		"notifytextmessage targetmode=1 target=7 invokerid=2 " +
			"invokername=Bob invokeruid=notifyuid msg=hello",
	)
	c.handleTextMessage(cmd)

	select {
	case m := <-msgs:
		if m.Message != "hello" {
			t.Errorf("expected 'hello', got %q", m.Message)
		}
		if m.TargetID != 7 {
			t.Errorf("expected TargetID 7, got %d", m.TargetID)
		}
		if m.InvokerUID != "notifyuid" {
			t.Errorf("expected InvokerUID from notify payload, got %q", m.InvokerUID)
		}
	case <-time.After(time.Second):
		t.Error("OnTextMessage not called")
	}
}

func TestHandleTextMessage_FallbackToClientCacheUID(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clients[99] = teamspeak.ClientInfo{ID: 99, UID: "cacheduid"}
	c.mu.Unlock()

	msgs := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { msgs <- m })

	cmd := wire.ParseCommand("notifytextmessage targetmode=2 invokerid=99 invokername=Unknown msg=hi")
	c.handleTextMessage(cmd)

	select {
	case m := <-msgs:
		if m.InvokerUID != "cacheduid" {
			t.Errorf("expected cached UID fallback, got %q", m.InvokerUID)
		}
		if m.TargetID != 0 {
			t.Errorf("expected zero TargetID when target missing, got %d", m.TargetID)
		}
	case <-time.After(time.Second):
		t.Error("OnTextMessage not called")
	}
}

func TestHandleTextMessage_MissingInvoker_NoUID(t *testing.T) {
	c := newTestClient(t)

	msgs := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(m TextMessageEvent) { msgs <- m })

	cmd := wire.ParseCommand("notifytextmessage targetmode=2 invokerid=99 invokername=Unknown msg=hi")
	c.handleTextMessage(cmd)

	select {
	case m := <-msgs:
		if m.InvokerUID != "" {
			t.Errorf("expected empty UID for unknown invoker, got %q", m.InvokerUID)
		}
	case <-time.After(time.Second):
		t.Error("OnTextMessage not called")
	}
}

func TestHandleClientPoke_TriggersCallback(t *testing.T) {
	c := newTestClient(t)

	poked := make(chan PokeEvent, 1)
	c.OnPoked(func(e PokeEvent) { poked <- e })

	cmd := wire.ParseCommand(
		"notifyclientpoke invokerid=5 invokername=Alice invokeruid=uid123 msg=hello",
	)
	c.handleClientPoke(cmd)

	select {
	case e := <-poked:
		if e.InvokerID != 5 {
			t.Errorf("expected InvokerID 5, got %d", e.InvokerID)
		}
		if e.InvokerName != "Alice" {
			t.Errorf("expected InvokerName 'Alice', got %q", e.InvokerName)
		}
		if e.InvokerUID != "uid123" {
			t.Errorf("expected InvokerUID 'uid123', got %q", e.InvokerUID)
		}
		if e.Message != "hello" {
			t.Errorf("expected Message 'hello', got %q", e.Message)
		}
	case <-time.After(time.Second):
		t.Error("OnPoked callback not called")
	}
}

func TestHandleClientPoke_EmptyMessage(t *testing.T) {
	c := newTestClient(t)

	poked := make(chan PokeEvent, 1)
	c.OnPoked(func(e PokeEvent) { poked <- e })

	cmd := wire.ParseCommand(
		"notifyclientpoke invokerid=3 invokername=Bob invokeruid=uid456 msg=",
	)
	c.handleClientPoke(cmd)

	select {
	case e := <-poked:
		if e.Message != "" {
			t.Errorf("expected empty message, got %q", e.Message)
		}
	case <-time.After(time.Second):
		t.Error("OnPoked callback not called")
	}
}

func TestHandleNotification_DispatchesPoke(t *testing.T) {
	c := newTestClient(t)

	poked := make(chan PokeEvent, 1)
	c.OnPoked(func(e PokeEvent) { poked <- e })

	cmd := wire.ParseCommand(
		"notifyclientpoke invokerid=5 invokername=Alice invokeruid=uid123 msg=hey",
	)
	c.handleNotification(c.handler, cmd)

	select {
	case e := <-poked:
		if e.Message != "hey" {
			t.Errorf("expected 'hey', got %q", e.Message)
		}
	case <-time.After(time.Second):
		t.Error("poke not dispatched through handleNotification")
	}
}

func TestHandleNotification_UnknownNotification_NoError(t *testing.T) {
	c := newTestClient(t)
	cmd := wire.ParseCommand("notifyunknowncommand foo=bar")
	c.handleNotification(c.handler, cmd)
}

// The server renames the client while a caller may be logging it; run with
// -race, String and LogValue must not read the nickname unguarded.
func TestClientDescriptionDoesNotRaceARename(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 7
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			cmd := fmt.Sprintf("notifycliententerview clid=7 client_nickname=TestBot%d"+
				" ctid=1 client_type=0 client_servergroups= client_unique_identifier=x", i)
			c.handleClientEnterView(c.handler, wire.ParseCommand(cmd))
		}
	}()
	for range 50 {
		_ = c.String()
		_ = c.LogValue().Resolve()
	}
	<-done
	if got := c.String(); !strings.Contains(got, `"TestBot49"`) {
		t.Errorf("String() = %s, want the latest nickname", got)
	}
}
