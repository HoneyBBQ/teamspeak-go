package serverquery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// connected is a client that has finished the handshake, with the transport it
// is on: the whoami the handshake reads answers client id 7.
func connected(t *testing.T, d *fakeDialer, opts ...Option) (*Client, *fakeTransport) {
	t.Helper()
	c := newClient(t, d, opts...)
	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return c, transport
}

// run calls fn on its own goroutine and returns what it will report.
func run(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()

	return done
}

// expect reads the next line the client sends, which must start with prefix.
func expect(t *testing.T, d *fakeDialer, prefix string) string {
	t.Helper()
	line, ok := d.nextWithin(t)
	if !ok || !strings.HasPrefix(line, prefix) {
		t.Fatalf("the client sent %q (sent at all: %t), want a line starting %q", line, ok, prefix)
	}

	return line
}

func finish(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(eventWait):
		t.Fatal("the command did not return")

		return nil
	}
}

func (c *Client) knownSelf() (teamspeak.ClientID, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.selfID, len(c.clients)
}

// knownClient is the roster's record of a client.
func (c *Client) knownClient(id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.clients[id]

	return entry, ok
}

// awaitRoster polls until the roster's record of id satisfies ok: a
// notification reaches it on the reader's goroutine, after the test sent it.
func awaitRoster(t *testing.T, c *Client, id teamspeak.ClientID, ok func(teamspeak.ClientEntry, bool) bool) {
	t.Helper()
	deadline := time.Now().Add(eventWait)
	for {
		entry, found := c.knownClient(id)
		if ok(entry, found) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the roster's record of %d is %+v (known: %t)", id, entry, found)
		}
		time.Sleep(time.Millisecond)
	}
}

// A clientlist row names the channel cid, where an enter notification names it
// ctid, so the roster reads both. The row is the shape the server answers with.
func TestUse_RosterHoldsTheChannelAListRowNames(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	done := run(func() error { return c.Use(context.Background(), ByID(2), UseOptions{}) })
	expect(t, d, "use")
	transport.reply("error id=0 msg=ok")
	expect(t, d, "whoami")
	transport.reply("client_id=9", "error id=0 msg=ok")
	expect(t, d, "clientlist")
	transport.reply(
		"clid=9 cid=1 client_database_id=2 client_nickname=bot client_type=1 "+
			"client_unique_identifier=botuid= client_servergroups=2|"+
			"clid=5 cid=3 client_database_id=14 client_nickname=Ann client_type=0 "+
			"client_unique_identifier=annuid= client_servergroups=6,9",
		"error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	if entry, ok := c.knownClient(5); !ok || entry.ChannelID != 3 || entry.Nickname != "Ann" {
		t.Fatalf("roster holds %+v (known: %t), want Ann in channel 3", entry, ok)
	}
	if entry, ok := c.knownClient(9); !ok || entry.ChannelID != 1 {
		t.Errorf("roster holds %+v (known: %t), want the query client in channel 1", entry, ok)
	}

	// A move updates the record, and a leave drops it.
	transport.lines <- `notifyclientmoved cfid=3 clid=5 ctid=6 reasonid=1 invokerid=2 invokername=a invokeruid=u`
	awaitRoster(t, c, 5, func(e teamspeak.ClientEntry, ok bool) bool { return ok && e.ChannelID == 6 })
	transport.lines <- `notifyclientleftview cfid=6 clid=5 ctid=0 reasonid=8 reasonmsg=Shutdown`
	awaitRoster(t, c, 5, func(_ teamspeak.ClientEntry, ok bool) bool { return !ok })
}

func TestLogin_SendsTheLoginEscaped(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	done := run(func() error { return c.Login(context.Background(), "serveradmin", "p w") })
	line := expect(t, d, "login")
	if want := `login client_login_name=serveradmin client_login_password=p\sw`; line != want {
		t.Errorf("sent %q, want %q", line, want)
	}
	transport.reply("error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Errorf("Login: %v", err)
	}

	// A refusal is the server's, as it is at Connect.
	done = run(func() error { return c.Login(context.Background(), "serveradmin", "wrong") })
	expect(t, d, "login")
	transport.reply("error id=520 msg=invalid\\sloginname\\sor\\spassword")
	err = finish(t, done)
	if !errors.Is(err, errcode.ClientInvalidPassword) {
		t.Errorf("a refused Login: %v, want 520", err)
	}
}

// Logout leaves the client on no server, so the id it read for the one it was
// on, and the clients it had seen there, are no longer true.
func TestLogout_ForgetsTheServer(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)
	if id, seen := c.knownSelf(); id != 7 || seen != 1 {
		t.Fatalf("before Logout: self %d, %d clients seen, want 7 and 1", id, seen)
	}

	done := run(func() error { return c.Logout(context.Background()) })
	if line := expect(t, d, "logout"); line != "logout" {
		t.Errorf("sent %q", line)
	}
	transport.reply("error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if id, seen := c.knownSelf(); id != 0 || seen != 0 {
		t.Errorf("after Logout: self %d, %d clients seen, want none", id, seen)
	}
}

// A Logout the server refuses changes nothing: the client is still where it was.
func TestLogout_RefusedKeepsTheSelf(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	done := run(func() error { return c.Logout(context.Background()) })
	expect(t, d, "logout")
	transport.reply("error id=5120 msg=out\\sof\\sscope")
	err := finish(t, done)
	if err == nil {
		t.Fatal("a refused Logout returned nil")
	}
	if id, _ := c.knownSelf(); id != 7 {
		t.Errorf("after a refused Logout: self %d, want 7", id)
	}
}

// Use reads the id the new server gave the connection, drops the clients it
// had seen, and — the client being configured with events — reads the new
// server's list.
func TestUse_ReadsTheNewSelf(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	done := run(func() error {
		return c.Use(context.Background(), ByID(2), UseOptions{Nickname: "second bot"})
	})
	if line := expect(t, d, "use"); line != `use sid=2 client_nickname=second\sbot` {
		t.Errorf("sent %q", line)
	}
	transport.reply("error id=0 msg=ok")
	expect(t, d, "whoami")
	transport.reply("client_id=9 client_nickname=second\\sbot", "error id=0 msg=ok")
	expect(t, d, "clientlist")
	transport.reply("clid=9 client_nickname=second\\sbot client_servergroups=6", "error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if id, seen := c.knownSelf(); id != 9 || seen != 1 {
		t.Errorf("after Use: self %d, %d clients seen, want 9 and 1", id, seen)
	}
}

func TestUse_ByPortWithoutEventsReadsNoList(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d, WithoutEvents())

	done := run(func() error { return c.Use(context.Background(), ByPort(9988), UseOptions{}) })
	if line := expect(t, d, "use"); line != "use port=9988" {
		t.Errorf("sent %q", line)
	}
	transport.reply("error id=0 msg=ok")
	expect(t, d, "whoami")
	transport.reply("client_id=9", "error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if line, ok := nextWithin(t, transport, handshakeIdle); ok {
		t.Errorf("a client with no events also sent %q", line)
	}
}

// The server drops the earlier selection when it refuses a Use, so the id the
// client holds for it is gone too, and nothing more is read.
func TestUse_RefusedLeavesNoServer(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	done := run(func() error { return c.Use(context.Background(), ByID(99), UseOptions{}) })
	expect(t, d, "use")
	transport.reply("error id=1033 msg=server\\sis\\snot\\srunning")
	err := finish(t, done)
	if !errors.Is(err, errcode.ServerIsNotRunning) {
		t.Fatalf("Use of a stopped server: %v, want 1033", err)
	}
	if id, seen := c.knownSelf(); id != 0 || seen != 0 {
		t.Errorf("after a refused Use: self %d, %d clients seen, want none", id, seen)
	}
	if line, ok := nextWithin(t, transport, handshakeIdle); ok {
		t.Errorf("a refused Use was followed by %q", line)
	}
}

// A selector that names nothing, or two servers, never reaches the server.
func TestUse_RefusesASelectorThatNamesNoOneServer(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	for name, selector := range map[string]ServerSelector{
		"nothing": {},
		"both":    {target: serverTarget{id: 1, port: 9987}},
	} {
		err := c.Use(context.Background(), selector, UseOptions{})
		if !errors.Is(err, teamspeak.ErrInvalidCommand) {
			t.Errorf("%s: err = %v, want ErrInvalidCommand", name, err)
		}
	}
	if line, ok := nextWithin(t, transport, handshakeIdle); ok {
		t.Errorf("sent %q for a selector that names no one server", line)
	}
}

func TestRegisterNotifications_SendsTheCategoryAndReadsTheList(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d, WithoutEvents())

	all := teamspeak.ChannelID(0)
	for _, tc := range []struct {
		opts NotificationOptions
		cat  Category
		want string
	}{
		{NotificationOptions{}, CategoryTextServer, "servernotifyregister event=textserver"},
		{NotificationOptions{ChannelID: &all}, CategoryChannel, "servernotifyregister event=channel id=0"},
	} {
		done := run(func() error { return c.RegisterNotifications(context.Background(), tc.cat, tc.opts) })
		if line := expect(t, d, "servernotifyregister"); line != tc.want {
			t.Errorf("sent %q, want %q", line, tc.want)
		}
		transport.reply("error id=0 msg=ok")
		expect(t, d, "clientlist")
		transport.reply("clid=7 client_nickname=bot", "error id=0 msg=ok")
		err := finish(t, done)
		if err != nil {
			t.Errorf("RegisterNotifications(%s): %v", tc.cat, err)
		}
	}

	// A refused registration reads nothing and reports the server's answer.
	done := run(func() error {
		return c.RegisterNotifications(context.Background(), CategoryBans, NotificationOptions{})
	})
	expect(t, d, "servernotifyregister")
	transport.reply("error id=1539 msg=parameter\\snot\\sfound")
	err := finish(t, done)
	if err == nil {
		t.Error("a refused registration returned nil")
	}
	if line, ok := nextWithin(t, transport, handshakeIdle); ok {
		t.Errorf("a refused registration was followed by %q", line)
	}
}

func TestUnregisterNotifications_SendsWhatIsAsked(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d)

	channel := teamspeak.ChannelID(5)
	for _, tc := range []struct {
		opts UnregisterNotificationsOptions
		want string
	}{
		{UnregisterNotificationsOptions{}, "servernotifyunregister"},
		{UnregisterNotificationsOptions{Category: CategoryBans}, "servernotifyunregister event=bans"},
		{
			UnregisterNotificationsOptions{Category: CategoryChannel, ChannelID: &channel},
			"servernotifyunregister event=channel id=5",
		},
	} {
		done := run(func() error { return c.UnregisterNotifications(context.Background(), tc.opts) })
		if line := expect(t, d, "servernotifyunregister"); line != tc.want {
			t.Errorf("sent %q, want %q", line, tc.want)
		}
		transport.reply("error id=0 msg=ok")
		err := finish(t, done)
		if err != nil {
			t.Errorf("UnregisterNotifications: %v", err)
		}
	}
}

// Every one of them needs a connection.
func TestSessionCommands_WithoutAConnection(t *testing.T) {
	c := newClient(t, newFakeDialer(true))
	ctx := context.Background()

	for name, err := range map[string]error{
		"Login":                   c.Login(ctx, "a", "b"),
		"Logout":                  c.Logout(ctx),
		"Use":                     c.Use(ctx, ByID(1), UseOptions{}),
		"RegisterNotifications":   c.RegisterNotifications(ctx, CategoryServer, NotificationOptions{}),
		"UnregisterNotifications": c.UnregisterNotifications(ctx, UnregisterNotificationsOptions{}),
	} {
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("%s: err = %v, want ErrNotConnected", name, err)
		}
	}
}

// A reconnect starts over from the options given to New. It does not repeat
// the Use made by hand: the session returns to the server it was configured
// for.
func TestReconnect_StartsOverFromTheOptions(t *testing.T) {
	d := newFakeDialer(true)
	c, transport := connected(t, d, WithServer(1), WithReconnect(teamspeak.ReconnectOptions{
		Backoff: teamspeak.BackoffPolicy{InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, Jitter: -1},
	}))

	done := run(func() error { return c.Use(context.Background(), ByID(2), UseOptions{}) })
	expect(t, d, "use")
	transport.reply("error id=0 msg=ok")
	expect(t, d, "whoami")
	transport.reply("client_id=9", "error id=0 msg=ok")
	expect(t, d, "clientlist")
	transport.reply("clid=9 client_nickname=bot", "error id=0 msg=ok")
	err := finish(t, done)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	transport.closeErr = errReset
	_ = transport.Close()

	// The first connection can still be queued on d.opened: Connect took it
	// from the dialer directly when the open had already happened.
	second := nextConnection(t, d, transport)
	var sent []string
	deadline := time.After(eventWait)
	for !containsSubstring(sent, "clientlist") {
		select {
		case line := <-second.sent:
			sent = append(sent, line)
			name, _, _ := strings.Cut(line, " ")
			switch name {
			case "version":
				second.reply("version=3.13.8 build=1 platform=Linux", "error id=0 msg=ok")
			case "whoami":
				second.reply("client_id=11", "error id=0 msg=ok")
			default:
				second.reply("error id=0 msg=ok")
			}
		case <-deadline:
			t.Fatalf("the reconnect never finished its handshake: %v", sent)
		}
	}
	if !containsSubstring(sent, "use sid=1") || containsSubstring(sent, "sid=2") {
		t.Errorf("the reconnect sent %v, want the configured server 1 and not the one Use chose", sent)
	}
}

// nextConnection waits for a connection the client opens after first.
func nextConnection(t *testing.T, d *fakeDialer, first *fakeTransport) *fakeTransport {
	t.Helper()
	deadline := time.After(eventWait)
	for {
		select {
		case tr := <-d.opened:
			if tr != first {
				return tr
			}
		case <-deadline:
			t.Fatal("the client did not reconnect")

			return nil
		}
	}
}
