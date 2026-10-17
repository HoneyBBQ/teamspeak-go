package serverquery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// The failures a test can make a transport report, named so the assertion can
// match on the same value the client wrapped.
var (
	errDialRefused = errors.New("connection refused")
	errReset       = errors.New("connection reset")
)

// fakeTransport records what is sent and answers from a script.
type fakeTransport struct {
	closeErr error
	sent     chan string
	lines    chan string
	closed   chan struct{}
	all      []string
	closeOne sync.Once
	mu       sync.Mutex
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		sent:   make(chan string, 64),
		lines:  make(chan string, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeTransport) WriteLine(_ context.Context, line string) error {
	f.mu.Lock()
	f.all = append(f.all, line)
	f.mu.Unlock()
	f.sent <- line

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
	f.closeOne.Do(func() { close(f.closed) })

	return nil
}

// reply sends the lines of one answer, as a raw server would.
func (f *fakeTransport) reply(lines ...string) {
	for _, line := range lines {
		f.lines <- line
	}
}

func (f *fakeTransport) sentLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.all...)
}

// handshakeIdle is how long answer waits for a further handshake command
// before deciding the handshake is over. Every command it handles is answered
// over an in-memory channel in microseconds, so the wait only ever bounds the
// look for one that never comes; a line that does arrive in the window is not
// lost, it goes back on the dialer's pending list for the test.
const handshakeIdle = 250 * time.Millisecond

// eventWait bounds a wait for something the client should send or deliver
// promptly.
const eventWait = 2 * time.Second

// handshakeCommands are the commands Connect sends. answer replies to these
// and stops at the first that is not one, so a test can drive the session
// afterwards without racing it.
var handshakeCommands = map[string]bool{
	"login": true, "use": true, "clientupdate": true,
	"version": true, "whoami": true,
	"servernotifyregister": true, "servernotifyregisterbans": true,
	"clientlist": true,
}

// fakeDialer is a Dialer whose connections come from the test. Each open
// publishes the transport it made, so the test can drive it: open runs on
// Connect's goroutine, so the transport is held under the mutex rather than in
// a plain field.
type fakeDialer struct {
	openErr     error
	validateErr error
	opened      chan *fakeTransport
	tr          *fakeTransport
	account     *login
	pending     []string
	mu          sync.Mutex
	notify      bool
	quit        bool
}

func newFakeDialer(notify bool) *fakeDialer {
	return &fakeDialer{notify: notify, opened: make(chan *fakeTransport, 8)}
}

func (d *fakeDialer) SupportsNotifications() bool { return d.notify }
func (d *fakeDialer) String() string              { return "fake" }
func (d *fakeDialer) credentials() *login         { return d.account }
func (d *fakeDialer) needsQuit() bool             { return d.quit }

// validate accepts the dialer unless the test wants it refused.
func (d *fakeDialer) validate() error { return d.validateErr }

func (d *fakeDialer) open(_ context.Context) (engine.Transport, error) {
	if d.openErr != nil {
		return nil, d.openErr
	}
	transport := newFakeTransport()
	d.mu.Lock()
	d.tr = transport
	d.mu.Unlock()
	d.opened <- transport

	return transport, nil
}

// transport returns the connection the client opened, waiting for it if the
// open has not happened yet.
func (d *fakeDialer) transport(t *testing.T) *fakeTransport {
	t.Helper()
	d.mu.Lock()
	tr := d.tr
	d.mu.Unlock()
	if tr != nil {
		return tr
	}
	select {
	case tr = <-d.opened:
		return tr
	case <-time.After(2 * time.Second):
		t.Fatal("the client did not open a connection")

		return nil
	}
}

// nextWithin waits for the next line the client sends, taking one that answer
// read back first.
func (d *fakeDialer) nextWithin(t *testing.T) (string, bool) {
	t.Helper()
	d.mu.Lock()
	if len(d.pending) > 0 {
		line := d.pending[0]
		d.pending = d.pending[1:]
		d.mu.Unlock()

		return line, true
	}
	d.mu.Unlock()

	return nextWithin(t, d.transport(t), eventWait)
}

// answer runs the handshake replies a successful Connect needs, in the order
// the client sends the commands, and returns once it has sent them all.
// answer replies to the handshake's commands, each of which waits for its
// answer before the next is sent, and stops at the first command that is not
// one of them. It returns the transport it drove.
func (d *fakeDialer) answer(t *testing.T) *fakeTransport {
	t.Helper()
	transport := d.transport(t)
	for {
		line, ok := nextWithin(t, transport, handshakeIdle)
		if !ok {
			// Nothing more is coming: the handshake is done.
			break
		}
		name, _, _ := strings.Cut(line, " ")
		if !handshakeCommands[name] {
			// The handshake is over: the test drives from here.
			d.mu.Lock()
			d.pending = append(d.pending, line)
			d.mu.Unlock()

			return transport
		}
		switch name {
		case "version":
			transport.reply("version=3.13.8 build=1 platform=Linux", "error id=0 msg=ok")
		case "whoami":
			transport.reply("client_id=7 client_nickname=bot", "error id=0 msg=ok")
		case "clientlist":
			transport.reply("clid=7 client_nickname=bot client_servergroups=6", "error id=0 msg=ok")
		default:
			// The other handshake commands answer with a bare ok, as the
			// server does.
			transport.reply("error id=0 msg=ok")
		}
	}

	return transport
}

func nextWithin(t *testing.T, transport *fakeTransport, d time.Duration) (string, bool) {
	t.Helper()
	select {
	case line := <-transport.sent:
		return line, true
	case <-time.After(d):
		return "", false
	}
}

func newClient(t *testing.T, d Dialer, opts ...Option) *Client {
	t.Helper()
	c, err := New(d, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	return c
}

// The handshake runs in the order the server requires, and a client that is
// told to log in sends it first.
func TestConnect_RunsTheHandshakeInOrder(t *testing.T) {
	d := &fakeDialer{notify: true, quit: true, opened: make(chan *fakeTransport, 8),
		account: &login{name: "serveradmin", password: "pw"}}
	c := newClient(t, d, WithServer(1), WithNickname("bot"))

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	sent := transport.sentLines()
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	names := commandNames(sent)
	want := []string{
		"login", "use", "clientupdate", "version", "whoami",
		"servernotifyregister", "servernotifyregister", "servernotifyregister",
		"servernotifyregister", "servernotifyregister", "clientlist",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("command order = %v, want %v", names, want)
	}
	// The login carries the account, and the nickname goes after use, which
	// the server refuses it before.
	if !strings.Contains(sent[0], "client_login_name=serveradmin") {
		t.Errorf("login sent %q", sent[0])
	}
	if !strings.Contains(sent[1], "sid=1") {
		t.Errorf("use sent %q", sent[1])
	}
	if !strings.Contains(sent[2], "client_nickname=bot") {
		t.Errorf("clientupdate sent %q", sent[2])
	}
}

// The five categories both servers accept are registered without being asked
// for, and bans is not among them.
func TestConnect_RegistersTheDefaultCategories(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	sent := transport.sentLines()
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var events []string
	for _, line := range sent {
		if strings.HasPrefix(line, "servernotifyregister") {
			events = append(events, line)
		}
	}
	if len(events) != 5 {
		t.Fatalf("registered %d categories, want 5: %v", len(events), events)
	}
	for _, banned := range []string{"event=bans", "event=server", "event=textprivate"} {
		if banned == "event=bans" && containsSubstring(events, banned) {
			t.Errorf("bans was registered without being asked for: %v", events)
		}
		if banned != "event=bans" && !containsSubstring(events, banned) {
			t.Errorf("%s was not registered: %v", banned, events)
		}
	}
}

// bans is registered only when it is named.
func TestWithEvents_RegistersBansWhenAsked(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d, WithEvents(CategoryBans))

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	sent := transport.sentLines()
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if !containsSubstring(sent, "event=bans") {
		t.Errorf("bans was asked for and not registered: %v", sent)
	}
}

// WithoutEvents connects and runs commands with nothing registered.
func TestWithoutEvents_RegistersNothing(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d, WithoutEvents())

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	sent := transport.sentLines()
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if containsSubstring(sent, "servernotifyregister") {
		t.Errorf("a category was registered with events off: %v", sent)
	}
}

// Over WebQuery, WithEvents is a configuration that cannot be honoured, so New
// refuses it rather than connecting and silently delivering nothing.
func TestNew_RefusesEventsOverATransportThatCannotDeliverThem(t *testing.T) {
	_, err := New(newFakeDialer(false), WithEvents(CategoryServer))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New = %v, want ErrInvalidConfig", err)
	}

	// Without asking for events, the same transport is fine.
	_, err = New(newFakeDialer(false))
	if err != nil {
		t.Errorf("New without events = %v, want it accepted", err)
	}
	// And WithoutEvents is accepted as well.
	_, err = New(newFakeDialer(false), WithoutEvents())
	if err != nil {
		t.Errorf("New with WithoutEvents = %v, want it accepted", err)
	}
}

// A configuration the server would refuse is refused up front.
func TestNew_RefusesAConfigurationTheTransportCannotServe(t *testing.T) {
	// A login with no name.
	_, err := New(TCPLogin("127.0.0.1:1", "", "pw"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("TCPLogin without a name: New = %v, want ErrInvalidConfig", err)
	}
	_, err = New(TCPLogin("127.0.0.1:1", "serveradmin", ""))
	if err != nil {
		t.Errorf("TCPLogin with an empty password: New = %v, want it accepted", err)
	}
	// The password stays out of the name a log line shows.
	if got := TCPLogin("127.0.0.1:1", "serveradmin", "s3cret").String(); strings.Contains(got, "s3cret") {
		t.Errorf("String = %q, it holds the password", got)
	}

	// Both a server and a port names one server two ways.
	_, err = New(newFakeDialer(true), WithServer(1), WithServerPort(9987))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with both a server and a port = %v, want ErrInvalidConfig", err)
	}
	// A zero id names no server.
	_, err = New(newFakeDialer(true), WithServer(0))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with a zero server id = %v, want ErrInvalidConfig", err)
	}
	// A nil dialer is refused rather than panicking later.
	_, err = New(nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
}

// A refused login is the server's own error and Connect returns it.
func TestConnect_ReturnsARefusedLogin(t *testing.T) {
	d := &fakeDialer{notify: true, opened: make(chan *fakeTransport, 8),
		account: &login{name: "serveradmin", password: "wrong"}}
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	line, ok := d.nextWithin(t)
	transport := d.transport(t)
	if !ok || !strings.HasPrefix(line, "login") {
		t.Fatalf("expected login first, got %q", line)
	}
	transport.reply(`error id=520 msg=invalid\sloginname\sor\spassword`)

	err := <-done
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != 520 {
		t.Fatalf("Connect = %v, want the server's 520", err)
	}
	if !strings.Contains(err.Error(), "login") {
		t.Errorf("the error does not say which step failed: %v", err)
	}
	if got := c.Status(); got != teamspeak.StatusDisconnected {
		t.Errorf("status after a failed connect = %v, want disconnected", got)
	}
}

// A transport that cannot be dialled reports the reason and leaves the client
// ready to try again.
func TestConnect_ReportsADialFailure(t *testing.T) {
	sentinel := errDialRefused
	d := &fakeDialer{notify: true, openErr: fmt.Errorf("%w: %w", ErrDial, sentinel), opened: make(chan *fakeTransport, 8)}
	c := newClient(t, d)

	// Events are delivered on their own goroutine, so the handler has to be
	// there before Connect fails or the event can be gone by the time it is.
	heard := make(chan teamspeak.DisconnectedEvent, 1)
	c.OnDisconnected(func(e teamspeak.DisconnectedEvent) { heard <- e })

	err := c.Connect(context.Background())
	if !errors.Is(err, ErrDial) || !errors.Is(err, sentinel) {
		t.Fatalf("Connect = %v, want ErrDial wrapping the cause", err)
	}
	if got := c.Status(); got != teamspeak.StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}
	// The failure is reported once, as a disconnected event with no reconnect.
	var got teamspeak.DisconnectedEvent
	select {
	case got = <-heard:
	case <-time.After(2 * time.Second):
		t.Fatal("no disconnected event was delivered")
	}
	if !errors.Is(got.Err, sentinel) || got.WillReconnect {
		t.Errorf("disconnected event = %+v, want the cause and no reconnect", got)
	}
}

// Connect on a client that is already connected is refused rather than
// starting a second session.
func TestConnect_RefusesAConnectedClient(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	err = c.Connect(context.Background())
	if !errors.Is(err, teamspeak.ErrAlreadyConnected) {
		t.Errorf("second Connect = %v, want ErrAlreadyConnected", err)
	}
}

// A client whose transport cannot deliver events still connects, and its On…
// methods for server events are inert rather than failing.
func TestNoEventsTransport_ConnectSucceedsAndInertHandlersDoNotPanic(t *testing.T) {
	d := newFakeDialer(false)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	called := false
	remove := c.OnTextMessage(func(teamspeak.TextMessageEvent) { called = true })
	remove()
	if called {
		t.Error("a handler fired over a transport with no events")
	}
	// The lifecycle events still work.
	if got := c.Status(); got != teamspeak.StatusConnected {
		t.Errorf("status = %v, want connected", got)
	}
}

// A connected event is delivered, and a reconnect's carries Reconnected.
func TestConnect_DeliversConnected(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	got := make(chan teamspeak.ConnectedEvent, 1)
	c.OnConnected(func(e teamspeak.ConnectedEvent) { got <- e })

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	select {
	case e := <-got:
		if e.Reconnected {
			t.Error("a caller's Connect reported a reconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connected was never delivered")
	}
}

// A text message is read into the event, with the sender's groups filled in
// from what the client knows.
func TestNotification_TextMessageIsDelivered(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	got := make(chan teamspeak.TextMessageEvent, 1)
	c.OnTextMessage(func(e teamspeak.TextMessageEvent) { got <- e })

	// The sender is the client the list carried, with its groups.
	transport.lines <- `notifytextmessage targetmode=2 target=7 invokerid=7 invokername=bot invokeruid=u msg=hi`

	select {
	case e := <-got:
		if e.Message != "hi" || e.TargetMode != teamspeak.TextMessageTarget(2) {
			t.Errorf("event = %+v, want the message and its target mode", e)
		}
		if e.InvokerGroups == nil || len(e.InvokerGroups) != 1 || e.InvokerGroups[0] != 6 {
			t.Errorf("invoker groups = %v, want [6] from the client list", e.InvokerGroups)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the text message was never delivered")
	}
}

// Every notification reaches OnNotification as the server sent it, modelled or
// not, and the unmodelled one reaches it alone.
func TestNotification_EveryNotificationIsDelivered(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	got := make(chan teamspeak.NotificationEvent, 2)
	c.OnNotification(func(e teamspeak.NotificationEvent) { got <- e })

	transport.lines <- `notifychanneledited cid=1 reasonid=1`
	transport.lines <- `notifytextmessage targetmode=3 invokerid=7 msg=hey`

	for _, want := range []string{"notifychanneledited", "notifytextmessage"} {
		select {
		case e := <-got:
			if e.Name != want {
				t.Errorf("notification = %q, want %q", e.Name, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was never delivered", want)
		}
	}
}

// A channel kick arrives as a move, and the client reports it as a kick while
// staying connected.
func TestNotification_ChannelKickIsReportedAsAKick(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	got := make(chan teamspeak.KickedEvent, 1)
	c.OnKicked(func(e teamspeak.KickedEvent) { got <- e })

	// clid 7 is this client, from whoami.
	transport.lines <- `notifyclientmoved clid=7 ctid=1 reasonid=4 reasonmsg=out`

	select {
	case e := <-got:
		if e.Reason != teamspeak.ReasonKickChannel {
			t.Errorf("reason = %v, want a channel kick", e.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the channel kick was never delivered")
	}
	if got := c.Status(); got != teamspeak.StatusConnected {
		t.Errorf("status = %v, want the connection to survive a channel kick", got)
	}
}

// Disconnect ends the session, tells the server to quit where it has a
// session, and reports a disconnected with no cause.
func TestDisconnect_QuitsAndReports(t *testing.T) {
	d := &fakeDialer{notify: true, quit: true, opened: make(chan *fakeTransport, 8)}
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	heard := make(chan teamspeak.DisconnectedEvent, 1)
	c.OnDisconnected(func(e teamspeak.DisconnectedEvent) { heard <- e })

	go func() {
		// quit is answered, so Disconnect does not wait out its timeout.
		line, _ := d.nextWithin(t)
		if strings.HasPrefix(line, "quit") {
			transport.reply("error id=0 msg=ok")
		}
	}()

	err = c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if got := c.Status(); got != teamspeak.StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}

	select {
	case e := <-heard:
		if e.Err != nil {
			t.Errorf("disconnected after Disconnect carried %v, want no cause", e.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnected was never delivered")
	}

	if !containsSubstring(transport.sentLines(), "quit") {
		t.Errorf("quit was not sent: %v", transport.sentLines())
	}
}

// A transport with no session to end is not told to quit.
func TestDisconnect_DoesNotQuitWhereThereIsNoSession(t *testing.T) {
	d := newFakeDialer(false)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	err = c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if containsSubstring(transport.sentLines(), "quit") {
		t.Errorf("quit was sent over a transport with no session: %v", transport.sentLines())
	}
}

// Disconnect on a client that never connected does nothing.
func TestDisconnect_DoesNothingWhenNotConnected(t *testing.T) {
	c := newClient(t, newFakeDialer(true))

	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("Disconnect = %v, want nothing", err)
	}
	if got := c.Status(); got != teamspeak.StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}
}

// Send runs the typed commands, which is what the whole package is for.
func TestSend_RunsATypedCommand(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	transport := d.transport(t)
	channels := make(chan []teamspeak.Channel, 1)
	failed := make(chan error, 1)
	go func() {
		got, err := c.ListChannels(context.Background(), teamspeak.ChannelListOptions{})
		if err != nil {
			failed <- err

			return
		}
		channels <- got
	}()

	line, _ := d.nextWithin(t)
	if !strings.HasPrefix(line, "channellist") {
		t.Fatalf("sent %q, want channellist", line)
	}
	transport.reply("cid=1 channel_name=Lobby", "error id=0 msg=ok")

	select {
	case got := <-channels:
		if len(got) != 1 || got[0].Name != "Lobby" {
			t.Errorf("channels = %+v, want the one channel", got)
		}
	case err := <-failed:
		t.Fatalf("ListChannels: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("ListChannels did not return")
	}
}

// A command middleware sees the typed commands and can answer them itself.
func TestSend_GoesThroughTheCommandMiddleware(t *testing.T) {
	d := newFakeDialer(true)
	var seen []string
	spy := func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			seen = append(seen, req.Command())

			return next.Send(ctx, req)
		})
	}
	c := newClient(t, d, WithCommandMiddleware(spy))

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	answered := make(chan struct{})
	go func() {
		_, _ = c.ListChannels(context.Background(), teamspeak.ChannelListOptions{})
		close(answered)
	}()
	transport := d.transport(t)
	line, ok := d.nextWithin(t)
	if !ok || !strings.HasPrefix(line, "channellist") {
		t.Fatalf("sent %q, want channellist", line)
	}
	transport.reply("error id=0 msg=ok")
	<-answered

	if !reflect.DeepEqual(seen, []string{"channellist"}) {
		t.Errorf("middleware saw %v, want [channellist]", seen)
	}
	// The handshake is the client's own, so it does not pass through it.
	for _, name := range seen {
		if name == "version" || name == "whoami" || name == "login" {
			t.Errorf("a handshake command reached the middleware: %v", seen)
		}
	}
}

// A connection that ends on its own is reported, and a client with no
// reconnect options stays down.
func TestConnectionDrop_IsReported(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	heard := make(chan teamspeak.DisconnectedEvent, 1)
	c.OnDisconnected(func(e teamspeak.DisconnectedEvent) { heard <- e })

	transport.closeErr = errReset
	_ = transport.Close()

	select {
	case e := <-heard:
		if e.Err == nil {
			t.Error("a drop was reported with no cause")
		}
		if e.WillReconnect {
			t.Error("a drop was reported as reconnecting with no reconnect options")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drop was never reported")
	}
	if got := c.Status(); got != teamspeak.StatusDisconnected {
		t.Errorf("status = %v, want disconnected", got)
	}
}

// Exec sends a raw line, which is the escape hatch the typed commands do not
// cover.
func TestExec_SendsARawLine(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	answered := make(chan []map[string]string, 1)
	go func() {
		rows, _ := c.Exec(context.Background(), "serverinfo")
		answered <- rows
	}()
	transport := d.transport(t)
	line, _ := d.nextWithin(t)
	if line != "serverinfo" {
		t.Fatalf("sent %q, want the line as given", line)
	}
	transport.reply("virtualserver_name=Test", "error id=0 msg=ok")

	if rows := <-answered; len(rows) != 1 || rows[0]["virtualserver_name"] != "Test" {
		t.Errorf("Exec = %v, want the row", rows)
	}
}

// Exec with no connection fails at once rather than waiting out a timeout.
func TestExec_WithoutAConnection(t *testing.T) {
	c := newClient(t, newFakeDialer(true))

	_, err := c.Exec(context.Background(), "serverinfo")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("Exec = %v, want ErrNotConnected", err)
	}
}

// WithLogger sends the logs to the caller's logger, which is how the no-events
// warning reaches anyone.
func TestNoEventsTransport_WarnsOncePerMethod(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d := newFakeDialer(false)
	c := newClient(t, d, WithLogger(logger))

	for range 3 {
		c.OnTextMessage(func(teamspeak.TextMessageEvent) {})
	}

	if got := strings.Count(logs.String(), "OnTextMessage"); got != 1 {
		t.Errorf("warned %d times, want once: %s", got, logs.String())
	}
}

// syncBuffer is an io.Writer a test can read while the client writes to it.
type syncBuffer struct {
	buf strings.Builder
	mu  sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func commandNames(lines []string) []string {
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, _ := strings.Cut(line, " ")
		names = append(names, name)
	}

	return names
}

func containsSubstring(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}

	return false
}

// The channel and server notifications reach their handlers, the answer to a
// description fetch is no edit, and each notification still reaches
// OnNotification after its typed event.
func TestNotification_ChannelAndServerEventsAreDelivered(t *testing.T) {
	d := newFakeDialer(true)
	c := newClient(t, d)

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	order := make(chan string, 16)
	c.OnChannelCreated(func(e teamspeak.ChannelCreatedEvent) {
		order <- "created"
		*e.Changes.Name = "mine"
	})
	c.OnChannelCreated(func(e teamspeak.ChannelCreatedEvent) { order <- "created:" + *e.Changes.Name })
	c.OnChannelEdited(func(e teamspeak.ChannelEditedEvent) { order <- "edited:" + *e.Changes.Topic })
	c.OnChannelMoved(func(teamspeak.ChannelMovedEvent) { order <- "moved" })
	c.OnChannelDeleted(func(e teamspeak.ChannelDeletedEvent) { order <- "deleted:" + e.InvokerName })
	c.OnChannelDescriptionChanged(func(teamspeak.ChannelDescriptionChangedEvent) { order <- "description" })
	c.OnChannelPasswordChanged(func(teamspeak.ChannelPasswordChangedEvent) { order <- "password" })
	c.OnServerEdited(func(e teamspeak.ServerEditedEvent) { order <- "server:" + e.Changes["virtualserver_name"] })
	c.OnNotification(func(e teamspeak.NotificationEvent) { order <- "n:" + e.Name })

	for _, line := range []string{
		`notifychannelcreated cid=9 cpid=0 channel_name=n invokerid=3 invokername=a`,
		`notifychanneledited cid=9 reasonid=9 channel_description=d`,
		`notifychanneledited cid=9 reasonid=10 invokerid=3 channel_topic=t`,
		`notifychannelmoved cid=9 cpid=0 order=0 reasonid=1`,
		`notifychanneldescriptionchanged cid=9`,
		`notifychannelpasswordchanged cid=9`,
		`notifychanneldeleted cid=9 invokerid=0 invokername=Server`,
		`notifyserveredited virtualserver_name=x`,
	} {
		transport.lines <- line
	}

	want := []string{
		"created", "created:n", "n:notifychannelcreated",
		"n:notifychanneledited", // the reason 9 answer: notification only
		"edited:t", "n:notifychanneledited",
		"moved", "n:notifychannelmoved",
		"description", "n:notifychanneldescriptionchanged",
		"password", "n:notifychannelpasswordchanged",
		"deleted:Server", "n:notifychanneldeleted",
		"server:x", "n:notifyserveredited",
	}
	for _, w := range want {
		select {
		case got := <-order:
			if got != w {
				t.Fatalf("got %q, want %q", got, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%q was never delivered", w)
		}
	}
}

// Over WebQuery the new On… methods are inert like the others, and warn once
// per method.
func TestNoEventsTransport_ChannelHandlersAreInert(t *testing.T) {
	d := newFakeDialer(false)
	c := newClient(t, d)
	for range 2 {
		c.OnChannelCreated(func(teamspeak.ChannelCreatedEvent) { t.Error("fired") })()
		c.OnServerEdited(func(teamspeak.ServerEditedEvent) { t.Error("fired") })()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.warned["OnChannelCreated"] || !c.warned["OnServerEdited"] {
		t.Errorf("warned = %v", c.warned)
	}
}
