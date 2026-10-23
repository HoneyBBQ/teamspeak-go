package stream

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
	"github.com/honeybbq/teamspeak-go/notify"
)

// sent is a command the fake host was given.
type sent struct {
	params map[string]string
	name   string
	line   string
}

// pendingSetup is a setupstream waiting for the test to announce it, as the real
// client holds one until the announcement that echoes its return_code arrives.
type pendingSetup struct {
	result     chan setupResult
	returnCode string
	sent       sent
}

type setupResult struct {
	err  error
	rows []map[string]string
}

// fakeHost stands in for the client a Streams attaches to: it records what is
// sent, answers as the test says, and delivers the events and notifications the
// test injects, on the caller's goroutine as the client does on its own.
type fakeHost struct {
	reply   func(sent) ([]map[string]string, error, bool)
	entries map[teamspeak.ClientID]teamspeak.ClientEntry
	subs    map[string][]*subscription
	family  teamspeak.ServerFamily
	version string
	exts    []string
	log     []sent
	setups  []*pendingSetup
	mu      sync.Mutex
	status  client.Status
	nextRC  int
	self    teamspeak.ClientID
}

type subscription struct {
	fn      any
	removed bool
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		status:  client.StatusConnected,
		self:    1,
		family:  client.ServerFamilyTS6,
		version: "6.0.0-beta13.1",
		exts:    []string{"FILETIME", extensionP2P},
		entries: make(map[teamspeak.ClientID]teamspeak.ClientEntry),
		subs:    make(map[string][]*subscription),
	}
}

func (h *fakeHost) Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	line := encoded(req)
	cmd := wire.ParseCommand(line)
	s := sent{name: cmd.Name, params: cmd.Params, line: line}

	h.mu.Lock()
	h.log = append(h.log, s)
	reply := h.reply
	var ps *pendingSetup
	if cmd.Name == "setupstream" {
		h.nextRC++
		ps = &pendingSetup{returnCode: strconv.Itoa(h.nextRC), result: make(chan setupResult, 1), sent: s}
	}
	h.mu.Unlock()

	if reply != nil {
		rows, err, ok := reply(s)
		if ok {
			return rows, err
		}
	}
	if ps == nil {
		return nil, nil
	}
	h.mu.Lock()
	h.setups = append(h.setups, ps)
	h.mu.Unlock()
	select {
	case r := <-ps.result:
		return r.rows, r.err
	case <-ctx.Done():
		h.mu.Lock()
		h.setups = slices.DeleteFunc(h.setups, func(x *pendingSetup) bool { return x == ps })
		h.mu.Unlock()

		return nil, fmt.Errorf("setupstream: %w", ctx.Err())
	}
}

func (h *fakeHost) ClientID() teamspeak.ClientID {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.self
}

func (h *fakeHost) Status() client.Status {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.status
}

func (h *fakeHost) ServerCapabilities() client.ServerCapabilities {
	h.mu.Lock()
	defer h.mu.Unlock()

	return client.ServerCapabilities{Family: h.family, Version: h.version, Extensions: h.exts}
}

func (h *fakeHost) Entries() []teamspeak.ClientEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Collect(maps.Values(h.entries))
}

func (h *fakeHost) Entry(id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.entries[id]

	return e, ok
}

func subscribe[E any](h *fakeHost, event string, fn func(E)) func() {
	sub := &subscription{fn: fn}
	h.mu.Lock()
	h.subs[event] = append(h.subs[event], sub)
	h.mu.Unlock()

	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		sub.removed = true
	}
}

func (h *fakeHost) OnNotification(fn func(client.NotificationEvent)) func() {
	return subscribe(h, "notification", fn)
}

func (h *fakeHost) OnClientEnter(fn func(client.ClientEnterEvent)) func() {
	return subscribe(h, "enter", fn)
}

func (h *fakeHost) OnClientUpdated(fn func(client.ClientUpdatedEvent)) func() {
	return subscribe(h, "updated", fn)
}

func (h *fakeHost) OnClientLeave(fn func(client.ClientLeaveEvent)) func() {
	return subscribe(h, "leave", fn)
}

func (h *fakeHost) OnConnected(fn func(client.ConnectedEvent)) func() {
	return subscribe(h, "connected", fn)
}

func (h *fakeHost) OnDisconnected(fn func(client.DisconnectedEvent)) func() {
	return subscribe(h, "disconnected", fn)
}

// listeners counts the live subscriptions to an event.
func (h *fakeHost) listeners(event string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(slices.DeleteFunc(slices.Clone(h.subs[event]), func(s *subscription) bool { return s.removed }))
}

func emit[E any](h *fakeHost, event string, e E) {
	h.mu.Lock()
	subs := slices.Clone(h.subs[event])
	h.mu.Unlock()
	for _, sub := range subs {
		h.mu.Lock()
		removed := sub.removed
		h.mu.Unlock()
		if fn, ok := sub.fn.(func(E)); ok && !removed {
			fn(e)
		}
	}
}

// notify delivers a notification, as the client's catch-all does.
func (h *fakeHost) notify(name string, params map[string]string) {
	emit(h, "notification", client.NotificationEvent{Name: name, Params: maps.Clone(params)})
}

// see puts a client in view.
func (h *fakeHost) see(id teamspeak.ClientID, streaming *bool) teamspeak.ClientEntry {
	e := teamspeak.ClientEntry{
		ID:          id,
		UID:         teamspeak.UID(fmt.Sprintf("uid-%d", id)),
		Nickname:    fmt.Sprintf("client%d", id),
		IsStreaming: streaming,
	}
	h.mu.Lock()
	h.entries[id] = e
	h.mu.Unlock()

	return e
}

func (h *fakeHost) enter(id teamspeak.ClientID, streaming *bool) {
	e := h.see(id, streaming)
	emit(h, "enter", client.ClientEnterEvent{ClientEntry: e})
}

func (h *fakeHost) setStreaming(id teamspeak.ClientID, on bool) {
	emit(h, "updated", client.ClientUpdatedEvent{ClientID: id, Changes: teamspeak.ClientChanges{IsStreaming: &on}})
}

func (h *fakeHost) leave(id teamspeak.ClientID) {
	h.mu.Lock()
	delete(h.entries, id)
	h.mu.Unlock()
	emit(h, "leave", client.ClientLeaveEvent{ClientID: id})
}

func (h *fakeHost) disconnect() {
	h.mu.Lock()
	h.status = client.StatusDisconnected
	h.mu.Unlock()
	emit(h, "disconnected", client.DisconnectedEvent{})
}

// reconnectQuietly is the client being connected again under another client id
// while its disconnected event for the old connection is still on its way.
func (h *fakeHost) reconnectQuietly(self teamspeak.ClientID) {
	h.mu.Lock()
	h.status, h.self = client.StatusConnected, self
	h.mu.Unlock()
}

// deliverDisconnected is the lagging event itself.
func (h *fakeHost) deliverDisconnected() {
	emit(h, "disconnected", client.DisconnectedEvent{})
}

func (h *fakeHost) connect() {
	h.mu.Lock()
	h.status = client.StatusConnected
	h.mu.Unlock()
	emit(h, "connected", client.ConnectedEvent{})
}

// commands returns the commands sent so far with this name.
func (h *fakeHost) commands(name string) []sent {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []sent
	for _, s := range h.log {
		if s.name == name {
			out = append(out, s)
		}
	}

	return out
}

func (h *fakeHost) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.log)
}

// pendingSetups is how many setupstream commands wait for an announcement.
func (h *fakeHost) pendingSetups() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.setups)
}

// announce is the server announcing the stream the which-th waiting setupstream
// started: the notification, carrying the command's return_code, and then the
// answer to the command, as measured.
func (h *fakeHost) announce(t *testing.T, params map[string]string, which int) {
	t.Helper()
	ps := h.takeSetup(t, which)
	row := maps.Clone(params)
	row["return_code"] = ps.returnCode
	h.notify(notify.StreamStarted, row)
	ps.result <- setupResult{rows: []map[string]string{row}}
}

// announceAfterError answers the command first and sends the notification after,
// the other order the tracker accepts.
func (h *fakeHost) announceAfterError(t *testing.T, params map[string]string, which int) {
	t.Helper()
	ps := h.takeSetup(t, which)
	row := maps.Clone(params)
	row["return_code"] = ps.returnCode
	ps.result <- setupResult{rows: []map[string]string{row}}
	h.notify(notify.StreamStarted, row)
}

// failSetup is the server's refusal of the which-th waiting setupstream.
func (h *fakeHost) failSetup(t *testing.T, err error, which int) {
	t.Helper()
	h.takeSetup(t, which).result <- setupResult{err: err}
}

func (h *fakeHost) takeSetup(t *testing.T, which int) *pendingSetup {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if which >= len(h.setups) {
		t.Fatalf("no setupstream #%d is waiting (%d are)", which, len(h.setups))
	}
	ps := h.setups[which]
	h.setups = slices.Delete(h.setups, which, which+1)

	return ps
}

// collector records what a handler is given.
type collector[E any] struct {
	items []E
	mu    sync.Mutex
}

func (c *collector[E]) add(e E) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, e)
}

func (c *collector[E]) all() []E {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.items)
}

func (c *collector[E]) len() int { return len(c.all()) }

// env is a Streams over a fake host, inside a synctest bubble.
type env struct {
	t *testing.T
	h *fakeHost
	s *Streams
}

// run makes an env for a test and runs it in a synctest bubble, so that time
// is virtual and a goroutine left running after the test fails it.
func run(t *testing.T, fn func(t *testing.T, e *env)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		h := newFakeHost()
		e := &env{t: t, h: h, s: newStreams(h, Options{})}
		fn(t, e)
		_ = e.s.Close(t.Context())
		// Whatever the test left to expire does, so a goroutine that outlives
		// its deadline shows up as a leak.
		time.Sleep(time.Minute)
	})
}

// runWith is run with Options and a host the test has prepared.
func runWith(t *testing.T, opts Options, prepare func(*fakeHost), fn func(t *testing.T, e *env)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		h := newFakeHost()
		if prepare != nil {
			prepare(h)
		}
		e := &env{t: t, h: h, s: newStreams(h, opts)}
		fn(t, e)
		_ = e.s.Close(t.Context())
		// Whatever the test left to expire does, so a goroutine that outlives
		// its deadline shows up as a leak.
		time.Sleep(time.Minute)
	})
}

// settle lets every goroutine run until all are waiting.
func (e *env) settle() {
	e.t.Helper()
	synctest.Wait()
}

// announcement is a notifystreamstarted row for a stream of client 5.
func announcement(id string, clid int) map[string]string {
	return map[string]string{
		"id": id, "clid": strconv.Itoa(clid), "name": "Demo", "type": "2", "access": "1", "mode": "1",
		"bitrate": "58208", "viewer_limit": "0", "audio": "1",
	}
}

// publish publishes a stream of client 1 (the env's own) and announces it.
func (e *env) publish(opts PublishOptions) *Published {
	e.t.Helper()
	type result struct {
		p   *Published
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := e.s.Publish(e.t.Context(), opts)
		done <- result{p, err}
	}()
	e.settle()
	e.h.announce(e.t, announcement("pub-"+strconv.Itoa(len(e.h.commands("setupstream"))), int(e.h.self)), 0)
	r := <-done
	if r.err != nil {
		e.t.Fatalf("Publish: %v", r.err)
	}
	e.settle()

	return r.p
}

func serverError(code errcode.Code) error {
	return &teamspeak.ServerError{Code: code, Message: code.Error()}
}
