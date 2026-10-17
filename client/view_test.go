package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// fixtureLines reads a recorded sequence: one raw command per line, as the
// client received it. Lines starting with # describe the recording.
var (
	errNetwork   = errors.New("the network went away")
	errHandshake = errors.New("the handshake failed")
	errDropped   = errors.New("dropped")
)

func fixtureLines(t *testing.T, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "view", name)) //nolint:gosec // a fixture of the test
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var lines []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines
}

func feed(c *Client, lines ...string) {
	for _, line := range lines {
		c.handleCommandLines(c.handler, line)
	}
}

// beginView is what Connect does to the view before the server speaks, and what
// initserver does to the client's own id.
func beginView(c *Client, self teamspeak.ClientID) {
	c.mu.Lock()
	c.resetViewLocked()
	c.clid = self
	c.mu.Unlock()
}

func channelNames(channels []teamspeak.Channel) []string {
	names := make([]string, len(channels))
	for i, ch := range channels {
		names[i] = ch.Name
	}

	return names
}

func viewIDs(channels []teamspeak.Channel) []teamspeak.ChannelID {
	ids := make([]teamspeak.ChannelID, len(channels))
	for i, ch := range channels {
		ids[i] = ch.ID
	}

	return ids
}

func clientIDs(clients []teamspeak.ClientEntry) []teamspeak.ClientID {
	ids := make([]teamspeak.ClientID, len(clients))
	for i, e := range clients {
		ids[i] = e.ID
	}

	return ids
}

//nolint:gocognit,funlen,gocyclo,cyclop // one scenario, read top to bottom
func TestViewWelcomeFromRecordings(t *testing.T) {
	for _, c := range []struct {
		name string
		file string
		self teamspeak.ClientID
	}{
		{"TS3", "ts3-welcome.txt", 22},
		{"TS6", "ts6-welcome.txt", 6},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := newTestClient(t)
			ready := make(chan ViewReadyEvent, 2)
			cl.OnViewReady(func(e ViewReadyEvent) { ready <- e })
			beginView(cl, c.self)

			lines := fixtureLines(t, c.file)
			finished := slices.Index(lines, "channellistfinished")
			feed(cl, lines[:finished]...)

			// The rows are not in the order of the tree, and the tree is not
			// built before the list is done.
			v := cl.View()
			if v.Status != ViewLoading || len(v.Channels()) != 0 {
				t.Fatalf("before the end of the list: %v, %d channels", v.Status, len(v.Channels()))
			}
			if got := clientIDs(v.ClientsIn(2)); len(got) != 2 {
				t.Errorf("the clients of the own channel = %v, want two", got)
			}

			feed(cl, lines[finished])
			settle(t, cl)
			v = cl.View()
			feed(cl, lines[finished+1:]...)

			if v.Status != ViewLive {
				t.Fatalf("Status = %v", v.Status)
			}
			want := []teamspeak.ChannelID{1, 2, 5, 6, 7, 3, 4}
			if got := viewIDs(v.Channels()); !slices.Equal(got, want) {
				t.Errorf("Channels() = %v, want %v", got, want)
			}
			if got := viewIDs(v.Children(0)); !slices.Equal(got, []teamspeak.ChannelID{1, 2, 3, 4}) {
				t.Errorf("Children(0) = %v", got)
			}
			if got := channelNames(v.Children(2)); !slices.Equal(got, []string{"Alpha-1", "Alpha-2", "Alpha-3"}) {
				t.Errorf("Children(2) = %v", got)
			}
			if got := viewIDs(v.Path(7)); !slices.Equal(got, []teamspeak.ChannelID{2, 7}) {
				t.Errorf("Path(7) = %v", got)
			}
			// The default channel arrived after Alpha and sits before it.
			if one, _ := v.Channel(1); one.Name != "Default Channel" || one.Order != 0 || !one.IsDefault {
				t.Errorf("channel 1 = %+v", one)
			}
			if two, _ := v.Channel(2); two.Order != 1 || two.Name != "Alpha" || !two.IsPermanent {
				t.Errorf("channel 2 = %+v", two)
			}
			if three, _ := v.Channel(3); !three.HasPassword || three.Order != 2 {
				t.Errorf("channel 3 = %+v", three)
			}
			for _, ch := range v.Channels() {
				if ch.TotalClients != nil || ch.TotalFamilyClients != nil {
					t.Errorf("channel %d carries a client count the server never updates", ch.ID)
				}
			}
			if v.Self == nil || v.Self.ID != c.self || v.Self.Nickname != "watcher" || v.Self.ChannelID != 2 {
				t.Errorf("Self = %+v", v.Self)
			}
			if got := len(v.ClientsIn(2)); got != 2 {
				t.Errorf("ClientsIn(2) has %d clients", got)
			}
			if got := v.ClientsIn(3); len(got) != 0 {
				t.Errorf("ClientsIn(3) = %v", got)
			}
			if e := receive(t, ready); e.Revision != v.Revision {
				t.Errorf("ViewReadyEvent.Revision = %d, View().Revision = %d", e.Revision, v.Revision)
			}
			err := cl.WaitView(t.Context())
			if err != nil {
				t.Errorf("WaitView = %v", err)
			}
			if !cl.view.tree.Consistent() {
				t.Error("the recorded list was taken for an inconsistent tree")
			}
		})
	}
}

// The ancestors of the own channel come first, deepest last, then the clients,
// then everything else in the order of the tree.
func TestViewWelcomeWithAncestorsFirst(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 9)
	feed(c,
		"channellist cid=8 cpid=0 channel_name=Top channel_order=2",
		"channellist cid=2 cpid=8 channel_name=Middle channel_order=0",
		"channellist cid=6 cpid=2 channel_name=Own channel_order=0",
		"notifycliententerview cfid=0 ctid=6 reasonid=2 clid=9 client_nickname=me client_unique_identifier=u9",
		"channellist cid=1 cpid=0 channel_name=First channel_order=0",
		"channellist cid=3 cpid=0 channel_name=Second channel_order=1",
		"channellist cid=7 cpid=2 channel_name=After channel_order=6",
		"channellist cid=10 cpid=8 channel_name=Sibling channel_order=2",
		"channellistfinished",
	)

	v := c.View()
	want := []teamspeak.ChannelID{1, 3, 8, 2, 6, 7, 10}
	if got := viewIDs(v.Channels()); !slices.Equal(got, want) {
		t.Errorf("Channels() = %v, want %v", got, want)
	}
	if got := viewIDs(v.Path(6)); !slices.Equal(got, []teamspeak.ChannelID{8, 2, 6}) {
		t.Errorf("Path(6) = %v", got)
	}
	if v.Self == nil || v.Self.ChannelID != 6 {
		t.Errorf("Self = %+v", v.Self)
	}
}

func TestViewFollowsRecordedChannelChanges(t *testing.T) {
	for _, c := range []struct {
		name string
		file string
		self teamspeak.ClientID
	}{
		{"TS3", "ts3-order.txt", 36},
		{"TS6", "ts6-order.txt", 17},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logs bytes.Buffer
			cl := newTestClient(t, WithLogger(slog.New(slog.NewTextHandler(&logs,
				&slog.HandlerOptions{Level: slog.LevelDebug}))))
			beginView(cl, c.self)
			lines := fixtureLines(t, c.file)
			finished := slices.Index(lines, "channellistfinished")
			feed(cl, lines[:finished+1]...)

			if got := viewIDs(cl.View().Channels()); !slices.Equal(got, []teamspeak.ChannelID{1, 2, 5, 6, 7, 3, 4}) {
				t.Fatalf("before the changes: %v", got)
			}
			feed(cl, lines[finished+1:]...)

			// Created 8, 9 and 10 in three places, put 11 under 4, moved 5 to
			// the top level, edited 8 to sit after 1, deleted 9, 11 and 4, moved
			// 2 under 8, renamed 6.
			v := cl.View()
			want := []teamspeak.ChannelID{10, 1, 8, 2, 6, 7, 3, 5}
			if got := viewIDs(v.Channels()); !slices.Equal(got, want) {
				t.Errorf("Channels() = %v, want %v", got, want)
			}
			if six, _ := v.Channel(6); six.Name != "Renamed" || six.ParentID != 2 || six.Order != 0 {
				t.Errorf("channel 6 = %+v", six)
			}
			if got := viewIDs(v.Path(7)); !slices.Equal(got, []teamspeak.ChannelID{8, 2, 7}) {
				t.Errorf("Path(7) = %v", got)
			}
			// The server rewrote their orders without a word.
			for id, order := range map[teamspeak.ChannelID]teamspeak.ChannelID{10: 0, 1: 10, 8: 1, 3: 8, 5: 3, 2: 0} {
				if ch, _ := v.Channel(id); ch.Order != order {
					t.Errorf("channel %d: Order = %d, want %d", id, ch.Order, order)
				}
			}
			if !cl.view.tree.Consistent() || strings.Contains(logs.String(), "does not fit") {
				t.Errorf("a recorded change was not placed:\n%s", logs.String())
			}
		})
	}
}

func TestViewLogsAChannelNotificationItCannotPlace(t *testing.T) {
	var logs bytes.Buffer
	c := newTestClient(t, WithLogger(slog.New(slog.NewTextHandler(&logs,
		&slog.HandlerOptions{Level: slog.LevelDebug}))))
	beginView(c, 1)
	feed(c, "channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished")
	feed(c, "notifychannelcreated cid=2 cpid=77 channel_name=Lost channel_order=0 invokerid=1")

	v := c.View()
	if got := viewIDs(v.Channels()); !slices.Equal(got, []teamspeak.ChannelID{1, 2}) {
		t.Errorf("Channels() = %v: the channel was not kept at the end", got)
	}
	if two, _ := v.Channel(2); two.ParentID != 0 {
		t.Errorf("channel 2 under %d", two.ParentID)
	}
	if !strings.Contains(logs.String(), "notifychannelcreated") {
		t.Errorf("the log names nothing:\n%s", logs.String())
	}
}

// A channel list that counts clients says how many there were when the client
// connected, and a channel notification may carry the same; the view keeps
// neither.
func TestViewLeavesOutTheClientCounts(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=1 cpid=0 channel_name=A channel_order=0 total_clients=4 total_clients_family=9",
		"channellistfinished",
		"notifychannelcreated cid=2 cpid=1 channel_name=B channel_order=0 total_clients=1",
		"notifychanneledited cid=1 reasonid=10 invokerid=1 total_clients_family=3 channel_topic=t")

	for _, ch := range c.View().Channels() {
		if ch.TotalClients != nil || ch.TotalFamilyClients != nil {
			t.Errorf("channel %d: %v %v", ch.ID, ch.TotalClients, ch.TotalFamilyClients)
		}
	}
	if one, _ := c.View().Channel(1); one.Topic != "t" {
		t.Errorf("the rest of the edit was lost: %+v", one)
	}
}

// The event a handler receives still carries what the server sent.
func TestViewEventsKeepTheirChanges(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	got := make(chan ChannelCreatedEvent, 1)
	c.OnChannelCreated(func(e ChannelCreatedEvent) { got <- e })
	feed(c, "channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished",
		"notifychannelcreated cid=2 cpid=1 channel_name=B channel_order=0 total_clients=1")

	if e := receive(t, got); e.Changes.TotalClients == nil {
		t.Error("the view took the count out of the event")
	}
}

func TestViewSeesTheChangeBeforeTheEvent(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished")

	// The view changes before the event is queued, and handlers run on their
	// own goroutine while later packets are handled: the handler of the first
	// event sees a view at least as new as that event, which may already hold
	// the second channel too.
	seen := make(chan []teamspeak.ChannelID, 2)
	c.OnChannelCreated(func(ChannelCreatedEvent) { seen <- viewIDs(c.View().Channels()) })
	feed(c, "notifychannelcreated cid=2 cpid=0 channel_name=B channel_order=1",
		"notifychannelcreated cid=3 cpid=0 channel_name=C channel_order=2")

	first := receive(t, seen)
	if !slices.Equal(first, []teamspeak.ChannelID{1, 2}) && !slices.Equal(first, []teamspeak.ChannelID{1, 2, 3}) {
		t.Errorf("the handler of the first event saw %v, want the view to hold channel 2 already", first)
	}
}

func enterLine(id teamspeak.ClientID, channel teamspeak.ChannelID, groups string) string {
	return fmt.Sprintf("notifycliententerview clid=%d client_nickname=c%d ctid=%d client_type=0 "+
		"client_servergroups=%s client_unique_identifier=u%d", id, id, channel, groups, id)
}

func TestViewDropsTheClientsOfAnUnsubscribedChannel(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0",
		"channellist cid=3 cpid=0 channel_name=B channel_order=2",
		enterLine(1, 2, "7"), enterLine(5, 2, "7"), "channellistfinished",
		enterLine(6, 3, "7"), enterLine(7, 3, "8"), "notifychannelsubscribed cid=3")
	left := make(chan ChannelUnsubscribedEvent, 2)
	c.OnChannelUnsubscribed(func(e ChannelUnsubscribedEvent) { left <- e })

	before := c.View()
	if got := clientIDs(before.ClientsIn(3)); !slices.Equal(got, []teamspeak.ClientID{6, 7}) {
		t.Fatalf("ClientsIn(3) = %v", got)
	}

	feed(c, "notifychannelunsubscribed cid=3")

	after := c.View()
	if got := clientIDs(after.Clients()); !slices.Equal(got, []teamspeak.ClientID{1, 5}) {
		t.Errorf("Clients() = %v, want 1 and 5", got)
	}
	if got := after.ClientsIn(3); len(got) != 0 {
		t.Errorf("ClientsIn(3) = %v", got)
	}
	if after.Revision <= before.Revision {
		t.Errorf("Revision %d did not pass %d", after.Revision, before.Revision)
	}
	// The roster is the same store.
	for _, id := range []teamspeak.ClientID{6, 7} {
		if _, ok := known(c, id); ok {
			t.Errorf("the roster still holds client %d", id)
		}
	}
	if e := receive(t, left); e.ChannelID != 3 {
		t.Errorf("event = %+v", e)
	}
	// Subscribing again announces who is there now, one of them having moved.
	feed(c, enterLine(6, 2, "7"), "notifychannelsubscribed cid=3")
	again := c.View()
	if got := clientIDs(again.ClientsIn(2)); !slices.Equal(got, []teamspeak.ClientID{1, 5, 6}) {
		t.Errorf("ClientsIn(2) = %v", got)
	}
	if got := again.ClientsIn(3); len(got) != 0 {
		t.Errorf("ClientsIn(3) = %v", got)
	}
}

func TestViewKeepsTheClientItselfWhenItsChannelIsUnsubscribed(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0", enterLine(1, 2, "7"), enterLine(5, 2, "7"),
		"channellistfinished", "notifychannelunsubscribed cid=2")

	v := c.View()
	if got := clientIDs(v.Clients()); !slices.Equal(got, []teamspeak.ClientID{1}) {
		t.Errorf("Clients() = %v", got)
	}
	if v.Self == nil || v.Self.ID != 1 {
		t.Errorf("Self = %+v", v.Self)
	}
}

func TestViewAndRosterAgreeOnGroups(t *testing.T) {
	for _, order := range []string{"update first", "group notice first"} {
		t.Run(order, func(t *testing.T) {
			c := newTestClient(t)
			beginView(c, 1)
			feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0", enterLine(1, 2, "7"),
				enterLine(5, 2, "7"), "channellistfinished")
			update := "notifyclientupdated clid=5 client_servergroups=7,9"
			notice := "notifyservergroupclientadded sgid=9 clid=5 invokerid=1 invokername=x invokeruid=y"
			if order == "update first" {
				feed(c, update, notice)
			} else {
				feed(c, notice, update)
			}
			var msg TextMessageEvent
			c.OnTextMessage(func(m TextMessageEvent) { msg = m })
			feed(c, "notifytextmessage targetmode=2 msg=hi invokerid=5 invokername=c5 invokeruid=u5")
			settle(t, c)
			entry, _ := c.View().Client(5)
			if !slices.Equal(entry.ServerGroups, []teamspeak.ServerGroupID{7, 9}) ||
				!slices.Equal(entry.ServerGroups, msg.InvokerGroups) {
				t.Errorf("view has %v, the message %v", entry.ServerGroups, msg.InvokerGroups)
			}
		})
	}
}

func TestViewFollowsTheClientsItIsToldAbout(t *testing.T) {
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0",
		"channellist cid=3 cpid=0 channel_name=B channel_order=2", enterLine(1, 2, "7"), "channellistfinished")
	rev := c.View().Revision

	steps := []struct {
		in   map[teamspeak.ChannelID][]teamspeak.ClientID
		line string
	}{
		{line: enterLine(5, 3, "7"), in: map[teamspeak.ChannelID][]teamspeak.ClientID{2: {1}, 3: {5}}},
		{line: "notifyclientmoved clid=5 ctid=2 reasonid=1", in: map[teamspeak.ChannelID][]teamspeak.ClientID{2: {1, 5}}},
		{
			line: "notifyclientupdated clid=5 client_nickname=renamed",
			in:   map[teamspeak.ChannelID][]teamspeak.ClientID{2: {1, 5}},
		},
		{line: "notifyclientleftview clid=5 ctid=0 reasonid=8", in: map[teamspeak.ChannelID][]teamspeak.ClientID{2: {1}}},
	}
	for _, s := range steps {
		feed(c, s.line)
		v := c.View()
		if v.Revision <= rev {
			t.Errorf("%q: Revision %d did not pass %d", s.line, v.Revision, rev)
		}
		rev = v.Revision
		for _, ch := range []teamspeak.ChannelID{2, 3} {
			if got := clientIDs(v.ClientsIn(ch)); !slices.Equal(got, s.in[ch]) && (len(got) > 0 || len(s.in[ch]) > 0) {
				t.Errorf("%q: ClientsIn(%d) = %v, want %v", s.line, ch, got, s.in[ch])
			}
		}
	}

	// An update of a client the view does not know adds none and changes nothing.
	feed(c, "notifyclientupdated clid=77 client_nickname=ghost")
	if v := c.View(); v.Revision != rev {
		t.Errorf("Revision moved to %d for an update of nobody", v.Revision)
	}
}

func welcomed(t *testing.T) *Client {
	t.Helper()
	c := newTestClient(t)
	beginView(c, 1)
	feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0",
		"channellist cid=3 cpid=2 channel_name=B channel_order=0", enterLine(1, 2, "7"), "channellistfinished")
	settle(t, c)

	return c
}

func TestViewIsStaleAfterTheSessionEnds(t *testing.T) {
	c := welcomed(t)
	before := c.View()

	c.handleConnectionClosed(c.handler, errNetwork)

	v := c.View()
	if v.Status != ViewStale {
		t.Fatalf("Status = %v", v.Status)
	}
	got := viewIDs(v.Channels())
	if !slices.Equal(got, viewIDs(before.Channels())) || v.Self == nil || len(v.Clients()) != 1 {
		t.Errorf("the last view was not kept: %v, %+v", got, v.Self)
	}
	err := c.WaitView(t.Context())
	if !errors.Is(err, teamspeak.ErrNotConnected) || !strings.Contains(err.Error(), "the network went away") {
		t.Errorf("WaitView = %v", err)
	}

	// A notification that arrives after the end changes nothing in it.
	feed(c, "notifychannelcreated cid=9 cpid=0 channel_name=Late channel_order=2 invokerid=1")
	if got := viewIDs(c.View().Channels()); !slices.Equal(got, viewIDs(before.Channels())) {
		t.Errorf("a stale view changed: %v", got)
	}
}

func TestViewIsClearedByTheNextConnect(t *testing.T) {
	c := welcomed(t)
	ready := make(chan ViewReadyEvent, 4)
	c.OnViewReady(func(e ViewReadyEvent) { ready <- e })
	c.handleConnectionClosed(c.handler, errDropped)
	stale := c.View()

	c.mu.Lock()
	c.resetForConnectLocked()
	c.mu.Unlock()
	completeCryptoInit(t, c.handler)

	v := c.View()
	if v.Status != ViewLoading || len(v.Channels()) != 0 || len(v.Clients()) != 0 || v.Self != nil {
		t.Errorf("after the reset: %v, %d channels, %d clients, %+v", v.Status, len(v.Channels()), len(v.Clients()), v.Self)
	}
	if v.Revision <= stale.Revision {
		t.Errorf("the revision went back: %d after %d", v.Revision, stale.Revision)
	}

	// Another welcome, of another tree, and the event again.
	c.mu.Lock()
	c.clid = 1
	c.mu.Unlock()
	feed(c, "channellist cid=8 cpid=0 channel_name=New channel_order=0", enterLine(1, 8, "7"), "channellistfinished")
	settle(t, c)
	v = c.View()
	if v.Status != ViewLive || !slices.Equal(viewIDs(v.Channels()), []teamspeak.ChannelID{8}) {
		t.Errorf("after the second welcome: %v, %v", v.Status, viewIDs(v.Channels()))
	}
	if e := receive(t, ready); e.Revision != v.Revision {
		t.Errorf("event %+v, view revision %d", e, v.Revision)
	}
	select {
	case e := <-ready:
		t.Errorf("a second event for one welcome: %+v", e)
	default:
	}
}

func TestViewRowsOfAnAnswerAreNotAWelcome(t *testing.T) {
	c := welcomed(t)
	// What ListChannels is answered with has the name of the welcome's rows.
	feed(c, "channellist cid=40 cpid=0 channel_name=Answer channel_order=0")
	if got := viewIDs(c.View().Channels()); !slices.Equal(got, []teamspeak.ChannelID{2, 3}) {
		t.Errorf("Channels() = %v", got)
	}
}

func TestViewEndsOnAFailedAttempt(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusConnecting
	c.resetViewLocked()
	c.mu.Unlock()
	waited := make(chan error, 1)
	go func() { waited <- c.WaitView(context.Background()) }()
	waitUntil(t, "WaitView to block", c.viewWaiting)

	c.failConnection(c.handler, errHandshake)

	err := receive(t, waited)
	if !errors.Is(err, teamspeak.ErrNotConnected) || !strings.Contains(err.Error(), "the handshake failed") {
		t.Errorf("WaitView = %v", err)
	}
	if v := c.View(); v.Status != ViewStale || len(v.Channels()) != 0 {
		t.Errorf("view after the failed attempt: %v, %d channels", v.Status, len(v.Channels()))
	}
}

func TestViewIsEmptyBeforeConnect(t *testing.T) {
	c := newTestClient(t)
	v := c.View()
	if v.Status != ViewEmpty || v.Self != nil || len(v.Channels()) != 0 || len(v.Clients()) != 0 {
		t.Errorf("View() = %+v", v)
	}
	if got := v.Children(0); len(got) != 0 {
		t.Errorf("Children(0) = %v", got)
	}
	if got := v.Path(1); len(got) != 0 {
		t.Errorf("Path(1) = %v", got)
	}
	if _, ok := v.Channel(1); ok {
		t.Error("Channel(1) found")
	}
	if _, ok := v.Client(1); ok {
		t.Error("Client(1) found")
	}
	// A zero ServerView is as empty.
	var zero ServerView
	if len(zero.Channels()) != 0 || len(zero.Clients()) != 0 || len(zero.ClientsIn(1)) != 0 {
		t.Error("the zero ServerView holds something")
	}
}

//nolint:funlen // one subtest for each way it can end
func TestWaitView(t *testing.T) {
	t.Run("waits through the welcome", func(t *testing.T) {
		c := newTestClient(t)
		beginView(c, 1)
		waited := make(chan error, 1)
		go func() { waited <- c.WaitView(context.Background()) }()
		waitUntil(t, "WaitView to block", c.viewWaiting)
		select {
		case err := <-waited:
			t.Fatalf("returned before the list was done: %v", err)
		default:
		}

		feed(c, "channellist cid=2 cpid=0 channel_name=A channel_order=0", "channellistfinished")

		err := receive(t, waited)
		if err != nil {
			t.Errorf("WaitView = %v", err)
		}
	})

	t.Run("waits before Connect for the connection Connect makes", func(t *testing.T) {
		c := newTestClient(t)
		waited := make(chan error, 1)
		go func() { waited <- c.WaitView(context.Background()) }()
		waitUntil(t, "WaitView to block", c.viewWaiting)

		beginView(c, 1)
		feed(c, "channellistfinished")

		err := receive(t, waited)
		if err != nil {
			t.Errorf("WaitView = %v", err)
		}
	})

	t.Run("returns at once when live", func(t *testing.T) {
		c := welcomed(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := c.WaitView(ctx)
		if err != nil {
			t.Errorf("WaitView = %v", err)
		}
	})

	t.Run("returns the context's error", func(t *testing.T) {
		c := newTestClient(t)
		beginView(c, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err := c.WaitView(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("WaitView = %v", err)
		}
	})

	t.Run("fails when the session ends first", func(t *testing.T) {
		c := newTestClient(t)
		beginView(c, 1)
		waited := make(chan error, 1)
		go func() { waited <- c.WaitView(context.Background()) }()
		waitUntil(t, "WaitView to block", c.viewWaiting)

		c.handleConnectionClosed(c.handler, errDropped)
		// A new connection that starts at once does not hide the end.
		c.mu.Lock()
		c.resetViewLocked()
		c.mu.Unlock()

		err := receive(t, waited)
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("WaitView = %v", err)
		}
	})

	t.Run("fails after Disconnect", func(t *testing.T) {
		c := welcomed(t)
		err := c.Disconnect(t.Context())
		if err != nil {
			t.Fatalf("Disconnect: %v", err)
		}
		err = c.WaitView(t.Context())
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("WaitView = %v", err)
		}
		if v := c.View(); v.Status != ViewStale || len(v.Channels()) != 2 {
			t.Errorf("view after Disconnect: %v, %d channels", v.Status, len(v.Channels()))
		}
	})
}

// viewWaiting reports whether a WaitView is blocked.
func (c *Client) viewWaiting() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.view.waiting > 0
}

func scribbleChannel(ch *teamspeak.Channel) { ch.Name = "changed" }

func scribbleClient(e *teamspeak.ClientEntry) { e.IsAway = true }

// Nothing the caller does to a view, or to what it returns, reaches the client
// or the next view.
//
//nolint:funlen // one scenario, read top to bottom
func TestViewIsACopy(t *testing.T) {
	c := welcomed(t)
	feed(c, enterLine(5, 2, "7,8"))
	want := c.View()

	mutate := func(v ServerView) {
		v.Revision = 99
		v.Status = ViewEmpty
		v.Self.Nickname = "changed"
		v.Self.ServerGroups[0] = 999
		for _, list := range [][]teamspeak.Channel{v.Channels(), v.Children(0), v.Path(3)} {
			for i := range list {
				list[i].Name = "changed"
				list[i].TotalClients = new(int32(7))
			}
			slices.Reverse(list)
		}
		for _, list := range [][]teamspeak.ClientEntry{v.Clients(), v.ClientsIn(2)} {
			for i := range list {
				list[i].Nickname = "changed"
				list[i].ServerGroups[0] = 999
			}
			slices.Reverse(list)
		}
		ch, _ := v.Channel(2)
		scribbleChannel(&ch)
		e, _ := v.Client(5)
		e.ServerGroups[0] = 999
		scribbleClient(&e)
	}
	mutate(want)
	mutate(c.View())

	got := c.View()
	if got.Self == nil || got.Self.Nickname == "changed" || got.Self.ServerGroups[0] == 999 {
		t.Errorf("Self = %+v", got.Self)
	}
	for _, ch := range got.Channels() {
		if ch.Name == "changed" || ch.TotalClients != nil {
			t.Errorf("channel %+v", ch)
		}
	}
	for _, e := range got.Clients() {
		if e.Nickname == "changed" || e.ServerGroups[0] == 999 || e.IsAway {
			t.Errorf("client %+v", e)
		}
	}
	if entry, _ := known(c, 5); entry.ServerGroups[0] == 999 {
		t.Error("the roster was edited through the view")
	}
	if got.Status != ViewLive {
		t.Errorf("Status = %v", got.Status)
	}

	// A view taken earlier does not follow the client.
	taken := c.View()
	feed(c, "notifychannelcreated cid=9 cpid=0 channel_name=New channel_order=2 invokerid=1",
		"notifyclientleftview clid=5 reasonid=8")
	if len(taken.Channels()) != 2 || len(taken.Clients()) != 2 {
		t.Errorf("an earlier view changed: %d channels, %d clients", len(taken.Channels()), len(taken.Clients()))
	}
}

func TestViewStatusNames(t *testing.T) {
	for status, want := range map[ViewStatus]string{
		ViewEmpty: "empty", ViewLoading: "loading", ViewLive: "live", ViewStale: "stale", ViewStatus(9): "view status 9",
	} {
		if got := status.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(status), got, want)
		}
	}
}

// Reading the view while packets are processed is safe: run with -race.
func TestViewCanBeReadWhilePacketsAreHandled(t *testing.T) {
	c := welcomed(t)
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				v := c.View()
				for _, ch := range v.Channels() {
					_ = v.Path(ch.ID)
					_ = v.ClientsIn(ch.ID)
				}
				_ = v.Clients()
				_, _ = v.Client(5)
				_ = c.WaitView(context.Background())
			}
		})
	}

	for i := range 200 {
		id := teamspeak.ChannelID(100 + i)
		feed(c,
			fmt.Sprintf("notifychannelcreated cid=%d cpid=2 channel_name=n%d channel_order=0 invokerid=1", id, i),
			enterLine(teamspeak.ClientID(10+i%5), id, "7"),
			fmt.Sprintf("notifyclientmoved clid=%d ctid=2 reasonid=1", 10+i%5),
			fmt.Sprintf("notifychannelmoved cid=%d cpid=0 order=2 reasonid=1 invokerid=1", id),
			fmt.Sprintf("notifychannelunsubscribed cid=%d", id),
			fmt.Sprintf("notifychanneldeleted cid=%d invokerid=1", id),
		)
	}
	close(stop)
	readers.Wait()
}

// Whatever notifications arrive, the view's channels all sit under a parent it
// holds, and the clients it lists are the roster's.
func FuzzViewNotifications(f *testing.F) {
	f.Add("channellist cid=2 cpid=0 channel_order=0|cid=3 cpid=2 channel_order=0\nchannellistfinished\n" +
		"notifychannelcreated cid=4 cpid=3 channel_order=3\nnotifychannelmoved cid=4 cpid=0 order=2")
	f.Add("channellistfinished\nnotifychannelcreated cid=1 cpid=1 channel_order=1\n" +
		"notifychanneledited cid=1 channel_order=1\nnotifychanneldeleted cid=1")
	f.Add("channellist cid=1 cpid=2|cid=2 cpid=1\nchannellistfinished\nnotifychannelunsubscribed cid=1")
	f.Add("notifycliententerview clid=3 ctid=2\nnotifychannelunsubscribed cid=2\nnotifyclientleftview clid=3")
	f.Add("channellistfinished\nnotifyservergrouplist sgid=3 name=C|sgid=1 name=A|sgid=3 name=D\n" +
		"notifychannelgrouplist cgid=2 name=X\nnotifyservergrouplist name=Nameless")
	f.Add("channellistfinished\nnotifyserveredited reasonid=10 virtualserver_name=N\n" +
		"notifyserverupdated virtualserver_uptime=1 virtualserver_maxclients=2\nnotifyserveredited")

	f.Fuzz(func(t *testing.T, data string) {
		c := newTestClient(t)
		beginView(c, 1)
		for line := range strings.SplitSeq(data, "\n") {
			c.handleCommandLines(c.handler, line)
			v := c.View()
			for _, ch := range v.Channels() {
				if ch.ParentID != 0 {
					if _, ok := v.Channel(ch.ParentID); !ok {
						t.Fatalf("channel %d is under %d, which the view lacks", ch.ID, ch.ParentID)
					}
				}
				if path := v.Path(ch.ID); len(path) == 0 || path[len(path)-1].ID != ch.ID {
					t.Fatalf("Path(%d) = %v", ch.ID, viewIDs(path))
				}
			}
			if len(v.Channels()) != v.tree.Len() {
				t.Fatalf("%d channels listed of %d", len(v.Channels()), v.tree.Len())
			}
			requireGroupsAndServerInOrder(t, v)
		}
	})
}

// requireGroupsAndServerInOrder fails unless the view's groups are in strictly
// ascending id and its server settings are all the server's own.
func requireGroupsAndServerInOrder(t *testing.T, v ServerView) {
	t.Helper()
	if !ascending(serverGroupIDs(v.ServerGroups)) || !ascending(channelGroupIDs(v.ChannelGroups)) {
		t.Fatalf("the groups are not in ascending id: %v, %v", v.ServerGroups, v.ChannelGroups)
	}
	for name := range v.Server {
		if !strings.HasPrefix(name, serverPropertyPrefix) {
			t.Fatalf("the view holds the setting %q", name)
		}
	}
}
