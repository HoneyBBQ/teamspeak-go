package client

import (
	"reflect"
	"slices"
	"sync"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// know puts a client in the client's list, as entering view would.
func know(c *Client, e teamspeak.ClientEntry) {
	c.mu.Lock()
	c.clients[e.ID] = e
	c.mu.Unlock()
}

func known(c *Client, id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.clients[id]

	return e, ok
}

// events collects every event a client delivers, in order, through middleware.
func collect(t *testing.T) (*Client, func() []Event) {
	t.Helper()
	var mu sync.Mutex
	var got []Event
	c := newTestClient(t, WithEventMiddleware(func(next func(Event)) func(Event) {
		return func(e Event) {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
			next(e)
		}
	}))

	return c, func() []Event {
		settle(t, c)
		mu.Lock()
		defer mu.Unlock()

		return slices.Clone(got)
	}
}

// The update replaces the groups the client knows, so the message that follows
// it in the stream carries the new ones, and the entry earlier events held is
// not edited under them.
func TestClientUpdated_RefreshesTheGroupsATextMessageCarries(t *testing.T) {
	c, events := collect(t)
	before := teamspeak.ClientEntry{
		ID: 5, UID: new(teamspeak.UID("u5")), Nickname: "Ann", ServerGroups: []teamspeak.ServerGroupID{6},
	}
	know(c, before)

	c.handleCommandLines(c.handler,
		"notifyclientupdated clid=5 client_servergroups=6,9 client_needed_serverquery_view_power=75")
	c.handleCommandLines(c.handler, "notifytextmessage targetmode=2 msg=hi invokerid=5 invokername=Ann invokeruid=u5")

	var msg TextMessageEvent
	var upd ClientUpdatedEvent
	for _, e := range events() {
		switch e := e.(type) {
		case TextMessageEvent:
			msg = e
		case ClientUpdatedEvent:
			upd = e
		}
	}
	if want := []teamspeak.ServerGroupID{6, 9}; !slices.Equal(msg.InvokerGroups, want) {
		t.Errorf("InvokerGroups = %v, want %v", msg.InvokerGroups, want)
	}
	if upd.ClientID != 5 || upd.Changes.ServerGroups == nil || upd.Changes.NeededServerQueryViewPower == nil {
		t.Errorf("event = %+v", upd)
	}
	if upd.Changes.Nickname != nil || upd.Changes.IsAway != nil {
		t.Errorf("event names changes the notification did not carry: %+v", upd.Changes)
	}
	if !slices.Equal(before.ServerGroups, []teamspeak.ServerGroupID{6}) {
		t.Errorf("the earlier entry was edited: %v", before.ServerGroups)
	}
}

// The group notification and the update arrive in either order, and only the
// update writes.
func TestServerGroupEvents_NeverWriteTheList(t *testing.T) {
	for _, order := range [][]string{{"added", "updated"}, {"updated", "added"}} {
		c, events := collect(t)
		know(c, teamspeak.ClientEntry{ID: 5, ServerGroups: []teamspeak.ServerGroupID{6}})

		for _, which := range order {
			switch which {
			case "added":
				c.handleCommandLines(c.handler,
					"notifyservergroupclientadded sgid=9 clid=5 name=Ann cluid=u5 invokerid=2 invokername=Admin invokeruid=adm")
				if e, _ := known(c, 5); !slices.Equal(e.ServerGroups, []teamspeak.ServerGroupID{6}) && which == order[0] {
					t.Errorf("%v: the group event wrote the list: %v", order, e.ServerGroups)
				}
			case "updated":
				c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_servergroups=6,9")
			}
		}

		e, _ := known(c, 5)
		if !slices.Equal(e.ServerGroups, []teamspeak.ServerGroupID{6, 9}) {
			t.Errorf("%v: groups = %v, want [6 9]", order, e.ServerGroups)
		}

		var added ClientServerGroupAddedEvent
		for _, ev := range events() {
			if a, ok := ev.(ClientServerGroupAddedEvent); ok {
				added = a
			}
		}
		want := ClientServerGroupAddedEvent{ClientServerGroupChange: ClientServerGroupChange{
			GroupID: 9, ClientID: 5, Nickname: "Ann", UID: "u5", InvokerID: 2, InvokerName: "Admin", InvokerUID: "adm",
		}}
		if added != want {
			t.Errorf("%v: event = %+v, want %+v", order, added, want)
		}
	}
}

func TestServerGroupRemoved_IsDelivered(t *testing.T) {
	c := newTestClient(t)
	got := make(chan ClientServerGroupRemovedEvent, 1)
	c.OnClientServerGroupRemoved(func(e ClientServerGroupRemovedEvent) { got <- e })

	c.handleCommandLines(c.handler,
		"notifyservergroupclientdeleted sgid=9 clid=5 name=Ann cluid=u5 invokerid=0 invokername=Server invokeruid=")
	e := receive(t, got)
	if e.GroupID != 9 || e.ClientID != 5 || e.InvokerName != "Server" || e.InvokerID != 0 {
		t.Errorf("event = %+v", e)
	}
}

func TestClientUpdated_NothingCarriedGivesNilChanges(t *testing.T) {
	c := newTestClient(t)
	got := make(chan ClientUpdatedEvent, 1)
	c.OnClientUpdated(func(e ClientUpdatedEvent) { got <- e })

	c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_flag_talking=1")
	if e := receive(t, got); !reflect.DeepEqual(e.Changes, teamspeak.ClientChanges{}) {
		t.Errorf("Changes = %+v, want none", e.Changes)
	}
}

// An update of a client not in view is reported and creates no entry.
func TestClientUpdated_UnknownClientIsNotAdded(t *testing.T) {
	c := newTestClient(t)
	got := make(chan ClientUpdatedEvent, 1)
	c.OnClientUpdated(func(e ClientUpdatedEvent) { got <- e })

	c.handleCommandLines(c.handler, "notifyclientupdated clid=44 client_away=1 client_away_message=lunch")
	e := receive(t, got)
	if e.ClientID != 44 || e.Changes.IsAway == nil || !*e.Changes.IsAway || *e.Changes.AwayMessage != "lunch" {
		t.Errorf("event = %+v", e)
	}
	if _, ok := known(c, 44); ok {
		t.Error("an update created an entry")
	}
}

func TestClientUpdated_ClearsWhatItNamesWithAZero(t *testing.T) {
	c := newTestClient(t)
	know(c, teamspeak.ClientEntry{
		ID: 5, IsAway: new(true), AwayMessage: new("lunch"), ServerGroups: []teamspeak.ServerGroupID{6},
	})

	c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_away=0 client_away_message= client_servergroups=")
	e, _ := known(c, 5)
	if e.IsAway == nil || *e.IsAway || e.AwayMessage == nil || *e.AwayMessage != "" ||
		e.ServerGroups == nil || len(e.ServerGroups) != 0 {
		t.Errorf("entry = %+v, want away cleared and no groups", e)
	}
}

func TestClientUpdated_OwnNicknameFollowsTheServer(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 9
	c.mu.Unlock()

	c.handleCommandLines(c.handler, "notifyclientupdated clid=9 client_nickname=Renamed")
	if got := ownNickname(c); got != "Renamed" {
		t.Errorf("Nickname = %q", got)
	}
	c.handleCommandLines(c.handler, "notifyclientupdated clid=10 client_nickname=Other")
	if got := ownNickname(c); got != "Renamed" {
		t.Errorf("another client's rename changed ours: %q", got)
	}
}

// A handler editing what it was given edits neither the next handler's copy nor
// the client's list.
func TestClientUpdated_ChangesAreTheEventsOwn(t *testing.T) {
	c := newTestClient(t)
	know(c, teamspeak.ClientEntry{ID: 5})
	c.OnClientUpdated(func(e ClientUpdatedEvent) {
		(*e.Changes.ServerGroups)[0] = 99
		*e.Changes.IsAway = false
	})
	seen := make(chan ClientUpdatedEvent, 1)
	c.OnClientUpdated(func(e ClientUpdatedEvent) { seen <- e })

	c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_servergroups=6,7 client_away=1")
	e := receive(t, seen)
	if !slices.Equal(*e.Changes.ServerGroups, []teamspeak.ServerGroupID{6, 7}) || !*e.Changes.IsAway {
		t.Errorf("the second handler saw the first's edit: %+v", e.Changes)
	}
	settle(t, c)
	if entry, _ := known(c, 5); !slices.Equal(entry.ServerGroups, []teamspeak.ServerGroupID{6, 7}) ||
		entry.IsAway == nil || !*entry.IsAway {
		t.Errorf("the client list was edited through an event: %+v", entry)
	}
}

// The same for an entered client: its optional fields are pointers.
func TestClientEnter_PointersAreTheEventsOwn(t *testing.T) {
	c := newTestClient(t)
	c.OnClientEnter(func(e ClientEnterEvent) { *e.IsInputMuted = false })

	c.handleCommandLines(c.handler, "notifycliententerview clid=5 client_nickname=a client_input_muted=1")
	settle(t, c)
	if entry, _ := known(c, 5); entry.IsInputMuted == nil || !*entry.IsInputMuted {
		t.Errorf("the client list was edited through an event: %+v", entry.IsInputMuted)
	}
}

func TestClientChannelGroupChanged_RefreshesOnlyTheChannelTheClientIsIn(t *testing.T) {
	c, events := collect(t)
	know(c, teamspeak.ClientEntry{ID: 5, ChannelID: 10, ChannelGroupID: new(teamspeak.ChannelGroupID(8))})

	// A group in a channel it is not in.
	c.handleCommandLines(c.handler,
		"notifyclientchannelgroupchanged clid=5 cid=11 cgid=4 cgi=11 invokerid=2 invokername=Admin invokeruid=adm")
	if e, _ := known(c, 5); e.ChannelGroupID == nil || *e.ChannelGroupID != 8 || e.ChannelGroupInheritedChannelID != nil {
		t.Errorf("a foreign channel's group was taken: %+v", e)
	}

	c.handleCommandLines(c.handler,
		"notifyclientchannelgroupchanged clid=5 cid=10 cgid=4 cgi=3 invokerid=0 invokername=Server invokeruid=")
	if e, _ := known(c, 5); e.ChannelGroupID == nil || *e.ChannelGroupID != 4 ||
		e.ChannelGroupInheritedChannelID == nil || *e.ChannelGroupInheritedChannelID != 3 {
		t.Errorf("entry = %+v, want group 4 inherited from 3", e)
	}

	var last ClientChannelGroupChangedEvent
	var n int
	for _, ev := range events() {
		if e, ok := ev.(ClientChannelGroupChangedEvent); ok {
			last = e
			n++
		}
	}
	want := ClientChannelGroupChangedEvent{
		ClientID: 5, ChannelID: 10, ChannelGroupID: 4, ChannelGroupInheritedChannelID: 3, InvokerName: "Server",
	}
	if n != 2 || last != want {
		t.Errorf("%d events, last %+v, want %+v", n, last, want)
	}
}

// Events queue in the order their packets arrived.
func TestClientUpdated_ArrivesBeforeALaterTextMessage(t *testing.T) {
	c, events := collect(t)
	know(c, teamspeak.ClientEntry{ID: 5})
	c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_away=1")
	c.handleCommandLines(c.handler, "notifytextmessage targetmode=2 msg=hi invokerid=5")

	var kinds []string
	for _, e := range events() {
		switch e.(type) {
		case ClientUpdatedEvent:
			kinds = append(kinds, "updated")
		case TextMessageEvent:
			kinds = append(kinds, "text")
		}
	}
	if !slices.Equal(kinds, []string{"updated", "text"}) {
		t.Errorf("order = %v", kinds)
	}
}

func ownNickname(c *Client) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.nickname
}
