//go:build integration

package client_test

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// These tests compare the view of a voice client with what the server answers
// to ListChannels and ListClients. An administrator over ServerQuery changes the
// channels; the voice client is told, and the test waits for the event of the
// last change, which the view is already ahead of, before it looks.

// treeIDs lists the ids of a tree in the order the server shows them.
func treeIDs(tree teamspeak.ChannelTree) []teamspeak.ChannelID {
	var ids []teamspeak.ChannelID
	var walk func(parent teamspeak.ChannelID)
	walk = func(parent teamspeak.ChannelID) {
		for _, ch := range tree.Children(parent) {
			ids = append(ids, ch.ID)
			walk(ch.ID)
		}
	}
	walk(0)

	return ids
}

func channelIDsOf(channels []teamspeak.Channel) []teamspeak.ChannelID {
	ids := make([]teamspeak.ChannelID, len(channels))
	for i, ch := range channels {
		ids[i] = ch.ID
	}

	return ids
}

// requireViewMatchesListing fails unless the view holds the channels the server
// lists, each under the same parent and after the same sibling, in the same
// order.
func requireViewMatchesListing(t *testing.T, v client.ServerView, admin *serverquery.Client, step string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	listing, err := admin.ListChannels(ctx, teamspeak.ChannelListOptions{})
	requireNoErr(t, err)

	if len(v.Channels()) != len(listing) {
		t.Errorf("%s: the view has %d channels, the server %d", step, len(v.Channels()), len(listing))
	}
	for _, want := range listing {
		got, ok := v.Channel(want.ID)
		switch {
		case !ok:
			t.Errorf("%s: channel %d (%s) is not in the view", step, want.ID, want.Name)
		case got.ParentID != want.ParentID || got.Order != want.Order || got.Name != want.Name:
			t.Errorf("%s: channel %d: the view has %q under %d after %d, the server %q under %d after %d",
				step, want.ID, got.Name, got.ParentID, got.Order, want.Name, want.ParentID, want.Order)
		case got.TotalClients != nil || got.TotalFamilyClients != nil:
			t.Errorf("%s: channel %d carries a client count", step, want.ID)
		}
	}
	if got, want := channelIDsOf(v.Channels()), treeIDs(teamspeak.NewChannelTree(listing)); !slices.Equal(got, want) {
		t.Errorf("%s: the view lists %v, the server's tree is %v", step, got, want)
	}
}

func waitViewLive(t *testing.T, c *client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), liveEventWait)
	defer cancel()
	requireNoErr(t, c.WaitView(ctx))
}

// The thirteen ways the server changes the order of channels: created with and
// without a place, moved to another parent and inside one, with its subchannels,
// edited, and deleted with and without subchannels. After each the view is the
// listing, including the order the server rewrote in the sibling next to the
// change without saying so.
//
//nolint:funlen // one scenario, read top to bottom
func TestIntegration_ViewTreeAfterChangesIncludingOrder(t *testing.T) {
	obs := requireSharedClient(t)
	admin := requireAdmin(t)
	ctx := t.Context()
	waitViewLive(t, obs)

	created := listen(t, obs.OnChannelCreated)
	edited := listen(t, obs.OnChannelEdited)
	moved := listen(t, obs.OnChannelMoved)
	deleted := listen(t, obs.OnChannelDeleted)

	requireViewMatchesListing(t, obs.View(), admin, "at the start")
	listing, err := admin.ListChannels(ctx, teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	var front teamspeak.ChannelID
	for _, ch := range listing {
		if ch.ParentID == 0 && ch.Order == 0 {
			front = ch.ID
		}
	}
	if front == 0 {
		t.Fatal("the server has no first channel")
	}

	create := func(name string, opts teamspeak.ChannelCreateOptions) teamspeak.ChannelID {
		opts.Name = uniqueName(name)
		cid := liveChannel(t, admin, opts)
		await(t, created, "created "+name, func(e teamspeak.ChannelCreatedEvent) bool { return e.ChannelID == cid })

		return cid
	}
	step := func(name string) {
		t.Helper()
		requireViewMatchesListing(t, obs.View(), admin, name)
	}

	a := create("va", teamspeak.ChannelCreateOptions{})
	step("create with no order")
	b := create("vb", teamspeak.ChannelCreateOptions{Order: new(teamspeak.ChannelID(0))})
	step("create first")
	c := create("vc", teamspeak.ChannelCreateOptions{Order: &front})
	step("create after the channel that was first")
	d := create("vd", teamspeak.ChannelCreateOptions{ParentID: a})
	step("create under a parent")
	e := create("ve", teamspeak.ChannelCreateOptions{ParentID: a, Order: new(teamspeak.ChannelID(0))})
	step("create first under a parent")

	requireNoErr(t, admin.MoveChannel(ctx, e, 0, teamspeak.ChannelMoveOptions{Order: &b}))
	await(t, moved, "moved e", func(m teamspeak.ChannelMovedEvent) bool { return m.ChannelID == e })
	step("move to another parent")

	requireNoErr(t, admin.MoveChannel(ctx, a, b, teamspeak.ChannelMoveOptions{Order: new(teamspeak.ChannelID(0))}))
	await(t, moved, "moved a", func(m teamspeak.ChannelMovedEvent) bool { return m.ChannelID == a })
	step("move a channel with its subchannels")

	requireNoErr(t, admin.EditChannel(ctx, c, teamspeak.ChannelEditOptions{Order: &b}))
	await(t, edited, "edited c order", func(m teamspeak.ChannelEditedEvent) bool {
		return m.ChannelID == c && m.Changes.Order != nil
	})
	step("edit the order")

	requireNoErr(t, admin.EditChannel(ctx, c, teamspeak.ChannelEditOptions{Name: new(uniqueName("vr"))}))
	await(t, edited, "edited c name", func(m teamspeak.ChannelEditedEvent) bool {
		return m.ChannelID == c && m.Changes.Name != nil
	})
	step("rename")

	requireNoErr(t, admin.DeleteChannel(ctx, e, teamspeak.ChannelDeleteOptions{}))
	await(t, deleted, "deleted e", func(m teamspeak.ChannelDeletedEvent) bool { return m.ChannelID == e })
	step("delete a middle sibling")

	// The subchannels go first, each with its own event, then the channel.
	requireNoErr(t, admin.DeleteChannel(ctx, b, teamspeak.ChannelDeleteOptions{Force: true}))
	await(t, deleted, "deleted b", func(m teamspeak.ChannelDeletedEvent) bool { return m.ChannelID == b })
	step("delete a channel with subchannels")
	if _, ok := obs.View().Channel(d); ok {
		t.Errorf("channel %d, under the deleted channel, is still in the view", d)
	}

	requireNoErr(t, admin.DeleteChannel(ctx, c, teamspeak.ChannelDeleteOptions{}))
	await(t, deleted, "deleted c", func(m teamspeak.ChannelDeletedEvent) bool { return m.ChannelID == c })
	step("back to the start")
}

// A client that joins a channel three levels down is sent that channel and its
// ancestors first, then its own channel's clients, then the rest of the tree.
// Once the list is finished the view is the listing, and holds the clients of
// the own channel only, whoever else is on the server.
//
//nolint:funlen // one scenario, read top to bottom
func TestIntegration_ViewWelcomeEqualsListing(t *testing.T) {
	admin := requireAdmin(t)
	ctx := t.Context()
	// Someone else on the server, in another channel, who must not be in the view.
	other := requireSharedClient(t)

	top := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("w1")})
	mid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("w2"), ParentID: top})
	low := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("w3"), ParentID: mid})
	liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("w4"), ParentID: top, Order: &mid})
	lowName := ""
	listing, err := admin.ListChannels(ctx, teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	for _, ch := range listing {
		if ch.ID == low {
			lowName = ch.Name
		}
	}
	topName, midName := "", ""
	for _, ch := range listing {
		switch ch.ID {
		case top:
			topName = ch.Name
		case mid:
			midName = ch.Name
		}
	}

	c := liveClient(t, uniqueName("viewer"), client.WithDefaultChannel(topName+"/"+midName+"/"+lowName))
	waitViewLive(t, c)

	v := c.View()
	if v.Status != client.ViewLive {
		t.Fatalf("Status = %v", v.Status)
	}
	requireViewMatchesListing(t, v, admin, "after connecting")
	if got := channelIDsOf(v.Path(low)); !slices.Equal(got, []teamspeak.ChannelID{top, mid, low}) {
		t.Errorf("Path(%d) = %v, want %v: did the server put the client in the channel asked for?",
			low, got, []teamspeak.ChannelID{top, mid, low})
	}

	// Who the server lists in the own channel, voice clients only.
	own := c.ChannelID()
	clients, err := admin.ListClients(ctx, teamspeak.ClientListOptions{})
	requireNoErr(t, err)
	var inOwn, voice []teamspeak.ClientID
	for _, e := range clients {
		if e.Type != teamspeak.ClientTypeVoice {
			continue
		}
		voice = append(voice, e.ID)
		if e.ChannelID == own {
			inOwn = append(inOwn, e.ID)
		}
	}
	slices.Sort(inOwn)
	seen := make([]teamspeak.ClientID, 0, len(inOwn))
	for _, e := range v.ClientsIn(own) {
		seen = append(seen, e.ID)
	}
	if !slices.Equal(seen, inOwn) {
		t.Errorf("ClientsIn(%d) = %v, the server lists %v", own, seen, inOwn)
	}
	if got := len(v.Clients()); got != len(inOwn) {
		t.Errorf("the view knows %d clients, all of them should be in the own channel (%d)", got, len(inOwn))
	}
	if len(voice) < 2 {
		t.Errorf("the server lists %v: expected the other client, in another channel", voice)
	}
	if _, ok := v.Client(other.ClientID()); ok && other.ChannelID() != own {
		t.Errorf("the view knows client %d in channel %d, which this client is not subscribed to",
			other.ClientID(), other.ChannelID())
	}
	if v.Self == nil || v.Self.ID != c.ClientID() || v.Self.ChannelID != own {
		t.Errorf("Self = %+v, ClientID = %d, ChannelID = %d", v.Self, c.ClientID(), own)
	}
}

// A channel created while a client is connected is what the next client to
// join is sent of it: the notification carries only what the creator gave, and
// the view fills the rest with the server's defaults.
func TestIntegration_ViewCreatedChannelEqualsWelcome(t *testing.T) {
	admin := requireAdmin(t)
	obs := requireSharedClient(t)
	waitViewLive(t, obs)

	created := listen(t, obs.OnChannelCreated)
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("vcd")})
	await(t, created, "created", func(e teamspeak.ChannelCreatedEvent) bool { return e.ChannelID == cid })

	later := liveClient(t, uniqueName("viewer"))
	waitViewLive(t, later)

	seen, ok := obs.View().Channel(cid)
	if !ok {
		t.Fatalf("channel %d is not in the first view", cid)
	}
	listed, ok := later.View().Channel(cid)
	if !ok {
		t.Fatalf("channel %d is not in the second view", cid)
	}

	// Derived or unknowable to the first view: the order is the server's to
	// settle, the counts and the empty time come only with a listing, the codec
	// encryption follows a server setting, the quota is TeamSpeak 6 only and
	// the unique identifier only comes with a notification there.
	drop := func(ch teamspeak.Channel) teamspeak.Channel {
		ch = ch.Clone()
		ch.Order, ch.TotalClients, ch.TotalFamilyClients, ch.NeededSubscribePower = 0, nil, nil, nil
		ch.EmptyFor, ch.IsUnencrypted, ch.StorageQuota, ch.UID, ch.FilePath = nil, nil, nil, "", ""

		return ch
	}
	if !reflect.DeepEqual(drop(seen), drop(listed)) {
		t.Errorf("the first view holds\n%+v\nthe client that joined later holds\n%+v", drop(seen), drop(listed))
	}
	if seen.UID != "" && seen.UID != listed.UID {
		t.Errorf("UID = %q in the first view, %q in the second", seen.UID, listed.UID)
	}
	if seen.Codec != 4 || seen.MaxClients != -1 {
		t.Errorf("Codec = %d, MaxClients = %d, want 4 and -1", seen.Codec, seen.MaxClients)
	}
}
