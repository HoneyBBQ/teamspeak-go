//go:build integration

package client_test

import (
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

// What a move says when the server says less: a client's own move names no
// invoker, and TeamSpeak 3 sends no cfid on any move, so the channel the client
// came from is the one the roster had it in. Measured on TeamSpeak 3 3.13.8 and
// TeamSpeak 6 6.0.0.
func TestIntegration_MovesNameTheirInvokerAndOrigin(t *testing.T) {
	admin := requireAdminWith(t)
	watcher := liveClient(t, "rec-watch-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	mover := liveClient(t, "rec-move-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	moved := listen(t, watcher.OnClientMoved)

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: "ts-go-rec-" + strconv.FormatInt(time.Now().UnixNano(), 36), IsSemiPermanent: new(true),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		_ = admin.DeleteChannel(t.Context(), cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	// A move is only told of a client in view: subscribe to every channel.
	requireNoErr(t, watcher.SubscribeAllChannels(t.Context()))
	time.Sleep(time.Second)
	home := mover.ChannelID()

	own := func(e client.ClientMovedEvent) bool { return e.ClientID == mover.ClientID() }
	requireNoErr(t, mover.MoveClient(t.Context(), mover.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	got := await(t, moved, "the mover's own move", own)
	t.Logf("own move: %+v", got)
	if got.Reason != teamspeak.ReasonNone || got.InvokerID != 0 || got.InvokerName != "" || got.InvokerUID != "" {
		t.Errorf("a move of its own names an invoker: %+v", got)
	}
	if got.TargetChannelID != cid || got.FromChannelID == nil || *got.FromChannelID != home {
		t.Errorf("own move = from %v to %d, want from %d to %d", got.FromChannelID, got.TargetChannelID, home, cid)
	}

	requireNoErr(t, admin.MoveClient(t.Context(), mover.ClientID(), home, teamspeak.ClientMoveOptions{}))
	got = await(t, moved, "the admin's move", own)
	t.Logf("admin move: %+v", got)
	if got.Reason != teamspeak.ReasonMoved || got.InvokerID == 0 || got.InvokerName == "" {
		t.Errorf("an admin move names its invoker: %+v", got)
	}
	if got.TargetChannelID != home || got.FromChannelID == nil || *got.FromChannelID != cid {
		t.Errorf("admin move = from %v to %d, want from %d to %d", got.FromChannelID, got.TargetChannelID, cid, home)
	}
}

// A clientlist row carries what its flag brings and nothing else: a field no
// flag was given for is absent, not false, 0 or empty. Measured on TeamSpeak 3
// 3.13.8 and TeamSpeak 6 6.0.0.
//
//nolint:gocyclo,cyclop // one check per flag
func TestIntegration_ListClientsFlagsBringTheirFields(t *testing.T) {
	admin := requireAdminWith(t)
	subject := liveClient(t, "rec-list-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	time.Sleep(time.Second)

	find := func(options teamspeak.ClientListOptions) teamspeak.ClientEntry {
		t.Helper()
		list, err := admin.ListClients(t.Context(), options)
		requireNoErr(t, err)
		for _, e := range list {
			if e.ID == subject.ClientID() {
				return e
			}
		}
		t.Fatalf("client %d is not in the list", subject.ClientID())

		return teamspeak.ClientEntry{}
	}

	bare := find(teamspeak.ClientListOptions{OmitUID: true})
	if bare.Nickname == "" || bare.ChannelID == 0 || bare.DatabaseID == 0 {
		t.Errorf("a bare row lacks what every row has: %+v", bare)
	}
	if bare.UID != nil || bare.ServerGroups != nil || bare.IsAway != nil || bare.IsRecording != nil ||
		bare.IsTalker != nil || bare.ChannelGroupID != nil || bare.IdleTime != nil || !bare.Created.IsZero() {
		t.Errorf("a bare row carries what a flag brings: %+v", bare)
	}
	if got := find(teamspeak.ClientListOptions{}); got.UID == nil || *got.UID != subject.UID() {
		t.Errorf("-uid: %v", got.UID)
	}
	if got := find(teamspeak.ClientListOptions{OmitUID: true, Away: true}); got.IsAway == nil || *got.IsAway ||
		got.AwayMessage == nil || got.UID != nil {
		t.Errorf("-away: %+v", got)
	}
	if got := find(teamspeak.ClientListOptions{OmitUID: true, Voice: true}); got.IsRecording == nil ||
		got.IsTalker == nil || got.IsAway != nil {
		t.Errorf("-voice: %+v", got)
	}
	if got := find(teamspeak.ClientListOptions{OmitUID: true, Groups: true}); got.ServerGroups == nil ||
		got.ChannelGroupID == nil || got.ChannelGroupInheritedChannelID == nil {
		t.Errorf("-groups: %+v", got)
	}
	if got := find(teamspeak.ClientListOptions{OmitUID: true, Times: true}); got.IdleTime == nil || got.Created.IsZero() {
		t.Errorf("-times: %+v", got)
	}
	if got := find(teamspeak.ClientListOptions{OmitUID: true, Info: true, Country: true}); got.Version == nil ||
		got.Platform == nil || got.Country == nil {
		t.Errorf("-info -country: %+v", got)
	}
}

// channellist and a channel notification never carry the description, and
// channelinfo does.
func TestIntegration_ChannelDescriptionIsAbsentUnlessAsked(t *testing.T) {
	admin := requireAdminWith(t)
	watcher := liveClient(t, "rec-desc-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	changed := listen(t, watcher.OnChannelDescriptionChanged)

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: "ts-go-desc-" + strconv.FormatInt(time.Now().UnixNano(), 36), IsSemiPermanent: new(true),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		_ = admin.DeleteChannel(t.Context(), cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Description: new("the text")}))
	await(t, changed, "the description change", func(e client.ChannelDescriptionChangedEvent) bool {
		return e.ChannelID == cid
	})

	list, err := admin.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	for _, ch := range list {
		if ch.ID == cid && ch.Description != nil {
			t.Errorf("channellist carried a description: %q", *ch.Description)
		}
	}
	if ch, ok := watcher.View().Channel(cid); !ok {
		t.Error("the view lacks the channel")
	} else if ch.Description != nil {
		t.Errorf("the view holds a description: %q", *ch.Description)
	}
	info, err := admin.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	if info.Description == nil || *info.Description != "the text" {
		t.Errorf("channelinfo description = %v, want the text", info.Description)
	}
}
