//go:build integration

package client_test

import (
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

// A client that closes a private chat, after writing in it, is heard as a
// ClientChatClosedEvent by the one it wrote to.
func TestIntegration_ClientChatClosed(t *testing.T) {
	a := liveClient(t, "audit-closer-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	b := liveClient(t, "audit-closed-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	closed := listen(t, b.OnClientChatClosed)

	requireNoErr(t, a.SendPrivateMessage(t.Context(), b.ClientID(), "hello"))
	requireNoErr(t, a.ClosePrivateChat(t.Context(), b.ClientID()))

	got := await(t, closed, "ClientChatClosedEvent", func(client.ClientChatClosedEvent) bool { return true })
	t.Logf("closed: clid %d, uid %s", got.ClientID, got.UID)
	if got.ClientID != a.ClientID() || got.UID != a.UID() {
		t.Errorf("event = %+v, want client %d, uid %s", got, a.ClientID(), a.UID())
	}
}

// A talk request carries the time it was made, in the update other clients
// receive and in clientinfo.
func TestIntegration_TalkRequestTime(t *testing.T) {
	admin := requireAdminWith(t)
	a := liveClient(t, "audit-talker-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	b := liveClient(t, "audit-watcher-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	updates := listen(t, b.OnClientUpdated)

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: "ts-go-talk-" + strconv.FormatInt(time.Now().UnixNano(), 36), IsSemiPermanent: new(true),
		NeededTalkPower: new(int32(100)),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		_ = admin.DeleteChannel(t.Context(), cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	requireNoErr(t, admin.MoveClient(t.Context(), a.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	requireNoErr(t, admin.MoveClient(t.Context(), b.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	time.Sleep(time.Second)

	before := time.Now().Add(-5 * time.Second)
	requireNoErr(t, a.UpdateClient(t.Context(), teamspeak.ClientUpdateOptions{
		IsRequestingTalk: new(true), TalkRequestMessage: new("may I?"),
	}))

	got := await(t, updates, "the talk request update", func(e client.ClientUpdatedEvent) bool {
		return e.ClientID == a.ClientID() && e.Changes.TalkRequestedAt != nil && !e.Changes.TalkRequestedAt.IsZero()
	})
	at := *got.Changes.TalkRequestedAt
	t.Logf("talk request at %v (now %v)", at, time.Now())
	if at.Before(before) || at.After(time.Now().Add(5*time.Second)) {
		t.Errorf("TalkRequestedAt = %v, want about now", at)
	}

	props, err := admin.GetClientProperties(t.Context(), a.ClientID())
	requireNoErr(t, err)
	if props["client_talk_request"] == "" || props["client_talk_request"] == "0" {
		t.Errorf("clientinfo client_talk_request = %q", props["client_talk_request"])
	}
}

// The enter, move and leave events of the voice client name the channels and,
// for an enter, the reason.
func TestIntegration_ChannelsOnEnterMoveLeave(t *testing.T) {
	admin := requireAdminWith(t)
	watcher := liveClient(t, "audit-watch-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	mover := liveClient(t, "audit-move-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36))
	entered := listen(t, watcher.OnClientEnter)
	moved := listen(t, watcher.OnClientMoved)
	left := listen(t, watcher.OnClientLeave)

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: "ts-go-view-" + strconv.FormatInt(time.Now().UnixNano(), 36), IsSemiPermanent: new(true),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		_ = admin.DeleteChannel(t.Context(), cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	home := mover.ChannelID()
	requireNoErr(t, admin.MoveClient(t.Context(), mover.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	time.Sleep(time.Second)

	// The watcher moves in beside the mover, which it is told of as coming into
	// view, because it was not subscribed to the channel the mover was in.
	requireNoErr(t, admin.MoveClient(t.Context(), watcher.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	enter := await(t, entered, "the mover coming into view", func(e client.ClientEnterEvent) bool {
		return e.ID == mover.ClientID()
	})
	t.Logf("enter: from %v, reason %v, in %d", enter.FromChannelID, enter.Reason, enter.ChannelID)
	if enter.Reason == nil || *enter.Reason != teamspeak.ReasonSubscription || enter.ChannelID != cid {
		t.Errorf("enter = reason %v in %d, want a subscription in %d", enter.Reason, enter.ChannelID, cid)
	}

	// The mover leaves the channel the watcher is in: a move, naming the channel it left.
	requireNoErr(t, admin.MoveClient(t.Context(), mover.ClientID(), home, teamspeak.ClientMoveOptions{}))
	move := await(t, moved, "the mover moving out", func(e client.ClientMovedEvent) bool {
		return e.ClientID == mover.ClientID()
	})
	t.Logf("moved: from %v to %d, reason %v", move.FromChannelID, move.TargetChannelID, move.Reason)
	// TeamSpeak 3 names no origin; the client says where the mover was.
	if move.TargetChannelID != home || move.FromChannelID == nil || *move.FromChannelID != cid {
		t.Errorf("move = from %v to %d, want from %d to %d", move.FromChannelID, move.TargetChannelID, cid, home)
	}

	requireNoErr(t, mover.Disconnect(t.Context()))
	got := await(t, left, "the mover leaving", func(e client.ClientLeaveEvent) bool {
		return e.ClientID == mover.ClientID() && e.Reason == teamspeak.ReasonDisconnect
	})
	t.Logf("leave: from %v to %v, reason %v", got.FromChannelID, got.TargetChannelID, got.Reason)
	if got.TargetChannelID == nil || *got.TargetChannelID != 0 || got.FromChannelID == nil || *got.FromChannelID != home {
		t.Errorf("leave = %+v, want a disconnect from %d", got, home)
	}
}
