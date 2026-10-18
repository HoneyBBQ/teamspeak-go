//go:build integration

package serverquery_test

// Integration tests for the server events a query connection receives: a
// client moving and entering, channels created, edited, moved and deleted, and
// the server edited. Events reach the transports that keep a session (raw TCP
// and SSH); WebQuery has no session, so it is left out. Each test registers
// before it acts, and waits for the one event it caused, which it picks out by
// the ids and names it made.

import (
	"context"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/prop"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// eventWait is how long an event is waited for.
const eventWait = 20 * time.Second

// awaitEvent registers a handler through on and returns a function that waits
// for the first event match accepts, failing the test when none arrives.
func awaitEvent[T any](t *testing.T, on func(func(T)) func(), what string, match func(T) bool) func() T {
	t.Helper()
	got := make(chan T, 1)
	remove := on(func(e T) {
		if !match(e) {
			return
		}
		select {
		case got <- e:
		default:
		}
	})
	t.Cleanup(remove)

	return func() T {
		t.Helper()
		select {
		case e := <-got:
			return e
		case <-time.After(eventWait):
			t.Fatalf("no %s event within %v", what, eventWait)

			var zero T

			return zero
		}
	}
}

// eventTransports runs body over the transports that deliver events.
func eventTransports(t *testing.T, body adminBody) {
	t.Helper()
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		if transport == "web" {
			t.Skip("WebQuery has no session, so it delivers no events")
		}
		body(t, c, family, transport)
	})
}

// A client moved into the channel the query connection is in is announced, with
// who moved it and why; a client that connects is announced as entering.
func TestQueryEvents_MoveAndEnter(t *testing.T) {
	eventTransports(t, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		me, err := c.WhoAmI(ctx)
		if err != nil {
			t.Fatalf("WhoAmI: %v", err)
		}
		nickname := "ts-go-ev-" + uniqueStamp()[:6]

		entered := awaitEvent(t, c.OnClientEnter, "client enter", func(e teamspeak.ClientEnterEvent) bool {
			return e.Nickname == nickname
		})
		voice := voiceClient(t, nickname)
		enter := entered()
		isVoice := enter.Type == teamspeak.ClientTypeVoice && enter.UID == voice.UID() && enter.ID == voice.ClientID()
		if !isVoice || enter.ChannelID == 0 {
			t.Errorf("the enter event = %+v, want voice client %d (%s) in a channel",
				enter.ClientEntry, voice.ClientID(), voice.UID())
		}

		// The voice client joins the default channel, which may be the query
		// connection's own: it goes to a channel of its own first, so that the
		// move below is a move either way.
		away := scratchChannel(t, c, "ts-go-ev-away-")
		err = c.MoveClient(ctx, voice.ClientID(), away, teamspeak.ClientMoveOptions{})
		if err != nil {
			t.Fatalf("MoveClient away: %v", err)
		}

		moved := awaitEvent(t, c.OnClientMoved, "client moved", func(e teamspeak.ClientMovedEvent) bool {
			return e.ClientID == voice.ClientID() && e.TargetChannelID == me.ChannelID
		})
		err = c.MoveClient(ctx, voice.ClientID(), me.ChannelID, teamspeak.ClientMoveOptions{})
		if err != nil {
			t.Fatalf("MoveClient: %v", err)
		}
		move := moved()
		if move.Reason != teamspeak.ReasonMoved || move.InvokerID != me.ClientID {
			t.Errorf("the move event = %+v, want reason %v by client %d", move, teamspeak.ReasonMoved, me.ClientID)
		}
		t.Logf("the move event: %+v", move)
	})
}

// A channel is created, edited, given a description and a password, moved and
// deleted, and the server renamed, and each change reaches the connection as
// its own event.
//
//nolint:funlen // one channel through every change, step by step
func TestQueryEvents_ChannelAndServerChanges(t *testing.T) {
	eventTransports(t, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		alpha := channelIDByName(t, c, "Alpha")
		name := "ts-go-ev-" + uniqueStamp()

		info, err := c.GetServerInfo(ctx)
		if err != nil {
			t.Fatalf("GetServerInfo: %v", err)
		}
		serverName := info[prop.VirtualServerName]
		cleanup(t, "the server's name", func(ctx context.Context) error {
			return c.EditServer(ctx, teamspeak.Properties{prop.VirtualServerName: serverName})
		})
		cleanup(t, "the channel", func(ctx context.Context) error { return deleteChannelsNamed(ctx, c, name) })

		var cid teamspeak.ChannelID
		created := awaitEvent(t, c.OnChannelCreated, "channel created", func(e teamspeak.ChannelCreatedEvent) bool {
			return e.Changes.Name != nil && *e.Changes.Name == name
		})
		cid, err = c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: name, Topic: new("t1"), IsPermanent: new(true)})
		if err != nil {
			t.Fatalf("CreateChannel: %v", err)
		}
		made := created()
		if made.ChannelID != cid || made.Changes.Topic == nil || *made.Changes.Topic != "t1" ||
			made.Changes.IsPermanent == nil || !*made.Changes.IsPermanent {
			t.Errorf("the created event = %+v, want channel %d with topic t1, permanent", made, cid)
		}

		edited := awaitEvent(t, c.OnChannelEdited, "channel edited",
			func(e teamspeak.ChannelEditedEvent) bool { return e.ChannelID == cid })
		err = c.EditChannel(ctx, cid, teamspeak.ChannelEditOptions{Topic: new("t2")})
		if err != nil {
			t.Fatalf("EditChannel topic: %v", err)
		}
		edit := edited()
		if edit.Changes.Topic == nil || *edit.Changes.Topic != "t2" || edit.Reason != teamspeak.ReasonChannelEdit {
			t.Errorf("the edited event = %+v, want topic t2 with reason %v", edit, teamspeak.ReasonChannelEdit)
		}

		described := awaitEvent(t, c.OnChannelDescriptionChanged, "description changed",
			func(e teamspeak.ChannelDescriptionChangedEvent) bool { return e.ChannelID == cid })
		err = c.EditChannel(ctx, cid, teamspeak.ChannelEditOptions{Description: new("text")})
		if err != nil {
			t.Fatalf("EditChannel description: %v", err)
		}
		described()

		locked := awaitEvent(t, c.OnChannelPasswordChanged, "password changed",
			func(e teamspeak.ChannelPasswordChangedEvent) bool { return e.ChannelID == cid })
		err = c.EditChannel(ctx, cid, teamspeak.ChannelEditOptions{Password: new("pw-ev")})
		if err != nil {
			t.Fatalf("EditChannel password: %v", err)
		}
		locked()

		moved := awaitEvent(t, c.OnChannelMoved, "channel moved",
			func(e teamspeak.ChannelMovedEvent) bool { return e.ChannelID == cid })
		err = c.MoveChannel(ctx, cid, alpha, teamspeak.ChannelMoveOptions{})
		if err != nil {
			t.Fatalf("MoveChannel: %v", err)
		}
		if move := moved(); move.ParentID != alpha {
			t.Errorf("the moved event = %+v, want parent %d", move, alpha)
		}

		deleted := awaitEvent(t, c.OnChannelDeleted, "channel deleted",
			func(e teamspeak.ChannelDeletedEvent) bool { return e.ChannelID == cid })
		err = c.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		if err != nil {
			t.Fatalf("DeleteChannel: %v", err)
		}
		deleted()

		renamed := awaitEvent(t, c.OnServerEdited, "server edited", func(e teamspeak.ServerEditedEvent) bool {
			_, ok := e.Changes[prop.VirtualServerName]

			return ok
		})
		err = c.EditServer(ctx, teamspeak.Properties{prop.VirtualServerName: serverName + " (ev)"})
		if err != nil {
			t.Fatalf("EditServer: %v", err)
		}
		if got := renamed().Changes[prop.VirtualServerName]; got != serverName+" (ev)" {
			t.Errorf("the server edited event named %q, want %q", got, serverName+" (ev)")
		}
	})
}
