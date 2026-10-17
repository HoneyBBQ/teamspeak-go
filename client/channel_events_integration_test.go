//go:build integration

package client_test

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// These tests act as an administrator over ServerQuery and watch what two kinds
// of client hear: a voice client that is a bystander, and, where the fixture
// offers raw TCP, the administrator's own query connection with its default
// categories. Everything a test creates or changes is restored.

// channelAPI is what the voice and the ServerQuery client both offer.
type channelAPI interface {
	OnChannelCreated(func(teamspeak.ChannelCreatedEvent)) func()
	OnChannelEdited(func(teamspeak.ChannelEditedEvent)) func()
	OnChannelMoved(func(teamspeak.ChannelMovedEvent)) func()
	OnChannelDeleted(func(teamspeak.ChannelDeletedEvent)) func()
	OnChannelDescriptionChanged(func(teamspeak.ChannelDescriptionChangedEvent)) func()
	OnChannelPasswordChanged(func(teamspeak.ChannelPasswordChangedEvent)) func()
	OnServerEdited(func(teamspeak.ServerEditedEvent)) func()
	OnNotification(func(teamspeak.NotificationEvent)) func()
}

var (
	_ channelAPI = (*client.Client)(nil)
	_ channelAPI = (*serverquery.Client)(nil)
)

// watched is everything one client heard of channels and the server.
type watched struct {
	name    string
	created <-chan teamspeak.ChannelCreatedEvent
	edited  <-chan teamspeak.ChannelEditedEvent
	moved   <-chan teamspeak.ChannelMovedEvent
	deleted <-chan teamspeak.ChannelDeletedEvent
	desc    <-chan teamspeak.ChannelDescriptionChangedEvent
	pass    <-chan teamspeak.ChannelPasswordChangedEvent
	server  <-chan teamspeak.ServerEditedEvent
	notes   <-chan teamspeak.NotificationEvent
}

func watch(t *testing.T, name string, c channelAPI) *watched {
	t.Helper()

	return &watched{
		name:    name,
		created: listen(t, c.OnChannelCreated),
		edited:  listen(t, c.OnChannelEdited),
		moved:   listen(t, c.OnChannelMoved),
		deleted: listen(t, c.OnChannelDeleted),
		desc:    listen(t, c.OnChannelDescriptionChanged),
		pass:    listen(t, c.OnChannelPasswordChanged),
		server:  listen(t, c.OnServerEdited),
		notes:   listen(t, c.OnNotification),
	}
}

// watchers returns the voice bystander, and the administrator's own query
// connection when the fixture is raw TCP (TeamSpeak 3). The query side is nil,
// and said so, otherwise.
func watchers(t *testing.T, p livePair, admin *serverquery.Client) (voice, query *watched) {
	t.Helper()
	voice = watch(t, "voice bystander", p.observer)
	if os.Getenv("TEAMSPEAK_QUERY_KIND") == "tcp" || os.Getenv("TEAMSPEAK_QUERY_KIND") == "ssh" {
		query = watch(t, "query connection", admin)
	} else {
		t.Logf("SKIP query side: TEAMSPEAK_QUERY_KIND=%q is neither raw TCP nor SSH, and WebQuery receives no notifications",
			os.Getenv("TEAMSPEAK_QUERY_KIND"))
	}

	return voice, query
}

func each(ws ...*watched) []*watched {
	return slices.DeleteFunc(ws, func(w *watched) bool { return w == nil })
}

func fieldsSet(v any) []string {
	var set []string
	rv := reflect.ValueOf(v)
	for i := range rv.NumField() {
		if !rv.Field(i).IsNil() {
			set = append(set, rv.Type().Field(i).Name)
		}
	}
	slices.Sort(set)

	return set
}

// liveChannel creates a permanent channel for the test and deletes it after.
func liveChannel(t *testing.T, admin *serverquery.Client, opts teamspeak.ChannelCreateOptions) teamspeak.ChannelID {
	t.Helper()
	opts.IsPermanent = new(true)
	cid, err := admin.CreateChannel(t.Context(), opts)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})

	return cid
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

func TestIntegration_ChannelLifecycleReachesABystanderAndAQueryClient(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	voice, query := watchers(t, p, admin)
	start := time.Now()

	name := uniqueName("lc")
	parent := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: name + "-parent"})
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{
		Name: name, Topic: new("t1"), MaxClients: new(int32(5)),
	})
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Topic: new("t2")}))
	requireNoErr(t, admin.MoveChannel(t.Context(), cid, parent, teamspeak.ChannelMoveOptions{}))
	requireNoErr(t, admin.DeleteChannel(t.Context(), cid, teamspeak.ChannelDeleteOptions{}))

	for _, w := range each(voice, query) {
		t.Run(w.name, func(t *testing.T) {
			created := await(t, w.created, "ChannelCreated", func(e teamspeak.ChannelCreatedEvent) bool { return e.ChannelID == cid })
			t.Logf("created: parent %d, fields %v, invoker %q (%d), after %s",
				created.ParentID, fieldsSet(created.Changes), created.InvokerName, created.InvokerID, time.Since(start))
			if created.Changes.Name == nil || *created.Changes.Name != name || created.Changes.Topic == nil ||
				*created.Changes.Topic != "t1" || created.Changes.IsPermanent == nil || !*created.Changes.IsPermanent ||
				created.Changes.MaxClients == nil || *created.Changes.MaxClients != 5 ||
				created.Changes.Description != nil || created.InvokerName == "" || created.InvokerID == 0 {
				t.Errorf("created = %+v", created)
			}

			edited := await(t, w.edited, "ChannelEdited", func(e teamspeak.ChannelEditedEvent) bool { return e.ChannelID == cid })
			t.Logf("edited: reason %v, fields %v, invoker %q", edited.Reason, fieldsSet(edited.Changes), edited.InvokerName)
			if edited.Reason != teamspeak.ReasonChannelEdit || !slices.Equal(fieldsSet(edited.Changes), []string{"Topic"}) ||
				*edited.Changes.Topic != "t2" || edited.InvokerID == 0 {
				t.Errorf("edited = %+v", edited)
			}

			moved := await(t, w.moved, "ChannelMoved", func(e teamspeak.ChannelMovedEvent) bool { return e.ChannelID == cid })
			t.Logf("moved: parent %d, order %d, reason %v, invoker %q", moved.ParentID, moved.Order, moved.Reason, moved.InvokerName)
			if moved.ParentID != parent || moved.InvokerID == 0 {
				t.Errorf("moved = %+v", moved)
			}

			deleted := await(t, w.deleted, "ChannelDeleted", func(e teamspeak.ChannelDeletedEvent) bool { return e.ChannelID == cid })
			t.Logf("deleted: invoker %q (%d)", deleted.InvokerName, deleted.InvokerID)
			if deleted.InvokerID == 0 || deleted.InvokerName == "" {
				t.Errorf("deleted = %+v", deleted)
			}
		})
	}
}

// An emptied temporary channel is deleted by the server.
func TestIntegration_TemporaryChannelIsDeletedByTheServerWhenItEmpties(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	voice, query := watchers(t, p, admin)
	home := p.subject.ChannelID()

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: uniqueName("tmp"),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.MoveClient(ctx, p.subject.ClientID(), home, teamspeak.ClientMoveOptions{})
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	// Creating a channel moves its creator into it, so the administrator has to
	// leave as well, or the channel is never empty.
	me, err := admin.WhoAmI(t.Context())
	requireNoErr(t, err)
	requireNoErr(t, admin.MoveClient(t.Context(), p.subject.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	requireNoErr(t, admin.MoveClient(t.Context(), p.subject.ClientID(), home, teamspeak.ClientMoveOptions{}))
	requireNoErr(t, admin.MoveClient(t.Context(), me.ClientID, home, teamspeak.ClientMoveOptions{}))
	left := time.Now()
	for _, w := range each(voice, query) {
		t.Run(w.name, func(t *testing.T) {
			deleted := await(t, w.deleted, "ChannelDeleted by the server",
				func(e teamspeak.ChannelDeletedEvent) bool { return e.ChannelID == cid })
			t.Logf("deleted %s after the last client left: invoker %q (%d, %q)",
				time.Since(left).Round(time.Millisecond), deleted.InvokerName, deleted.InvokerID, deleted.InvokerUID)
			if deleted.InvokerName != "Server" || deleted.InvokerID != 0 {
				t.Errorf("deleted = %+v, want the server", deleted)
			}
		})
	}
}

func TestIntegration_DescriptionAndPasswordChangesAreReported(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	voice, query := watchers(t, p, admin)
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("dp")})

	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Description: new("a description")}))
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Password: new("hunter2")}))
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Password: new("")}))

	for _, w := range each(voice, query) {
		t.Run(w.name, func(t *testing.T) {
			sameChannel := func(e teamspeak.ChannelEditedEvent) bool { return e.ChannelID == cid }
			await(t, w.desc, "ChannelDescriptionChanged", func(e teamspeak.ChannelDescriptionChangedEvent) bool { return e.ChannelID == cid })
			e := await(t, w.edited, "the edit that goes with a description", sameChannel)
			if len(fieldsSet(e.Changes)) != 0 {
				t.Errorf("a description edit names %v, want none", fieldsSet(e.Changes))
			}

			await(t, w.pass, "ChannelPasswordChanged (set)", func(e teamspeak.ChannelPasswordChangedEvent) bool { return e.ChannelID == cid })
			e = await(t, w.edited, "the edit that sets the password", sameChannel)
			if e.Changes.HasPassword == nil || !*e.Changes.HasPassword {
				t.Errorf("setting a password: %+v", e.Changes)
			}
			await(t, w.pass, "ChannelPasswordChanged (cleared)", func(e teamspeak.ChannelPasswordChangedEvent) bool { return e.ChannelID == cid })
			e = await(t, w.edited, "the edit that clears the password", sameChannel)
			if e.Changes.HasPassword == nil || *e.Changes.HasPassword {
				t.Errorf("clearing the password: %+v", e.Changes)
			}
		})
	}
}

func TestIntegration_ServerEditIsReported(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	voice, query := watchers(t, p, admin)

	info, err := admin.GetServerInfo(t.Context())
	requireNoErr(t, err)
	oldName, oldWelcome := info["virtualserver_name"], info["virtualserver_welcomemessage"]
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.EditServer(ctx, teamspeak.Properties{
			"virtualserver_name": oldName, "virtualserver_welcomemessage": oldWelcome,
		})
	})

	newName := uniqueName("srv")
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_name": newName}))
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_welcomemessage": "hello " + newName}))

	for _, w := range each(voice, query) {
		t.Run(w.name, func(t *testing.T) {
			named := await(t, w.server, "ServerEdited with the name", func(e teamspeak.ServerEditedEvent) bool {
				return e.Changes["virtualserver_name"] == newName
			})
			t.Logf("name change: %v, invoker %q", named.Changes, named.InvokerName)
			if named.InvokerID == 0 || named.InvokerName == "" {
				t.Errorf("no invoker: %+v", named)
			}
			welcome := await(t, w.server, "ServerEdited for the welcome message", func(e teamspeak.ServerEditedEvent) bool {
				_, named := e.Changes["virtualserver_name"]

				return !named
			})
			t.Logf("welcome message change: %d properties", len(welcome.Changes))
			if len(welcome.Changes) != 0 {
				t.Errorf("welcome message change named %v", welcome.Changes)
			}
		})
	}
}

// The answer to a description fetch is no edit even with a real edit in flight,
// which neither is lost nor mistaken for the answer.
func TestIntegration_DescriptionFetchIsNoEditAndSurvivesAnEditInFlight(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("fetch")})
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Description: new("the text")}))

	edits := listen(t, p.subject.OnChannelEdited)
	notes := listen(t, p.subject.OnNotification)

	const rounds = 10
	var wg sync.WaitGroup
	wrong := make(chan string, rounds)
	for i := range rounds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Edits that name properties, from the other connection, while the
			// subject waits for its answer.
			_ = admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Topic: new(fmt.Sprintf("t%d", i))})
		}()
		got, err := p.subject.GetChannelDescription(t.Context(), cid)
		if err != nil || got != "the text" {
			wrong <- fmt.Sprintf("round %d: %q, %v", i, got, err)
		}
	}
	wg.Wait()
	close(wrong)
	for w := range wrong {
		t.Error(w)
	}

	// Let the notifications of the last edits arrive.
	time.Sleep(2 * time.Second)
	var reason9, realEdits int
	for len(edits) > 0 {
		e := <-edits
		if e.Reason == teamspeak.ReasonChannelUpdate {
			reason9++
		} else if e.ChannelID == cid {
			realEdits++
		}
	}
	var answers int
	for len(notes) > 0 {
		n := <-notes
		if n.Name == "notifychanneledited" && n.Params["reasonid"] == "9" {
			answers++
		}
	}
	t.Logf("%d fetches: %d answers seen as notifications, %d reason 9 events, %d real edit events", rounds, answers, reason9, realEdits)
	if reason9 != 0 || answers == 0 || realEdits < rounds {
		t.Errorf("reason 9 events %d (want 0), answers as notifications %d (want some), real edits %d (want at least %d)",
			reason9, answers, realEdits, rounds)
	}
}

func TestIntegration_SubscribeAndUnsubscribeAreReported(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("sub")})
	subscribed := listen(t, p.subject.OnChannelSubscribed)
	unsubscribed := listen(t, p.subject.OnChannelUnsubscribed)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = p.subject.UnsubscribeChannel(ctx, cid)
	})

	start := time.Now()
	requireNoErr(t, p.subject.SubscribeChannel(t.Context(), cid))
	await(t, subscribed, "ChannelSubscribed", func(e teamspeak.ChannelSubscribedEvent) bool { return e.ChannelID == cid })
	t.Logf("subscribed after %s", time.Since(start).Round(time.Millisecond))
	requireNoErr(t, p.subject.UnsubscribeChannel(t.Context(), cid))
	await(t, unsubscribed, "ChannelUnsubscribed", func(e teamspeak.ChannelUnsubscribedEvent) bool { return e.ChannelID == cid })
	t.Logf("unsubscribed after %s", time.Since(start).Round(time.Millisecond))
}

// quiet reports whether nothing arrives on ch within d.
func quiet[E any](ch <-chan E, d time.Duration) bool {
	select {
	case <-ch:
		return false
	case <-time.After(d):
		return true
	}
}

func TestIntegration_PluginCommandReachesTheTargetedClients(t *testing.T) {
	p := requireLivePair(t)
	fromSender := listen(t, p.subject.OnPluginCommand)
	fromPeer := listen(t, p.observer.OnPluginCommand)
	subjectID, peerID := p.subject.ClientID(), p.observer.ClientID()
	named := func(name string) func(teamspeak.PluginCommandEvent) bool {
		return func(e teamspeak.PluginCommandEvent) bool { return e.Name == name }
	}

	for _, tc := range []struct {
		target     teamspeak.PluginCommandTarget
		name       string
		senderGets bool
		peerGets   bool
	}{
		{teamspeak.PluginToChannel(), "ch", true, true},
		{teamspeak.PluginToServer(), "srv", true, true},
		{teamspeak.PluginToClient(peerID), "peer", false, true},
		{teamspeak.PluginToClient(subjectID), "self", true, false},
	} {
		start := time.Now()
		requireNoErr(t, p.subject.SendPluginCommand(t.Context(), "b2 "+tc.name, "a b|c/d", tc.target))
		if tc.peerGets {
			e := await(t, fromPeer, "the peer's plugin command "+tc.name, named("b2 "+tc.name))
			t.Logf("%s: peer got it after %s", tc.name, time.Since(start).Round(time.Millisecond))
			if e.Data != "a b|c/d" || e.InvokerID != subjectID || e.InvokerName == "" {
				t.Errorf("%s: %+v", tc.name, e)
			}
		} else if !quiet(fromPeer, time.Second) {
			t.Errorf("%s: the peer received a command not addressed to it", tc.name)
		}
		if tc.senderGets {
			await(t, fromSender, "the sender's own plugin command "+tc.name, named("b2 "+tc.name))
		} else if !quiet(fromSender, time.Second) {
			t.Errorf("%s: the sender received a command it addressed to another", tc.name)
		}
	}
}

func TestIntegration_ChatComposingReachesOnlyTheTarget(t *testing.T) {
	p := requireLivePair(t)
	atPeer := listen(t, p.observer.OnClientChatComposing)
	atSender := listen(t, p.subject.OnClientChatComposing)

	start := time.Now()
	requireNoErr(t, p.subject.SendChatComposing(t.Context(), p.observer.ClientID()))
	e := await(t, atPeer, "the typing indicator", func(teamspeak.ClientChatComposingEvent) bool { return true })
	t.Logf("typing indicator after %s", time.Since(start).Round(time.Millisecond))
	if e.ClientID != p.subject.ClientID() || e.UID != p.subject.UID() {
		t.Errorf("event = %+v", e)
	}
	if !quiet(atSender, time.Second) {
		t.Error("the sender was told it was typing")
	}
	// Closing a chat that was never opened is accepted and sends nothing.
	requireNoErr(t, p.subject.ClosePrivateChat(t.Context(), p.observer.ClientID()))
}

// What a TS3 raw query connection is not sent: the voice-only notifications.
func TestIntegration_VoiceOnlyNotificationsDoNotReachARawQueryClient(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	if kind := os.Getenv("TEAMSPEAK_QUERY_KIND"); kind != "tcp" && kind != "ssh" {
		t.Skipf("TEAMSPEAK_QUERY_KIND=%q: only a raw TCP or SSH query connection receives notifications on this fixture",
			os.Getenv("TEAMSPEAK_QUERY_KIND"))
	}
	notes := listen(t, admin.OnNotification)
	cid := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("neg")})
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = p.subject.UnsubscribeChannel(ctx, cid)
		_ = p.subject.UpdateClient(ctx, teamspeak.ClientUpdateOptions{IsAway: new(false), AwayMessage: new("")})
	})

	// Everything a voice client would hear of.
	requireNoErr(t, p.subject.SendPluginCommand(t.Context(), "neg", "d", teamspeak.PluginToServer()))
	requireNoErr(t, p.subject.SendChatComposing(t.Context(), p.observer.ClientID()))
	requireNoErr(t, p.subject.SubscribeChannel(t.Context(), cid))
	requireNoErr(t, p.subject.UnsubscribeChannel(t.Context(), cid))
	requireNoErr(t, p.subject.UpdateClient(t.Context(), teamspeak.ClientUpdateOptions{IsAway: new(true), AwayMessage: new("neg")}))
	// And a control the query connection does receive.
	requireNoErr(t, admin.EditChannel(t.Context(), cid, teamspeak.ChannelEditOptions{Topic: new("control")}))

	voiceOnly := []string{
		"notifyplugincmd", "notifyclientchatcomposing", "notifychannelsubscribed", "notifychannelunsubscribed",
		"notifyclientupdated", "notifyservergroupclientadded", "notifyservergroupclientdeleted",
		"notifyclientchannelgroupchanged",
	}
	var seen []string
	controlSeen := false
	deadline := time.After(4 * time.Second)
collect:
	for {
		select {
		case n := <-notes:
			seen = append(seen, n.Name)
			controlSeen = controlSeen || (n.Name == "notifychanneledited" && n.Params["cid"] == fmt.Sprint(uint64(cid)))
		case <-deadline:
			break collect
		}
	}
	t.Logf("the query connection heard: %s", strings.Join(seen, " "))
	if !controlSeen {
		t.Error("the control, a channel edit, never reached the query connection")
	}
	for _, name := range seen {
		if slices.Contains(voiceOnly, name) {
			t.Errorf("the query connection was sent %s", name)
		}
	}
}
