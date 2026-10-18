//go:build integration

package client_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/internal/livetest"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// The live-state tests need two voice clients in one channel: the subject
// changes something about itself and the observer, a bystander, must hear of it
// and keep its record of the subject fresh. The shared client and the shared
// peer are those two. Anything a test changes on the server it restores.

const liveEventWait = 8 * time.Second

// livePair is the subject and the observer, with the observer's view of events.
type livePair struct {
	subject, observer *client.Client
	subjectDBID       teamspeak.ClientDBID
}

func requireLivePair(t *testing.T) livePair {
	t.Helper()
	addr := requireTeamSpeakAddr(t)
	subject := requireSharedClient(t)
	observer := requireIntegrationPeer(t, addr)

	// A client learns its channel from its own enter notification, which can
	// arrive just after Connect returns.
	for deadline := time.Now().Add(liveEventWait); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if subject.ChannelID() != 0 && observer.ChannelID() != 0 {
			break
		}
	}
	if subject.ChannelID() != observer.ChannelID() {
		t.Skipf("the shared client is in channel %d and the peer in %d: a bystander needs the same channel",
			subject.ChannelID(), observer.ChannelID())
	}

	var dbid teamspeak.ClientDBID
	clients, err := subject.ListClients(t.Context(), teamspeak.ClientListOptions{})
	requireNoErr(t, err)
	for _, entry := range clients {
		if entry.UID == subject.UID() {
			dbid = entry.DatabaseID
		}
	}
	if dbid == 0 {
		t.Fatalf("the client list has no database id for the subject: %+v", clients)
	}

	// The observer must see the subject, or nothing below can be heard.
	deadline := time.Now().Add(liveEventWait)
	for {
		if _, ok := observer.KnownClientForTest(subject.ClientID()); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Skipf("the peer does not know the shared client (clid %d) after %s", subject.ClientID(), liveEventWait)
		}
		time.Sleep(50 * time.Millisecond)
	}

	return livePair{subject: subject, observer: observer, subjectDBID: dbid}
}

// cleanupContext is a context for restoring the server: the test's own is
// already canceled by the time its cleanups run.
func cleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// listen registers a handler for the test's duration and returns the channel it
// feeds.
func listen[E any](t *testing.T, on func(func(E)) func()) <-chan E {
	t.Helper()
	ch := make(chan E, 32)
	off := on(func(e E) { ch <- e })
	t.Cleanup(off)

	return ch
}

// await returns the first event from ch that match accepts, failing if none
// comes in time.
func await[E any](t *testing.T, ch <-chan E, what string, match func(E) bool) E {
	t.Helper()
	timeout := time.After(liveEventWait)
	for {
		select {
		case e := <-ch:
			if match(e) {
				return e
			}
		case <-timeout:
			var zero E
			t.Fatalf("no %s within %s", what, liveEventWait)

			return zero
		}
	}
}

// setFields lists the fields of a changes struct that are set.
func setFields(changes teamspeak.ClientChanges) []string {
	var set []string
	v := reflect.ValueOf(changes)
	for i := range v.NumField() {
		if !v.Field(i).IsNil() {
			set = append(set, v.Type().Field(i).Name)
		}
	}
	slices.Sort(set)

	return set
}

// requireAdmin connects a ServerQuery client as the fixture's administrator, to
// act on the voice clients: the guest group that the voice clients belong to may
// not change groups, and an administrator is who does it in practice. WebQuery
// cannot receive notifications, but acting is all it is used for here.
func requireAdmin(t *testing.T) *serverquery.Client {
	t.Helper()
	var dialer serverquery.Dialer
	var opts []serverquery.Option
	switch {
	case os.Getenv("TEAMSPEAK_QUERY_KIND") == "tcp" && os.Getenv("TEAMSPEAK_QUERY_HOST") != "":
		dialer = serverquery.TCPLogin(os.Getenv("TEAMSPEAK_QUERY_HOST")+":"+os.Getenv("TEAMSPEAK_QUERY_PORT"),
			os.Getenv("TEAMSPEAK_QUERY_LOGIN_NAME"), os.Getenv("TEAMSPEAK_QUERY_LOGIN_PASSWORD"))
	case os.Getenv("TEAMSPEAK_QUERY_KIND") == "ssh" && os.Getenv("TEAMSPEAK_QUERY_SSH_HOST") != "":
		// The host key is verified: against the caller's known_hosts file, or
		// else against the key the server presents.
		addr := os.Getenv("TEAMSPEAK_QUERY_SSH_HOST") + ":" + os.Getenv("TEAMSPEAK_QUERY_SSH_PORT")
		check, err := serverquery.KnownHosts(livetest.KnownHostsFor(t, addr))
		requireNoErr(t, err)
		dialer = serverquery.SSHWith(addr,
			os.Getenv("TEAMSPEAK_QUERY_SSH_USER"), os.Getenv("TEAMSPEAK_QUERY_SSH_PASSWORD"),
			serverquery.SSHOptions{HostKeyCheck: check})
	case os.Getenv("TEAMSPEAK_QUERY_KIND") == "web" && os.Getenv("TEAMSPEAK_QUERY_URL") != "":
		dialer = serverquery.Web(os.Getenv("TEAMSPEAK_QUERY_URL"), os.Getenv("TEAMSPEAK_QUERY_API_KEY"))
	default:
		t.Skipf("no administrator query endpoint provisioned (TEAMSPEAK_QUERY_KIND=%q): "+
			"a group change needs one", os.Getenv("TEAMSPEAK_QUERY_KIND"))
	}
	admin, err := serverquery.New(dialer, append(opts, serverquery.WithServer(1))...)
	if err != nil {
		t.Fatalf("serverquery.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	requireNoErr(t, admin.Connect(ctx))
	t.Cleanup(func() {
		stop, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelStop()
		_ = admin.Disconnect(stop)
	})

	return admin
}

// temporaryGroup creates a server group for the test and deletes it afterwards,
// with the subject removed from it first.
//
// A client in any explicit group no longer has the default group's permissions,
// so the new group is a copy of it: the subject must still be able to send the
// message that follows the change.
func temporaryGroup(t *testing.T, p livePair, admin *serverquery.Client) teamspeak.ServerGroupID {
	t.Helper()
	existing, err := admin.ListServerGroups(t.Context(), teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	var template teamspeak.ServerGroupID
	for _, g := range existing {
		if g.Name == "Guest" && g.Type == teamspeak.GroupRegular {
			template = g.ID
		}
	}
	if template == 0 {
		t.Skip("the server has no regular group named Guest to copy for the temporary group")
	}
	name := fmt.Sprintf("live-state-%d", time.Now().UnixNano())
	gid, err := admin.CopyServerGroup(t.Context(), template, 0, name, teamspeak.GroupRegular)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.RemoveClientFromServerGroup(ctx, gid, p.subjectDBID)
		_ = admin.DeleteServerGroup(ctx, gid, teamspeak.GroupDeleteOptions{Force: true})
	})

	return gid
}

// groupsOfNextMessage has the subject say text in its channel and returns the
// groups the observer attaches to it.
func groupsOfNextMessage(
	t *testing.T, p livePair, texts <-chan teamspeak.TextMessageEvent, text string,
) []teamspeak.ServerGroupID {
	t.Helper()
	requireNoErr(t, p.subject.SendChannelMessage(t.Context(), text))
	msg := await(t, texts, "the subject's text message", func(e teamspeak.TextMessageEvent) bool {
		return e.InvokerID == p.subject.ClientID() && e.Message == text
	})

	return msg.InvokerGroups
}

func TestIntegration_ServerGroupChangeReachesABystanderAndFreshensItsGroups(t *testing.T) {
	p := requireLivePair(t)
	subjectID := p.subject.ClientID()
	admin := requireAdmin(t)

	added := listen(t, p.observer.OnClientServerGroupAdded)
	removed := listen(t, p.observer.OnClientServerGroupRemoved)
	updated := listen(t, p.observer.OnClientUpdated)
	texts := listen(t, p.observer.OnTextMessage)

	gid := temporaryGroup(t, p, admin)
	listUpdate := func(want bool) func(teamspeak.ClientUpdatedEvent) bool {
		return func(e teamspeak.ClientUpdatedEvent) bool {
			return e.ClientID == subjectID && e.Changes.ServerGroups != nil &&
				slices.Contains(*e.Changes.ServerGroups, gid) == want
		}
	}

	requireNoErr(t, admin.AddClientToServerGroup(t.Context(), gid, p.subjectDBID))

	add := await(t, added, "ClientServerGroupAdded", func(e client.ClientServerGroupAddedEvent) bool {
		return e.GroupID == gid
	})
	if add.ClientID != subjectID || add.UID != p.subject.UID() || add.InvokerName == "" || add.InvokerID == subjectID {
		t.Errorf("ClientServerGroupAdded = %+v, want group %d on client %d by the admin", add, gid, subjectID)
	}
	upd := await(t, updated, "ClientUpdated with the group list", listUpdate(true))
	t.Logf("ClientUpdated after the add: groups %v, fields %v, invoker %d",
		*upd.Changes.ServerGroups, setFields(upd.Changes), upd.InvokerID)

	// The message follows the group change: its invoker groups must be the new
	// ones, not what the observer learned when the subject entered view.
	if got := groupsOfNextMessage(t, p, texts, "after the group was added"); !slices.Contains(got, gid) {
		t.Errorf("InvokerGroups = %v, want it to hold the new group %d", got, gid)
	}

	requireNoErr(t, admin.RemoveClientFromServerGroup(t.Context(), gid, p.subjectDBID))
	rem := await(t, removed, "ClientServerGroupRemoved", func(e client.ClientServerGroupRemovedEvent) bool {
		return e.GroupID == gid
	})
	if rem.ClientID != subjectID || rem.UID != p.subject.UID() {
		t.Errorf("ClientServerGroupRemoved = %+v", rem)
	}
	await(t, updated, "ClientUpdated without the group", listUpdate(false))
	if got := groupsOfNextMessage(t, p, texts, "after the group was removed"); slices.Contains(got, gid) {
		t.Errorf("InvokerGroups = %v, want the removed group %d gone", got, gid)
	}
}

// changer returns a function that has the subject update itself and returns the
// update the observer hears with the field set, and one that reads the
// observer's record of the subject. The subject's state is restored afterwards.
func changer(t *testing.T, p livePair) (
	func(teamspeak.ClientUpdateOptions, func(teamspeak.ClientChanges) bool) teamspeak.ClientUpdatedEvent,
	func() teamspeak.ClientEntry,
) {
	t.Helper()
	subjectID := p.subject.ClientID()
	updated := listen(t, p.observer.OnClientUpdated)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = p.subject.UpdateClient(ctx, teamspeak.ClientUpdateOptions{
			IsAway: new(false), AwayMessage: new(""), IsInputMuted: new(false),
		})
	})

	change := func(
		options teamspeak.ClientUpdateOptions, field func(teamspeak.ClientChanges) bool,
	) teamspeak.ClientUpdatedEvent {
		requireNoErr(t, p.subject.UpdateClient(t.Context(), options))

		return await(t, updated, "ClientUpdated", func(e teamspeak.ClientUpdatedEvent) bool {
			return e.ClientID == subjectID && field(e.Changes)
		})
	}
	record := func() teamspeak.ClientEntry {
		entry, _ := p.observer.KnownClientForTest(subjectID)

		return entry
	}

	return change, record
}

func TestIntegration_AwayReachesABystanderAsExactlyTheChangedFields(t *testing.T) {
	change, record := changer(t, requireLivePair(t))
	away := func(c teamspeak.ClientChanges) bool { return c.IsAway != nil }

	e := change(teamspeak.ClientUpdateOptions{IsAway: new(true), AwayMessage: new("lunch")}, away)
	t.Logf("away: fields %v", setFields(e.Changes))
	if !*e.Changes.IsAway || e.Changes.AwayMessage == nil || *e.Changes.AwayMessage != "lunch" ||
		!slices.Equal(setFields(e.Changes), []string{"AwayMessage", "IsAway"}) || e.InvokerID != 0 {
		t.Errorf("away update = %+v (fields %v)", e, setFields(e.Changes))
	}
	if entry := record(); !entry.IsAway || entry.AwayMessage != "lunch" {
		t.Errorf("the observer's record: away %v, message %q", entry.IsAway, entry.AwayMessage)
	}

	e = change(teamspeak.ClientUpdateOptions{IsAway: new(false), AwayMessage: new("")}, away)
	t.Logf("back: fields %v", setFields(e.Changes))
	if *e.Changes.IsAway {
		t.Errorf("the clear says away: %+v", e.Changes)
	}
	if entry := record(); entry.IsAway || entry.AwayMessage != "" {
		t.Errorf("the observer's record is still away: %v %q", entry.IsAway, entry.AwayMessage)
	}
}

func TestIntegration_MuteReachesABystanderAsExactlyTheChangedField(t *testing.T) {
	change, record := changer(t, requireLivePair(t))
	muted := func(c teamspeak.ClientChanges) bool { return c.IsInputMuted != nil }

	e := change(teamspeak.ClientUpdateOptions{IsInputMuted: new(true)}, muted)
	t.Logf("muted: fields %v", setFields(e.Changes))
	if !*e.Changes.IsInputMuted || !slices.Equal(setFields(e.Changes), []string{"IsInputMuted"}) {
		t.Errorf("mute update fields %v, want exactly IsInputMuted=true", setFields(e.Changes))
	}
	if entry := record(); entry.IsInputMuted == nil || !*entry.IsInputMuted {
		t.Errorf("the observer's record: muted %v", entry.IsInputMuted)
	}

	e = change(teamspeak.ClientUpdateOptions{IsInputMuted: new(false)}, muted)
	if *e.Changes.IsInputMuted {
		t.Errorf("the unmute says muted: %+v", e.Changes)
	}
	if entry := record(); entry.IsInputMuted == nil || *entry.IsInputMuted {
		t.Errorf("the observer's record after the unmute: muted %v", entry.IsInputMuted)
	}
}

func TestIntegration_ChannelGroupChangeIsReportedAndRefreshesTheRecord(t *testing.T) {
	p := requireLivePair(t)
	ctx := t.Context()
	subjectID := p.subject.ClientID()
	channel := p.subject.ChannelID()
	admin := requireAdmin(t)
	changed := listen(t, p.observer.OnClientChannelGroupChanged)

	groups, err := admin.ListChannelGroups(ctx, teamspeak.ChannelGroupListOptions{})
	requireNoErr(t, err)
	before, _ := p.observer.KnownClientForTest(subjectID)
	var target teamspeak.ChannelGroupID
	for _, g := range groups {
		if g.Type == teamspeak.GroupRegular && g.ID != before.ChannelGroupID {
			target = g.ID
		}
	}
	if target == 0 {
		t.Skipf("the server has no regular channel group other than %d to switch to", before.ChannelGroupID)
	}
	t.Cleanup(func() {
		restore, cancel := cleanupContext()
		defer cancel()
		_ = admin.SetClientChannelGroup(restore, before.ChannelGroupID, channel, p.subjectDBID)
	})

	requireNoErr(t, admin.SetClientChannelGroup(ctx, target, channel, p.subjectDBID))
	e := await(t, changed, "ClientChannelGroupChanged", func(e client.ClientChannelGroupChangedEvent) bool {
		return e.ClientID == subjectID && e.ChannelGroupID == target
	})
	if e.ChannelID != channel || e.InvokerName == "" || e.ChannelGroupInheritedChannelID != channel {
		t.Errorf("event = %+v, want channel %d, an invoker, inherited from %d", e, channel, channel)
	}
	if after, _ := p.observer.KnownClientForTest(subjectID); after.ChannelGroupID != target {
		t.Errorf("the observer's record holds channel group %d, want %d", after.ChannelGroupID, target)
	}

	requireNoErr(t, admin.SetClientChannelGroup(ctx, before.ChannelGroupID, channel, p.subjectDBID))
	await(t, changed, "ClientChannelGroupChanged back", func(e client.ClientChannelGroupChangedEvent) bool {
		return e.ClientID == subjectID && e.ChannelGroupID == before.ChannelGroupID
	})
	if after, _ := p.observer.KnownClientForTest(subjectID); after.ChannelGroupID != before.ChannelGroupID {
		t.Errorf("the observer's record holds channel group %d after the restore, want %d",
			after.ChannelGroupID, before.ChannelGroupID)
	}
}
