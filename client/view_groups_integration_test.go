//go:build integration

package client_test

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// These tests compare the groups and server settings a voice client holds in
// its view with what the server answers to the same questions. An
// administrator over ServerQuery changes the groups; the voice client is told,
// and the test waits on ViewChangedEvent, never on a clock, before it looks.
// Every group a test creates carries the test's own prefix, and is deleted when
// the test ends, whether it passed or not.

// groupWait is how long a view may take to catch up with 124 group changes.
const groupWait = 20 * time.Second

// groupCount is above the size at which the transport sends a command in
// fragments: a list of this many groups is about 8 KB.
const groupCount = 62

// tidyGroups registers the deletion of every server and channel group whose
// name starts with prefix, and must be called before the first one is created:
// it lists the groups itself, so a group that was created but whose creation
// the test did not see to the end is deleted too.
func tidyGroups(t *testing.T, admin *serverquery.Client, prefix string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, err := range deleteGroupsNamed(ctx, admin, prefix) {
			t.Errorf("cleanup: %v", err)
		}
	})
}

// deleteGroupsNamed deletes the server and channel groups whose name starts
// with prefix, and returns what went wrong without stopping at it.
func deleteGroupsNamed(ctx context.Context, admin *serverquery.Client, prefix string) []error {
	var failed []error
	servers, err := admin.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
	if err != nil {
		failed = append(failed, fmt.Errorf("listing server groups: %w", err))
	}
	for _, g := range servers {
		if strings.HasPrefix(g.Name, prefix) {
			err = admin.DeleteServerGroup(ctx, g.ID, teamspeak.GroupDeleteOptions{Force: true})
			if err != nil {
				failed = append(failed, fmt.Errorf("deleting server group %q: %w", g.Name, err))
			}
		}
	}
	channels, err := admin.ListChannelGroups(ctx, teamspeak.ChannelGroupListOptions{})
	if err != nil {
		failed = append(failed, fmt.Errorf("listing channel groups: %w", err))
	}
	for _, g := range channels {
		if strings.HasPrefix(g.Name, prefix) {
			err = admin.DeleteChannelGroup(ctx, g.ID, teamspeak.GroupDeleteOptions{Force: true})
			if err != nil {
				failed = append(failed, fmt.Errorf("deleting channel group %q: %w", g.Name, err))
			}
		}
	}

	return failed
}

// createGroups makes n server groups and n channel groups named prefix-s0 and so on,
// and returns their ids in creation order.
func createGroups(
	t *testing.T, admin *serverquery.Client, prefix string, n int,
) ([]teamspeak.ServerGroupID, []teamspeak.ChannelGroupID) {
	t.Helper()
	servers := make([]teamspeak.ServerGroupID, 0, n)
	channels := make([]teamspeak.ChannelGroupID, 0, n)
	for i := range n {
		sg, err := admin.CreateServerGroup(t.Context(), fmt.Sprintf("%s-s%d", prefix, i), teamspeak.GroupRegular)
		requireNoErr(t, err)
		servers = append(servers, sg)
		cg, err := admin.CreateChannelGroup(t.Context(), fmt.Sprintf("%s-c%d", prefix, i), teamspeak.GroupRegular)
		requireNoErr(t, err)
		channels = append(channels, cg)
	}

	return servers, channels
}

// viewWatcher is a voice client's view and the events that say it changed.
type viewWatcher struct {
	c *client.Client
	// signal holds a token when an event has arrived since the last wait.
	signal <-chan struct{}
	// events lists every event since the client began, under mu.
	events *[]client.ViewChangedEvent
	mu     *sync.Mutex
}

// seen returns the events so far.
func (w viewWatcher) seen() []client.ViewChangedEvent {
	w.mu.Lock()
	defer w.mu.Unlock()

	return slices.Clone(*w.events)
}

// watchedClient connects a fresh client with a ViewChangedEvent handler already
// registered, so that none of the events of the welcome is missed.
func watchedClient(t *testing.T, nickname string) viewWatcher {
	t.Helper()
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	c := newClient(t, id, addr, nickname, integrationClientOptions(nil)...)
	signal := make(chan struct{}, 1)
	var mu sync.Mutex
	var events []client.ViewChangedEvent
	c.OnViewChanged(func(e client.ViewChangedEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		select {
		case signal <- struct{}{}:
		default:
		}
	})
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	waitViewLive(t, c)

	return viewWatcher{c: c, signal: signal, events: &events, mu: &mu}
}

// until returns once the view satisfies done, looking after every
// ViewChangedEvent. Whatever the view lacks at the deadline, the failure says.
func (w viewWatcher) until(t *testing.T, what string, done func(client.ServerView) (bool, string)) client.ServerView {
	t.Helper()
	deadline := time.After(groupWait)
	for {
		v := w.c.View()
		ok, why := done(v)
		if ok {
			return v
		}
		select {
		case <-w.signal:
		case <-deadline:
			t.Fatalf("%s: the view did not catch up within %s: %s", what, groupWait, why)

			return v
		}
	}
}

// listings are the groups the server lists.
func listings(t *testing.T, admin *serverquery.Client) ([]teamspeak.ServerGroup, []teamspeak.ChannelGroup) {
	t.Helper()
	servers, err := admin.ListServerGroups(t.Context(), teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	channels, err := admin.ListChannelGroups(t.Context(), teamspeak.ChannelGroupListOptions{})
	requireNoErr(t, err)

	return servers, channels
}

// matchesListing reports whether the view holds the groups the server lists,
// entry by entry and in the same order, and if not, how it differs.
func matchesListing(
	v client.ServerView, servers []teamspeak.ServerGroup, channels []teamspeak.ChannelGroup,
) (bool, string) {
	if !slices.Equal(v.ServerGroups, servers) {
		return false, fmt.Sprintf("%d server groups in the view, %d listed", len(v.ServerGroups), len(servers))
	}
	if !slices.Equal(v.ChannelGroups, channels) {
		return false, fmt.Sprintf("%d channel groups in the view, %d listed", len(v.ChannelGroups), len(channels))
	}

	return true, ""
}

// untilGroupsMatch waits for the view to equal the server's listing as it
// stands when the wait begins.
func (w viewWatcher) untilGroupsMatch(t *testing.T, admin *serverquery.Client, step string) client.ServerView {
	t.Helper()
	servers, channels := listings(t, admin)

	return w.until(t, step, func(v client.ServerView) (bool, string) {
		if !v.GroupsLoaded {
			return false, "the groups are not loaded"
		}

		return matchesListing(v, servers, channels)
	})
}

// A server with 62 groups of each kind, and then one of each renamed, copied
// and deleted: after every step the view is the server's listing.
//
//nolint:funlen // one scenario, read top to bottom
func TestIntegration_ViewGroupsEqualListing(t *testing.T) {
	admin := requireAdmin(t)
	prefix := uniqueName("vg")
	tidyGroups(t, admin, prefix)
	w := watchedClient(t, uniqueName("vgobs"))
	w.untilGroupsMatch(t, admin, "at the start")

	servers, channels := createGroups(t, admin, prefix, groupCount)
	v := w.untilGroupsMatch(t, admin, "after creating the groups")
	if len(v.ServerGroups) < groupCount || len(v.ChannelGroups) < groupCount {
		t.Fatalf("the view holds %d and %d groups", len(v.ServerGroups), len(v.ChannelGroups))
	}
	if !slices.IsSortedFunc(v.ServerGroups, func(a, b teamspeak.ServerGroup) int { return int(a.ID) - int(b.ID) }) {
		t.Error("the server groups are not in ascending id")
	}
	for _, id := range servers {
		if _, ok := v.ServerGroup(id); !ok {
			t.Errorf("server group %d is not in the view", id)
		}
	}

	renamed := prefix + "-renamed"
	requireNoErr(t, admin.RenameServerGroup(t.Context(), servers[3], renamed))
	requireNoErr(t, admin.RenameChannelGroup(t.Context(), channels[3], renamed))
	v = w.untilGroupsMatch(t, admin, "after renaming")
	if g, _ := v.ServerGroup(servers[3]); g.Name != renamed {
		t.Errorf("the renamed server group is %q", g.Name)
	}

	copiedServer, err := admin.CopyServerGroup(t.Context(), servers[4], 0, prefix+"-copy", teamspeak.GroupRegular)
	requireNoErr(t, err)
	copiedChannel, err := admin.CopyChannelGroup(t.Context(), channels[4], 0, prefix+"-copy", teamspeak.GroupRegular)
	requireNoErr(t, err)
	v = w.untilGroupsMatch(t, admin, "after copying")
	if _, ok := v.ServerGroup(copiedServer); !ok {
		t.Errorf("the copied server group %d is not in the view", copiedServer)
	}
	if _, ok := v.ChannelGroup(copiedChannel); !ok {
		t.Errorf("the copied channel group %d is not in the view", copiedChannel)
	}

	requireNoErr(t, admin.DeleteServerGroup(t.Context(), servers[5], teamspeak.GroupDeleteOptions{Force: true}))
	requireNoErr(t, admin.DeleteChannelGroup(t.Context(), channels[5], teamspeak.GroupDeleteOptions{Force: true}))
	v = w.untilGroupsMatch(t, admin, "after deleting")
	if _, ok := v.ServerGroup(servers[5]); ok {
		t.Errorf("the deleted server group %d is still in the view", servers[5])
	}

	// The server announces no permission change of a group, and the view holds
	// none: the next change, which it does announce, is the only one it sees.
	before := w.c.View().Revision
	requireNoErr(t, admin.AddServerGroupPermission(t.Context(), servers[6],
		teamspeak.PermissionByName(perm.GroupModifyPower), 33, teamspeak.ServerGroupPermissionOptions{}))
	requireNoErr(t, admin.RenameServerGroup(t.Context(), servers[6], renamed+"2"))
	v = w.until(t, "after the permission and the rename", func(v client.ServerView) (bool, string) {
		g, _ := v.ServerGroup(servers[6])

		return g.Name == renamed+"2", "the rename has not arrived"
	})
	if v.Revision != before+1 {
		t.Errorf("a permission change and a rename moved the revision from %d to %d, want one step", before, v.Revision)
	}
	w.untilGroupsMatch(t, admin, "after the permission change")
}

// A client that joins a server with 70 groups is sent them right after the
// channel list, and holds them all once they have arrived.
func TestIntegration_ViewWelcomeWithGroups(t *testing.T) {
	admin := requireAdmin(t)
	prefix := uniqueName("vw")
	tidyGroups(t, admin, prefix)
	createGroups(t, admin, prefix, groupCount)

	w := watchedClient(t, uniqueName("vwobs"))
	seen := 0
	v := w.until(t, "after joining", func(v client.ServerView) (bool, string) {
		seen++
		servers, channels := listings(t, admin)
		if !v.GroupsLoaded {
			return false, "the groups are not loaded"
		}

		return matchesListing(v, servers, channels)
	})
	if v.Status != client.ViewLive || len(v.ServerGroups) < groupCount {
		t.Errorf("Status = %v, %d server groups", v.Status, len(v.ServerGroups))
	}
	t.Logf("the view was complete after %d looks", seen)
}

// Groups added while a client joins: whatever the welcome delivered, the view
// ends as the listing.
func TestIntegration_ViewGroupsChurnDuringJoin(t *testing.T) {
	admin := requireAdmin(t)
	prefix := uniqueName("vc")
	tidyGroups(t, admin, prefix)

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 20 {
			name := fmt.Sprintf("%s-s%d", prefix, i)
			_, err := admin.CreateServerGroup(context.Background(), name, teamspeak.GroupRegular)
			if err != nil {
				t.Errorf("creating a group: %v", err)

				return
			}
		}
	})
	w := watchedClient(t, uniqueName("vcobs"))
	wg.Wait()

	w.untilGroupsMatch(t, admin, "after the churn")
}

// serverSettingsToRestore picks, from serverinfo, the settings that
// TestIntegration_ViewServerProperties edits. The icon and the banner are only
// there when the server sends them.
func serverSettingsToRestore(info teamspeak.Properties) teamspeak.Properties {
	restore := teamspeak.Properties{}
	for _, key := range []string{
		"virtualserver_name", "virtualserver_welcomemessage", "virtualserver_maxclients",
		"virtualserver_icon_id", "virtualserver_hostbanner_gfx_url",
	} {
		if value, ok := info[key]; ok {
			restore[key] = value
		}
	}

	return restore
}

// The name is announced with the edit; the welcome message and the client limit
// are not, and the view has them again only once the client asks for them.
//
//nolint:funlen // one scenario, read top to bottom
func TestIntegration_ViewServerProperties(t *testing.T) {
	admin := requireAdmin(t)
	w := watchedClient(t, uniqueName("vsobs"))

	info, err := admin.GetServerInfo(t.Context())
	requireNoErr(t, err)
	oldName, oldWelcome := info["virtualserver_name"], info["virtualserver_welcomemessage"]
	oldMax := info["virtualserver_maxclients"]
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		restoreErr := admin.EditServer(ctx, serverSettingsToRestore(info))
		if restoreErr != nil {
			t.Errorf("cleanup: restoring the server: %v", restoreErr)
		}
	})

	nameIs := func(want string) func(client.ServerView) (bool, string) {
		return func(v client.ServerView) (bool, string) {
			return v.Server["virtualserver_name"] == want, fmt.Sprintf("the name is %q", v.Server["virtualserver_name"])
		}
	}
	v := w.until(t, "at the start", nameIs(oldName))
	if v.Server["virtualserver_welcomemessage"] != oldWelcome {
		t.Errorf("welcome message %q, the server's %q", v.Server["virtualserver_welcomemessage"], oldWelcome)
	}

	newName := uniqueName("srv")
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_name": newName}))
	v = w.until(t, "after the name", nameIs(newName))
	if v.ServerName() != newName {
		t.Errorf("ServerName = %q, want %q", v.ServerName(), newName)
	}

	// An edit that is announced without its setting. A later edit that is
	// announced with its key proves the earlier notification has been handled.
	newWelcome := "hello " + newName
	newMax := "31"
	if oldMax == "31" {
		newMax = "30"
	}
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_welcomemessage": newWelcome}))
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_maxclients": newMax}))
	marker := uniqueName("srv2")
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_name": marker}))
	v = w.until(t, "after the marker", nameIs(marker))
	if v.Server["virtualserver_welcomemessage"] != oldWelcome || v.Server["virtualserver_maxclients"] != oldMax {
		t.Errorf("the view followed a silent edit: welcome %q, max clients %q",
			v.Server["virtualserver_welcomemessage"], v.Server["virtualserver_maxclients"])
	}

	// The answer to servergetvariables is what brings them.
	answer, err := w.c.GetServerVariables(t.Context())
	requireNoErr(t, err)
	if answer["virtualserver_welcomemessage"] != newWelcome || answer["virtualserver_maxclients"] != newMax {
		t.Fatalf("the answer has welcome %q and max clients %q",
			answer["virtualserver_welcomemessage"], answer["virtualserver_maxclients"])
	}
	if _, ok := answer["virtualserver_clientsonline"]; !ok {
		t.Error("the answer holds no counter, so this does not test that the view leaves them out")
	}
	v = w.c.View()
	if v.Server["virtualserver_welcomemessage"] != newWelcome || v.Server["virtualserver_maxclients"] != newMax {
		t.Errorf("after the answer: welcome %q, max clients %q",
			v.Server["virtualserver_welcomemessage"], v.Server["virtualserver_maxclients"])
	}

	// An icon and a banner: current once the edit is announced or
	// servergetvariables has been answered. The server refuses a signed icon id
	// in an edit (convert error), though it may send one.
	newBanner := "https://example.com/" + newName + ".png"
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{
		"virtualserver_icon_id": "2766950830", "virtualserver_hostbanner_gfx_url": newBanner,
	}))
	_, err = w.c.GetServerVariables(t.Context())
	requireNoErr(t, err)
	v = w.c.View()
	if v.ServerIconID() != 2766950830 || v.ServerBannerImageURL() != newBanner {
		t.Errorf("after the edit: icon %d, banner %q", v.ServerIconID(), v.ServerBannerImageURL())
	}

	// Every setting the view holds is what the server says, and none is a counter.
	now, err := w.c.GetServerInfo(t.Context())
	requireNoErr(t, err)
	for name, value := range v.Server {
		if now[name] != value {
			t.Errorf("%s: the view has %q, serverinfo %q", name, value, now[name])
		}
	}
	for _, counter := range []string{
		"virtualserver_clientsonline", "virtualserver_queryclientsonline", "virtualserver_channelsonline",
		"virtualserver_uptime", "virtualserver_client_connections", "virtualserver_query_client_connections",
		"virtualserver_month_bytes_downloaded", "virtualserver_month_bytes_uploaded",
		"virtualserver_total_bytes_downloaded", "virtualserver_total_bytes_uploaded",
		"virtualserver_total_packetloss_speech", "virtualserver_total_packetloss_keepalive",
		"virtualserver_total_packetloss_control", "virtualserver_total_packetloss_total", "virtualserver_total_ping",
	} {
		if _, ok := v.Server[counter]; ok {
			t.Errorf("the view holds %s", counter)
		}
	}
	for name := range v.Server {
		if !strings.HasPrefix(name, "virtualserver_") {
			t.Errorf("the view holds %q", name)
		}
	}
}

// Previous is the record the view held, for a deleted channel and a client that
// left.
func TestIntegration_ViewPrevious(t *testing.T) {
	admin := requireAdmin(t)
	w := watchedClient(t, uniqueName("vpobs"))
	deleted := listen(t, w.c.OnChannelDeleted)
	created := listen(t, w.c.OnChannelCreated)
	left := listen(t, w.c.OnClientLeave)

	parent := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("vp")})
	child := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("vpc"), ParentID: parent})
	await(t, created, "created parent", func(e teamspeak.ChannelCreatedEvent) bool { return e.ChannelID == parent })
	await(t, created, "created child", func(e teamspeak.ChannelCreatedEvent) bool { return e.ChannelID == child })

	// The subchannel goes first, each event with its own record.
	v := w.c.View()
	wantChild, okChild := v.Channel(child)
	wantParent, okParent := v.Channel(parent)
	if !okChild || !okParent {
		t.Fatalf("the view lacks the channels: %v %v", okParent, okChild)
	}
	requireNoErr(t, admin.DeleteChannel(t.Context(), parent, teamspeak.ChannelDeleteOptions{Force: true}))
	for _, want := range []teamspeak.Channel{wantChild, wantParent} {
		e := await(t, deleted, fmt.Sprintf("deleted %d", want.ID),
			func(e teamspeak.ChannelDeletedEvent) bool { return e.ChannelID == want.ID })
		if e.Previous == nil || !reflect.DeepEqual(*e.Previous, want) {
			t.Errorf("channel %d: Previous = %+v, the view held %+v", want.ID, e.Previous, want)
		}
	}
	if _, ok := w.c.View().Channel(child); ok {
		t.Error("the deleted channel is still in the view")
	}

	// A bystander in the same channel enters and leaves.
	bystander := liveClient(t, uniqueName("vpby"))
	var held teamspeak.ClientEntry
	w.until(t, "the bystander enters", func(v client.ServerView) (bool, string) {
		e, ok := v.Client(bystander.ClientID())
		held = e

		return ok && e.ChannelID == w.c.ChannelID(), "the bystander is not in the view"
	})
	requireNoErr(t, bystander.Disconnect(t.Context()))
	e := await(t, left, "the bystander leaving", func(e teamspeak.ClientLeaveEvent) bool {
		return e.ClientID == bystander.ClientID()
	})
	if e.Previous == nil || e.Previous.ID != held.ID || e.Previous.UID == nil || held.UID == nil ||
		*e.Previous.UID != *held.UID ||
		e.Previous.Nickname != held.Nickname || e.Previous.ChannelID != held.ChannelID ||
		!slices.Equal(e.Previous.ServerGroups, held.ServerGroups) {
		t.Errorf("Previous = %+v, the view held %+v", e.Previous, held)
	}
	if _, ok := w.c.View().Client(bystander.ClientID()); ok {
		t.Error("the client that left is still in the view")
	}
}

// Many changes in a row give fewer events than changes, the last of them
// naming the final revision.
func TestIntegration_ViewChangedCoalesces(t *testing.T) {
	admin := requireAdmin(t)
	prefix := uniqueName("vn")
	tidyGroups(t, admin, prefix)
	w := watchedClient(t, uniqueName("vnobs"))
	w.untilGroupsMatch(t, admin, "at the start")
	start := len(w.seen())

	// The burst: each creation is a change of the group list.
	createGroups(t, admin, prefix, groupCount)
	w.untilGroupsMatch(t, admin, "after the burst")

	// A channel move is another kind of change.
	a := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("vna")})
	b := liveChannel(t, admin, teamspeak.ChannelCreateOptions{Name: uniqueName("vnb")})
	w.until(t, "the channels", func(v client.ServerView) (bool, string) {
		_, okA := v.Channel(a)
		_, okB := v.Channel(b)

		return okA && okB, "the channels are not in the view"
	})
	requireNoErr(t, admin.MoveChannel(t.Context(), b, a, teamspeak.ChannelMoveOptions{}))
	w.until(t, "the move", func(v client.ServerView) (bool, string) {
		ch, _ := v.Channel(b)

		return ch.ParentID == a, "the channel has not moved"
	})

	// Quiet: the last event names the revision the view is at.
	w.until(t, "the last event", func(v client.ServerView) (bool, string) {
		events := w.seen()
		if len(events) == 0 {
			return false, "no event"
		}

		return events[len(events)-1].Revision == v.Revision, fmt.Sprintf("last event %d, view %d",
			events[len(events)-1].Revision, v.Revision)
	})
	events := w.seen()[start:]
	changes := 2*groupCount + 2 + 1
	if n := len(events); n < 1 || n > changes {
		t.Errorf("%d ViewChangedEvents for %d changes", n, changes)
	}
	t.Logf("%d ViewChangedEvents for %d group creations, two channel creations and a move",
		len(events), 2*groupCount)
}
