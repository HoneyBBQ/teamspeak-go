package client

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

var (
	sgidPattern = regexp.MustCompile(`\bsgid=(\d+)`)
	cgidPattern = regexp.MustCompile(`\bcgid=(\d+)`)
)

// idsIn lists the ids a recorded group list line names, in the order it names them.
func idsIn(t *testing.T, line string, pattern *regexp.Regexp) []uint64 {
	t.Helper()
	matches := pattern.FindAllStringSubmatch(line, -1)
	ids := make([]uint64, 0, len(matches))
	for _, m := range matches {
		id, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	return ids
}

func serverGroupIDs(groups []teamspeak.ServerGroup) []uint64 {
	ids := make([]uint64, len(groups))
	for i, g := range groups {
		ids[i] = uint64(g.ID)
	}

	return ids
}

func channelGroupIDs(groups []teamspeak.ChannelGroup) []uint64 {
	ids := make([]uint64, len(groups))
	for i, g := range groups {
		ids[i] = uint64(g.ID)
	}

	return ids
}

// serverGroupLine is a group list of server groups: id and name for each.
func serverGroupLine(groups ...string) string {
	rows := make([]string, len(groups))
	for i, g := range groups {
		id, name, _ := strings.Cut(g, "=")
		rows[i] = fmt.Sprintf("sgid=%s name=%s type=1 iconid=0 savedb=1 sortid=0 namemode=0 "+
			"n_modifyp=75 n_member_addp=50 n_member_removep=40", id, name)
	}

	return "notifyservergrouplist " + strings.Join(rows, "|")
}

func channelGroupLine(groups ...string) string {
	rows := make([]string, len(groups))
	for i, g := range groups {
		id, name, _ := strings.Cut(g, "=")
		rows[i] = fmt.Sprintf("cgid=%s name=%s type=1 iconid=0 savedb=1 sortid=0 namemode=0 "+
			"n_modifyp=75 n_member_addp=50 n_member_removep=40", id, name)
	}

	return "notifychannelgrouplist " + strings.Join(rows, "|")
}

func ascending(ids []uint64) bool {
	return slices.IsSorted(ids) && len(slices.Compact(slices.Clone(ids))) == len(ids)
}

// The lists a server sends after the channel list, and after every change to a
// group, each one command line holding every row: the view is the list, in
// ascending id, and says so only once both kinds have arrived.
//
//nolint:gocognit,funlen,gocyclo,cyclop // one scenario per server, read top to bottom
func TestViewGroupsFromRecordings(t *testing.T) {
	for _, c := range []struct {
		name string
		tag  string
	}{
		{"TS3", "ts3"},
		{"TS6", "ts6"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := newTestClient(t)
			ready := make(chan ViewReadyEvent, 2)
			changed := make(chan ViewChangedEvent, 64)
			cl.OnViewReady(func(e ViewReadyEvent) { ready <- e })
			cl.OnViewChanged(func(e ViewChangedEvent) { changed <- e })
			beginView(cl, 1)

			welcome := fixtureLines(t, "groups-"+c.tag+"-welcome.txt")
			finished := slices.Index(welcome, "channellistfinished")
			feed(cl, welcome[:finished+1]...)
			settle(t, cl)
			receive(t, ready)

			v := cl.View()
			if v.Status != ViewLive || v.GroupsLoaded || len(v.ServerGroups) != 0 || len(v.ChannelGroups) != 0 {
				t.Fatalf("at the end of the channel list: %v, loaded %v, %d and %d groups",
					v.Status, v.GroupsLoaded, len(v.ServerGroups), len(v.ChannelGroups))
			}

			// The channel groups come first, then the server groups, as recorded.
			channelList, serverList := welcome[finished+1], welcome[finished+2]
			feed(cl, channelList)
			v = cl.View()
			gotChannels := channelGroupIDs(v.ChannelGroups)
			if want := idsIn(t, channelList, cgidPattern); !slices.Equal(gotChannels, want) || v.GroupsLoaded {
				t.Errorf("after the channel groups: %v loaded %v, want %v", gotChannels, v.GroupsLoaded, want)
			}
			feed(cl, serverList)
			v = cl.View()
			gotServers := serverGroupIDs(v.ServerGroups)
			if want := idsIn(t, serverList, sgidPattern); !slices.Equal(gotServers, want) || !v.GroupsLoaded {
				t.Errorf("after the server groups: %v loaded %v, want %v", gotServers, v.GroupsLoaded, want)
			}
			if len(v.ServerGroups) != 8 || len(v.ChannelGroups) != 8 {
				t.Errorf("%d server groups and %d channel groups, recorded eight each", len(v.ServerGroups), len(v.ChannelGroups))
			}
			guest, ok := v.ServerGroup(1)
			if !ok || guest.Name != "Guest Server Query" || guest.Type != teamspeak.GroupQuery || guest.ModifyPower != 100 {
				t.Errorf("server group 1 = %+v, %v", guest, ok)
			}
			admin, ok := v.ChannelGroup(1)
			if !ok || admin.Name != "Channel Admin" || admin.IconID != 100 || !admin.SavedInDatabase || admin.ModifyPower != 75 {
				t.Errorf("channel group 1 = %+v, %v", admin, ok)
			}
			if _, ok := v.ServerGroup(9999); ok {
				t.Error("a server group nobody has is in the view")
			}

			// The groups arrived after the view turned live, and are announced.
			settle(t, cl)
			last := receive(t, changed)
			for len(changed) > 0 {
				last = <-changed
			}
			if last.Revision != v.Revision {
				t.Errorf("the last ViewChangedEvent has revision %d, the view %d", last.Revision, v.Revision)
			}

			// Every list after a change is the whole set again.
			for _, line := range fixtureLines(t, "groups-"+c.tag+"-changes.txt") {
				before := cl.View().Revision
				feed(cl, line)
				v = cl.View()
				var got, want []uint64
				if strings.HasPrefix(line, "notifyservergrouplist") {
					got, want = serverGroupIDs(v.ServerGroups), idsIn(t, line, sgidPattern)
				} else {
					got, want = channelGroupIDs(v.ChannelGroups), idsIn(t, line, cgidPattern)
				}
				if !slices.Equal(got, want) || !ascending(got) {
					t.Errorf("a list of %d rows gave %d groups: %v, want %v", len(want), len(got), got, want)
				}
				if v.Revision < before {
					t.Errorf("the revision went back")
				}
			}
			settle(t, cl)
		})
	}
}

// Sixty-two lists back to back, each a packet of its own: the view ends as the
// last one, and every list replaced the one before.
func TestViewGroupsOfAConsecutiveRun(t *testing.T) {
	cl := welcomed(t)
	lines := fixtureLines(t, "groups-ts3-run.txt")
	if len(lines) != 62 {
		t.Fatalf("the recording holds %d lists", len(lines))
	}
	for i, line := range lines {
		feed(cl, line)
		want := idsIn(t, line, sgidPattern)
		if got := serverGroupIDs(cl.View().ServerGroups); !slices.Equal(got, want) {
			t.Fatalf("after list %d: %v, want %v", i+1, got, want)
		}
	}
	if cl.View().GroupsLoaded {
		t.Error("the channel groups never arrived, and the view says it is loaded")
	}
}

//nolint:funlen // one scenario, read top to bottom
func TestViewGroupListReplacesTheSet(t *testing.T) {
	cl := welcomed(t)
	rev := func() uint64 { return cl.View().Revision }

	feed(cl, serverGroupLine("3=C", "1=A", "2=B"))
	v := cl.View()
	if got := serverGroupIDs(v.ServerGroups); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("rows out of order: %v", got)
	}

	// The same list again changes nothing, the revision included.
	before := rev()
	feed(cl, serverGroupLine("1=A", "2=B", "3=C"))
	if rev() != before {
		t.Errorf("an identical list moved the revision from %d to %d", before, rev())
	}

	// A rename; a deletion; an addition.
	feed(cl, serverGroupLine("1=A", "2=Renamed", "3=C"))
	if g, _ := cl.View().ServerGroup(2); g.Name != "Renamed" || rev() != before+1 {
		t.Errorf("after the rename: %+v, revision %d from %d", g, rev(), before)
	}
	feed(cl, serverGroupLine("1=A", "3=C"))
	if _, ok := cl.View().ServerGroup(2); ok {
		t.Error("a group missing from the list is still there")
	}
	feed(cl, serverGroupLine("1=A", "3=C", "4=D"))
	if got := serverGroupIDs(cl.View().ServerGroups); !slices.Equal(got, []uint64{1, 3, 4}) {
		t.Errorf("after the addition: %v", got)
	}

	// A list of one row is a set of one group.
	feed(cl, serverGroupLine("9=Only"))
	if got := serverGroupIDs(cl.View().ServerGroups); !slices.Equal(got, []uint64{9}) {
		t.Errorf("a one-row list: %v", got)
	}

	// A row without an id is skipped, a repeated id keeps the last row.
	feed(cl, "notifyservergrouplist name=Nameless type=1|sgid=5 name=First type=1|sgid=5 name=Second type=1")
	v = cl.View()
	if got := serverGroupIDs(v.ServerGroups); !slices.Equal(got, []uint64{5}) {
		t.Errorf("a row without an id, and a repeat: %v", got)
	}
	if g, _ := v.ServerGroup(5); g.Name != "Second" {
		t.Errorf("the repeated id kept %q, want the last row", g.Name)
	}

	// The rows of one line move the revision once, not once per row.
	before = rev()
	feed(cl, serverGroupLine("1=A", "2=B", "3=C", "4=D", "5=E"))
	if rev() != before+1 {
		t.Errorf("five rows moved the revision from %d to %d", before, rev())
	}

	// Channel groups are a set of their own, and a group permission change,
	// which the server does not announce, leaves the view as it was.
	feed(cl, channelGroupLine("1=X", "2=Y"))
	v = cl.View()
	if got := channelGroupIDs(v.ChannelGroups); !slices.Equal(got, []uint64{1, 2}) || len(v.ServerGroups) != 5 {
		t.Errorf("channel groups %v beside %d server groups", got, len(v.ServerGroups))
	}
	if g, ok := v.ChannelGroup(2); !ok || g.Name != "Y" {
		t.Errorf("channel group 2 = %+v, %v", g, ok)
	}
}

// A caller's ServerGroupList is answered by the same line the view reads, and
// still gets its rows.
func TestViewGroupListStillAnswersTheCommand(t *testing.T) {
	cl := welcomed(t)
	rc, done := cl.cmdTrack.register(responseFor("servergrouplist"), "", false)

	feed(cl, serverGroupLine("1=A", "2=B", "3=C"))
	cl.cmdTrack.resolve(rc, nil, 0)

	if rows := receive(t, done).Data; len(rows) != 3 || rows[1]["name"] != "B" {
		t.Errorf("the command got %v", rows)
	}
	if got := serverGroupIDs(cl.View().ServerGroups); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Errorf("the view holds %v", got)
	}
}

func TestViewGroupsLoadedNeedsBothKinds(t *testing.T) {
	cl := newTestClient(t)
	beginView(cl, 1)

	// Lists are taken while the view is loading, before the channel list ends.
	feed(cl, serverGroupLine("1=A"))
	if v := cl.View(); v.GroupsLoaded || len(v.ServerGroups) != 1 {
		t.Errorf("one kind: loaded %v, %d groups", v.GroupsLoaded, len(v.ServerGroups))
	}
	feed(cl, channelGroupLine("1=X"))
	if !cl.View().GroupsLoaded {
		t.Error("both kinds have arrived and the view is not loaded")
	}

	// A list with no group in it is still a list: none, and known.
	cl = welcomed(t)
	feed(cl, "notifyservergrouplist", "notifychannelgrouplist")
	if v := cl.View(); !v.GroupsLoaded || len(v.ServerGroups) != 0 || len(v.ChannelGroups) != 0 {
		t.Errorf("empty lists: loaded %v, %+v", v.GroupsLoaded, v.ServerGroups)
	}

	// A connect starts again; the end of the session keeps what was there and
	// takes no more.
	cl = welcomed(t)
	feed(cl, serverGroupLine("1=A"), channelGroupLine("1=X"))
	cl.handleConnectionClosed(cl.handler, errDropped)
	feed(cl, serverGroupLine("1=A", "2=B"), channelGroupLine("7=Z"))
	v := cl.View()
	if v.Status != ViewStale || !v.GroupsLoaded || len(v.ServerGroups) != 1 || len(v.ChannelGroups) != 1 {
		t.Errorf("stale: %v loaded %v, %d and %d groups", v.Status, v.GroupsLoaded, len(v.ServerGroups), len(v.ChannelGroups))
	}
	cl.mu.Lock()
	cl.resetForConnectLocked()
	cl.mu.Unlock()
	if v := cl.View(); v.GroupsLoaded || len(v.ServerGroups) != 0 || len(v.ChannelGroups) != 0 || len(v.Server) != 0 {
		t.Errorf("after the reset: loaded %v, %d and %d groups, server %v",
			v.GroupsLoaded, len(v.ServerGroups), len(v.ChannelGroups), v.Server)
	}
}

// connecting is a client that has not yet been told it is connected, so that
// initserver is handled as the server's answer to the handshake.
func connecting(t *testing.T) *Client {
	t.Helper()
	cl := newTestClient(t)
	cl.mu.Lock()
	cl.resetViewLocked()
	cl.status = StatusConnecting
	cl.mu.Unlock()

	return cl
}

//nolint:gocognit // one scenario per server, read top to bottom
func TestViewServerFromRecordings(t *testing.T) {
	for _, c := range []struct {
		name, tag, serverName string
	}{
		{"TS3", "ts3", "TeamSpeak ]I[ Server"},
		{"TS6", "ts6", "TeamSpeak 6 Server"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := connecting(t)
			lines := fixtureLines(t, "server-"+c.tag+".txt")

			feed(cl, lines[0])
			v := cl.View()
			if v.Status != ViewLoading || v.Server["virtualserver_name"] != c.serverName {
				t.Fatalf("after initserver: %v, name %q", v.Status, v.Server["virtualserver_name"])
			}
			for name := range v.Server {
				if !strings.HasPrefix(name, "virtualserver_") {
					t.Errorf("the view holds %q", name)
				}
			}
			if _, ok := v.Server["virtualserver_clientsonline"]; ok {
				t.Error("initserver put a counter in the view")
			}
			created := v.Server["virtualserver_created"]
			if created == "" {
				t.Fatal("initserver has no virtualserver_created")
			}

			// The answer to servergetvariables adds what initserver lacks and
			// leaves what only initserver has.
			feed(cl, lines[1])
			v = cl.View()
			if v.Server["virtualserver_created"] != created {
				t.Error("a key only initserver has was lost")
			}
			if v.Server["virtualserver_port"] != "9987" || v.Server["virtualserver_antiflood_points_tick_reduce"] != "65000" {
				t.Errorf("the answer was not merged: port %q", v.Server["virtualserver_port"])
			}
			wantWelcome := "Welcome to TeamSpeak, check [URL]www.teamspeak.com[/URL] for latest information"
			if v.Server["virtualserver_welcomemessage"] != wantWelcome {
				t.Errorf("welcome message = %q", v.Server["virtualserver_welcomemessage"])
			}
			for _, counter := range serverCounters {
				if _, ok := v.Server[counter]; ok {
					t.Errorf("the view holds the counter %s", counter)
				}
			}
		})
	}
}

// The counters and statistics of rule 17.
var serverCounters = []string{
	"virtualserver_clientsonline", "virtualserver_queryclientsonline", "virtualserver_channelsonline",
	"virtualserver_uptime", "virtualserver_client_connections", "virtualserver_query_client_connections",
	"virtualserver_month_bytes_downloaded", "virtualserver_month_bytes_uploaded",
	"virtualserver_total_bytes_downloaded", "virtualserver_total_bytes_uploaded",
	"virtualserver_total_packetloss_speech", "virtualserver_total_packetloss_keepalive",
	"virtualserver_total_packetloss_control", "virtualserver_total_packetloss_total", "virtualserver_total_ping",
}

func TestViewServerSeedLeavesOutTheClientsOwnParameters(t *testing.T) {
	cl := connecting(t)
	feed(cl, "initserver virtualserver_name=Mine virtualserver_maxclients=32 client_nickname=Me "+
		"client_server_password=hunter2 client_default_channel_password=hunter3 client_default_token=tok "+
		"client_key_offset=77 acn=Me aclid=3 pv=6")

	v := cl.View()
	want := teamspeak.Properties{"virtualserver_name": "Mine", "virtualserver_maxclients": "32"}
	if !reflect.DeepEqual(v.Server, want) {
		t.Errorf("Server = %v, want %v", v.Server, want)
	}
}

// The name, icon and banner are read from the view, which follows the server's
// edits; the handshake's record holds what lasts the connection and stays as it
// was.
func TestViewServerNameIconAndBanner(t *testing.T) {
	cl := connecting(t)
	feed(cl, "initserver virtualserver_name=Before virtualserver_icon_id=0 virtualserver_hostbanner_gfx_url "+
		"virtualserver_version=3.13.8 virtualserver_capability_extensions=FILETIME aclid=3",
		"channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished")
	settle(t, cl)
	if v := cl.View(); v.ServerName() != "Before" || v.ServerIconID() != 0 || v.ServerBannerImageURL() != "" {
		t.Errorf("after initserver: name %q, icon %d, banner %q", v.ServerName(), v.ServerIconID(), v.ServerBannerImageURL())
	}
	if v := (ServerView{}); v.ServerName() != "" || v.ServerIconID() != 0 || v.ServerBannerImageURL() != "" {
		t.Error("an empty view names a server")
	}
	caps := cl.ServerCapabilities()

	feed(cl, `notifyserveredited reasonid=10 invokerid=5 invokername=admin invokeruid=u5 virtualserver_name=Renamed `+
		`virtualserver_icon_id=-1528016466 virtualserver_hostbanner_gfx_url=\shttps:\/\/example.com\/banner.png\s`)
	v := cl.View()
	if v.ServerName() != "Renamed" {
		t.Errorf("ServerName = %q", v.ServerName())
	}
	// The server sends the CRC32 as a signed 32-bit number; the icon file is
	// named by the unsigned one.
	if v.ServerIconID() != 2766950830 {
		t.Errorf("ServerIconID = %d, want 2766950830", v.ServerIconID())
	}
	if v.ServerBannerImageURL() != "https://example.com/banner.png" {
		t.Errorf("ServerBannerImageURL = %q, want it trimmed", v.ServerBannerImageURL())
	}
	if !reflect.DeepEqual(cl.ServerCapabilities(), caps) {
		t.Errorf("ServerCapabilities changed with the edit: %+v, was %+v", cl.ServerCapabilities(), caps)
	}

	feed(cl, "notifyserveredited virtualserver_icon_id=2766950830")
	if got := cl.View().ServerIconID(); got != 2766950830 {
		t.Errorf("ServerIconID of the unsigned form = %d", got)
	}
	feed(cl, "notifyserveredited virtualserver_icon_id=x")
	if got := cl.View().ServerIconID(); got != 0 {
		t.Errorf("ServerIconID of garbage = %d, want 0", got)
	}
}

//nolint:funlen // one scenario, read top to bottom
func TestViewServerFollowsEditsAndAnswers(t *testing.T) {
	cl := connecting(t)
	feed(cl, "initserver virtualserver_name=Before virtualserver_welcomemessage=Hello aclid=3",
		"channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished")
	settle(t, cl)
	rev := func() uint64 { return cl.View().Revision }

	// An edit names the setting it changed, with the value it has now.
	before := rev()
	feed(cl, "notifyserveredited reasonid=10 invokerid=5 invokername=admin invokeruid=u5 virtualserver_name=After")
	if v := cl.View(); v.Server["virtualserver_name"] != "After" || v.Revision != before+1 {
		t.Errorf("after the edit: %q, revision %d from %d", v.Server["virtualserver_name"], v.Revision, before)
	}

	// An edit that names nothing changes nothing; neither does a repeat.
	before = rev()
	feed(cl, "notifyserveredited reasonid=10 invokerid=5 invokername=admin invokeruid=u5",
		"notifyserveredited reasonid=10 invokerid=5 invokername=admin invokeruid=u5 virtualserver_name=After")
	if rev() != before {
		t.Errorf("the revision moved from %d to %d", before, rev())
	}
	if got := cl.View().Server["virtualserver_welcomemessage"]; got != "Hello" {
		t.Errorf("welcome message = %q", got)
	}

	// An answer to servergetvariables brings the silent edits, keeps what it
	// lacks, drops the counters and keeps a key nobody has heard of.
	feed(cl, "notifyserverupdated virtualserver_welcomemessage=Changed\\sin\\ssilence virtualserver_maxclients=64 "+
		"virtualserver_clientsonline=3 virtualserver_uptime=900 virtualserver_total_ping=12.5 "+
		"virtualserver_future_setting=1 return_code=7")
	v := cl.View()
	if v.Server["virtualserver_welcomemessage"] != "Changed in silence" || v.Server["virtualserver_maxclients"] != "64" {
		t.Errorf("the answer was not merged: %v", v.Server)
	}
	if v.Server["virtualserver_name"] != "After" || v.Server["virtualserver_future_setting"] != "1" {
		t.Errorf("a key was lost or dropped: %v", v.Server)
	}
	for _, key := range []string{
		"virtualserver_clientsonline", "virtualserver_uptime", "virtualserver_total_ping", "return_code",
	} {
		if _, ok := v.Server[key]; ok {
			t.Errorf("the view holds %s", key)
		}
	}
	before = rev()
	feed(cl, "notifyserverupdated virtualserver_maxclients=64 virtualserver_clientsonline=4")
	if rev() != before {
		t.Errorf("an answer that changed nothing moved the revision from %d to %d", before, rev())
	}

	// A stale view takes none.
	cl.handleConnectionClosed(cl.handler, errDropped)
	feed(cl, "notifyserveredited reasonid=10 virtualserver_name=Late")
	if got := cl.View().Server["virtualserver_name"]; got != "After" {
		t.Errorf("a stale view took %q", got)
	}
}

func TestViewServerAndGroupsAreCopies(t *testing.T) {
	cl := connecting(t)
	feed(cl, "initserver virtualserver_name=Mine aclid=3", "channellistfinished",
		serverGroupLine("1=A", "2=B"), channelGroupLine("1=X"))

	v := cl.View()
	v.Server["virtualserver_name"] = "scribble"
	v.ServerGroups[0].Name = "scribble"
	v.ChannelGroups[0].Name = "scribble"
	slices.Reverse(v.ServerGroups)

	again := cl.View()
	if again.Server["virtualserver_name"] != "Mine" || again.ServerGroups[0].Name != "A" ||
		again.ChannelGroups[0].Name != "X" {
		t.Errorf("a change to a view reached the next: %v, %+v, %+v", again.Server, again.ServerGroups, again.ChannelGroups)
	}
	if g, ok := again.ServerGroup(2); !ok || g.Name != "B" {
		t.Errorf("ServerGroup(2) = %+v, %v", g, ok)
	}
	// A lookup does not depend on the order of the caller's slice.
	if g, ok := v.ServerGroup(1); !ok || g.ID != 1 {
		t.Errorf("ServerGroup(1) on a reordered slice = %+v, %v", g, ok)
	}
}

// Previous is what the view held, taken as the channel was removed.
func TestChannelDeletedCarriesThePreviousChannel(t *testing.T) {
	cl := welcomed(t)
	feed(cl, "notifychannelcreated cid=4 cpid=2 channel_name=C channel_order=3 invokerid=1")
	settle(t, cl)

	deleted := make(chan ChannelDeletedEvent, 8)
	cl.OnChannelDeleted(func(e ChannelDeletedEvent) { deleted <- e })

	// B sits first under A, C after it; deleting B rewrites C's order, but
	// the record of B is as it stood.
	before, _ := cl.View().Channel(3)
	feed(cl, "notifychanneldeleted cid=3 invokerid=1 invokername=admin")
	evt := receive(t, deleted)
	if evt.Previous == nil || !reflect.DeepEqual(*evt.Previous, before) {
		t.Fatalf("Previous = %+v, the view held %+v", evt.Previous, before)
	}
	if evt.Previous.Name != "B" || evt.Previous.ParentID != 2 || evt.Previous.TotalClients != nil {
		t.Errorf("Previous = %+v", evt.Previous)
	}

	// A channel deleted with a subchannel: the subchannel first, each event
	// with its own record.
	feed(cl, "notifychannelcreated cid=5 cpid=4 channel_name=Child channel_order=0 invokerid=1")
	child, _ := cl.View().Channel(5)
	feed(cl, "notifychanneldeleted cid=5 invokerid=1")
	parent, _ := cl.View().Channel(4)
	feed(cl, "notifychanneldeleted cid=4 invokerid=1")
	for _, want := range []teamspeak.Channel{child, parent} {
		e := receive(t, deleted)
		if e.Previous == nil || !reflect.DeepEqual(*e.Previous, want) {
			t.Errorf("channel %d: Previous = %+v, want %+v", want.ID, e.Previous, want)
		}
	}

	// Not held: the view does not know the channel.
	feed(cl, "notifychanneldeleted cid=77 invokerid=1")
	if e := receive(t, deleted); e.Previous != nil {
		t.Errorf("an unknown channel has Previous %+v", e.Previous)
	}

	// Not live: the tree is not built until the channel list is finished.
	loading := newTestClient(t)
	beginView(loading, 1)
	loading.OnChannelDeleted(func(e ChannelDeletedEvent) { deleted <- e })
	feed(loading, "channellist cid=8 cpid=0 channel_name=A channel_order=0", "notifychanneldeleted cid=8 invokerid=1")
	if e := receive(t, deleted); e.Previous != nil {
		t.Errorf("a loading view gave Previous %+v", e.Previous)
	}
}

func TestClientLeaveCarriesThePreviousClient(t *testing.T) {
	cl := welcomed(t)
	left := make(chan ClientLeaveEvent, 8)
	cl.OnClientLeave(func(e ClientLeaveEvent) { left <- e })

	feed(cl, enterLine(5, 2, "7,9"))
	before, _ := cl.View().Client(5)
	feed(cl, "notifyclientleftview cfid=2 ctid=0 reasonid=8 reasonmsg=bye clid=5")
	evt := receive(t, left)
	if evt.Previous == nil || !reflect.DeepEqual(*evt.Previous, before) {
		t.Fatalf("Previous = %+v, the view held %+v", evt.Previous, before)
	}
	if evt.Previous.Nickname != "c5" || !slices.Equal(evt.Previous.ServerGroups, []teamspeak.ServerGroupID{7, 9}) {
		t.Errorf("Previous = %+v", evt.Previous)
	}
	if _, ok := cl.View().Client(5); ok {
		t.Error("the client is still in the view")
	}

	// Never announced: there is nothing to attach.
	feed(cl, "notifyclientleftview cfid=2 ctid=0 reasonid=8 clid=99")
	if e := receive(t, left); e.Previous != nil {
		t.Errorf("a client the view never held has Previous %+v", e.Previous)
	}
}

// Each handler has its own copy of Previous: one that edits it does not change
// what the next sees.
func TestPreviousIsACopyPerHandler(t *testing.T) {
	cl := welcomed(t)
	feed(cl, enterLine(5, 2, "7,9"))
	type seen struct {
		channel string
		client  string
		groups  []teamspeak.ServerGroupID
	}
	var mu sync.Mutex
	var saw []seen
	for range 3 {
		cl.OnChannelDeleted(func(e ChannelDeletedEvent) {
			mu.Lock()
			defer mu.Unlock()
			saw = append(saw, seen{channel: e.Previous.Name})
			e.Previous.Name = "scribble"
		})
		cl.OnClientLeave(func(e ClientLeaveEvent) {
			mu.Lock()
			defer mu.Unlock()
			saw = append(saw, seen{client: e.Previous.Nickname, groups: slices.Clone(e.Previous.ServerGroups)})
			e.Previous.Nickname = "scribble"
			e.Previous.ServerGroups[0] = 1000
		})
	}

	feed(cl, "notifychanneldeleted cid=3 invokerid=1",
		"notifyclientleftview cfid=2 ctid=0 reasonid=8 clid=5")
	settle(t, cl)

	mu.Lock()
	defer mu.Unlock()
	if len(saw) != 6 {
		t.Fatalf("%d calls", len(saw))
	}
	for _, s := range saw {
		switch {
		case s.channel != "" && s.channel != "B":
			t.Errorf("a handler saw channel %q", s.channel)
		case s.client != "" && (s.client != "c5" || !slices.Equal(s.groups, []teamspeak.ServerGroupID{7, 9})):
			t.Errorf("a handler saw client %q %v", s.client, s.groups)
		}
	}
}

// viewLog is what the handlers of a test saw, in order.
type viewLog struct {
	lines []string
	mu    sync.Mutex
}

func (l *viewLog) addf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *viewLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.lines)
}

// blockQueue holds the event goroutine on a handler of the first client-enter
// event it is given, so that the packets fed meanwhile queue up. It returns
// the function that lets it go.
func blockQueue(t *testing.T, cl *Client, log *viewLog) func() {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	cl.OnClientEnter(func(e ClientEnterEvent) {
		log.addf("enter %d", e.ID)
		once.Do(func() { <-gate })
	})
	cl.OnViewChanged(func(e ViewChangedEvent) { log.addf("changed %d", e.Revision) })

	return func() { close(gate) }
}

func TestViewChangedFollowsTheTypedEventsOnce(t *testing.T) {
	cl := welcomed(t)
	log := &viewLog{}
	release := blockQueue(t, cl, log)

	// The first packet's handler holds the queue; three more arrive meanwhile.
	for id := teamspeak.ClientID(10); id < 14; id++ {
		feed(cl, enterLine(id, 2, "7"))
	}
	revision := cl.View().Revision
	release()
	settle(t, cl)

	want := []string{"enter 10", "enter 11", "enter 12", "enter 13", fmt.Sprintf("changed %d", revision)}
	if got := log.snapshot(); !slices.Equal(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
}

func TestViewChangedSkipsAtMostSixtyThreeInARow(t *testing.T) {
	cl := welcomed(t)
	log := &viewLog{}
	release := blockQueue(t, cl, log)

	const packets = 200
	for id := range packets {
		feed(cl, enterLine(teamspeak.ClientID(100+id), 2, "7"))
	}
	revision := cl.View().Revision
	release()
	settle(t, cl)

	// With 200 markers queued the cap makes the 64th deliver instead of skip,
	// after the 64 typed events it covers; it carries the revision of the
	// moment, which already includes the rest, so the markers after it find
	// nothing new.
	got := log.snapshot()
	want := fmt.Sprintf("changed %d", revision)
	var at []int
	for i, line := range got {
		if strings.HasPrefix(line, "changed") {
			at = append(at, i)
		}
	}
	if len(got) != packets+1 || !slices.Equal(at, []int{64}) || got[64] != want {
		t.Errorf("%d events, announced at positions %v, want one at 64 saying %q", len(got), at, want)
	}
}

//nolint:funlen // one scenario, read top to bottom
func TestViewChangedIsNotSentWhenNothingMoved(t *testing.T) {
	// Not while loading, and not for the welcome that makes the view live: that
	// is the ViewReadyEvent.
	cl := newTestClient(t)
	log := &viewLog{}
	cl.OnViewReady(func(e ViewReadyEvent) { log.addf("ready %d", e.Revision) })
	cl.OnViewChanged(func(e ViewChangedEvent) { log.addf("changed %d", e.Revision) })
	beginView(cl, 1)
	feed(cl, "channellist cid=2 cpid=0 channel_name=A channel_order=0", enterLine(1, 2, "7"))
	settle(t, cl)
	if got := log.snapshot(); len(got) != 0 {
		t.Fatalf("while loading: %v", got)
	}
	feed(cl, "channellistfinished")
	settle(t, cl)
	ready := cl.View().Revision
	if got := log.snapshot(); !slices.Equal(got, []string{fmt.Sprintf("ready %d", ready)}) {
		t.Fatalf("at the end of the list: %v", got)
	}

	// A packet that changes nothing, and one the view ignores.
	feed(cl, "notifyclientupdated clid=77 client_nickname=Nobody", "notifychannelunsubscribed cid=77",
		"notifyservergroupclientadded sgid=7 clid=1")
	settle(t, cl)
	if got := log.snapshot(); len(got) != 1 {
		t.Errorf("a packet that changed nothing: %v", got)
	}

	// A change.
	feed(cl, enterLine(5, 2, "7"))
	settle(t, cl)
	revision := cl.View().Revision
	if got := log.snapshot(); !slices.Equal(got[1:], []string{fmt.Sprintf("changed %d", revision)}) {
		t.Errorf("after a change: %v", got)
	}

	// The end of the session is announced once.
	cl.handleConnectionClosed(cl.handler, errDropped)
	settle(t, cl)
	stale := cl.View().Revision
	if got := log.snapshot(); !slices.Equal(got[2:], []string{fmt.Sprintf("changed %d", stale)}) || stale == revision {
		t.Errorf("at the end: %v, revision %d after %d", got, stale, revision)
	}
	feed(cl, "notifychannelcreated cid=9 cpid=0 channel_name=Late channel_order=2 invokerid=1")
	settle(t, cl)
	if got := log.snapshot(); len(got) != 3 {
		t.Errorf("a stale view announced a change: %v", got)
	}
}

// The groups arrive after the view is live, and the event that says so comes
// after the ViewReadyEvent.
func TestViewChangedAnnouncesTheGroupsOfTheWelcome(t *testing.T) {
	cl := newTestClient(t)
	log := &viewLog{}
	cl.OnViewReady(func(ViewReadyEvent) { log.addf("ready") })
	cl.OnViewChanged(func(ViewChangedEvent) {
		v := cl.View()
		log.addf("changed loaded=%v groups=%d", v.GroupsLoaded, len(v.ServerGroups))
	})
	beginView(cl, 1)
	feed(cl, "channellist cid=1 cpid=0 channel_name=A channel_order=0", "channellistfinished",
		channelGroupLine("1=X"), serverGroupLine("1=A", "2=B"))
	settle(t, cl)

	got := log.snapshot()
	if len(got) < 2 || got[0] != "ready" || got[len(got)-1] != "changed loaded=true groups=2" {
		t.Errorf("events = %v", got)
	}
}

// Packets are handled on one goroutine while handlers and readers run on
// others: run with -race.
func TestViewGroupsAndServerCanBeReadWhilePacketsAreHandled(t *testing.T) {
	cl := welcomed(t)
	cl.OnViewChanged(func(ViewChangedEvent) { _ = cl.View() })
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
				v := cl.View()
				for _, g := range v.ServerGroups {
					_, _ = v.ServerGroup(g.ID)
				}
				_ = v.Server["virtualserver_name"]
			}
		})
	}
	for i := range 200 {
		feed(cl,
			serverGroupLine("1=A", fmt.Sprintf("%d=n", 2+i%7)),
			channelGroupLine("1=X"),
			fmt.Sprintf("notifyserveredited reasonid=10 virtualserver_name=n%d", i),
			fmt.Sprintf("notifyserverupdated virtualserver_maxclients=%d virtualserver_uptime=%d", i%5, i),
			enterLine(teamspeak.ClientID(10+i%3), 2, "7"),
			"notifyclientleftview cfid=2 ctid=0 reasonid=8 clid=10",
		)
	}
	close(stop)
	readers.Wait()
	settle(t, cl)
}
