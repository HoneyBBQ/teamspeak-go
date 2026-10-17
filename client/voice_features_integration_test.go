//go:build integration

package client_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// These tests join their own clients, so that none of them depends on what an
// earlier test left the shared pair doing. What a test changes on the server it
// restores.

// liveClient connects a fresh client and disconnects it when the test ends.
func liveClient(t *testing.T, nickname string, opts ...client.Option) *client.Client {
	t.Helper()
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	c := newClient(t, id, addr, nickname, append(integrationClientOptions(nil), opts...)...)
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	// A client learns its channel from its own enter notification.
	for deadline := time.Now().Add(liveEventWait); c.ChannelID() == 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}

	return c
}

// dbIDOf is c's database id, from the client list.
func dbIDOf(t *testing.T, via, c *client.Client) teamspeak.ClientDBID {
	t.Helper()
	clients, err := via.ListClients(t.Context(), teamspeak.ClientListOptions{})
	requireNoErr(t, err)
	for _, e := range clients {
		if e.UID == c.UID() {
			return e.DatabaseID
		}
	}
	t.Fatalf("the client list has no entry for %s", c.UID())

	return 0
}

// requireAdminWith is requireAdmin with extra options, such as middleware.
func requireAdminWith(t *testing.T, extra ...serverquery.Option) *serverquery.Client {
	t.Helper()
	var dialer serverquery.Dialer
	var opts []serverquery.Option
	switch {
	case os.Getenv("TEAMSPEAK_QUERY_KIND") == "tcp" && os.Getenv("TEAMSPEAK_QUERY_HOST") != "":
		dialer = serverquery.TCP(os.Getenv("TEAMSPEAK_QUERY_HOST") + ":" + os.Getenv("TEAMSPEAK_QUERY_PORT"))
		opts = append(opts, serverquery.WithLogin(
			os.Getenv("TEAMSPEAK_QUERY_LOGIN_NAME"), os.Getenv("TEAMSPEAK_QUERY_LOGIN_PASSWORD")))
	case os.Getenv("TEAMSPEAK_QUERY_KIND") == "web" && os.Getenv("TEAMSPEAK_QUERY_URL") != "":
		dialer = serverquery.Web(os.Getenv("TEAMSPEAK_QUERY_URL"), os.Getenv("TEAMSPEAK_QUERY_API_KEY"))
	default:
		t.Skipf("no administrator query endpoint provisioned (TEAMSPEAK_QUERY_KIND=%q)", os.Getenv("TEAMSPEAK_QUERY_KIND"))
	}
	admin, err := serverquery.New(dialer, append(append(opts, serverquery.WithServer(1)), extra...)...)
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

// voiceFrom collects the speakers a client hears.
type voiceFrom struct {
	speaker map[teamspeak.ClientID]int
	mu      sync.Mutex
}

func hearing(c *client.Client) *voiceFrom {
	v := &voiceFrom{speaker: map[teamspeak.ClientID]int{}}
	c.OnVoiceData(func(e client.VoiceDataEvent) {
		v.mu.Lock()
		v.speaker[e.ClientID]++
		v.mu.Unlock()
	})

	return v
}

func (v *voiceFrom) heard(id teamspeak.ClientID) int {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.speaker[id]
}

// whisperFor sends frames for a while, so that a creates datagram does not
// decide the test, and returns once the window has passed.
func whisperFor(t *testing.T, send func() error) {
	t.Helper()
	for range 25 {
		requireNoErr(t, send())
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(time.Second)
}

var whisperFrame = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// guestCopy makes a server group of the Guest group's permissions, deleted when
// the test ends: a client in an explicit group no longer has the default
// group's permissions, so a plain group would take the whisper power away.
func guestCopy(t *testing.T, admin *serverquery.Client, prefix string) teamspeak.ServerGroupID {
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
		t.Skip("the server has no regular group named Guest to copy")
	}
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1e9)
	gid, err := admin.CopyServerGroup(t.Context(), template, 0, name, teamspeak.GroupRegular)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteServerGroup(ctx, gid, teamspeak.GroupDeleteOptions{Force: true})
	})

	return gid
}

// channelGroupCopy makes a channel group of a regular group's permissions,
// deleted when the test ends.
func channelGroupCopy(t *testing.T, admin *serverquery.Client, prefix string) teamspeak.ChannelGroupID {
	t.Helper()
	groups, err := admin.ListChannelGroups(t.Context(), teamspeak.ChannelGroupListOptions{})
	requireNoErr(t, err)
	var template teamspeak.ChannelGroupID
	for _, g := range groups {
		if g.Type == teamspeak.GroupRegular && (template == 0 || g.Name == "Guest") {
			template = g.ID
		}
	}
	if template == 0 {
		t.Skip("the server has no regular channel group to copy")
	}
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1e9)
	cgid, err := admin.CopyChannelGroup(t.Context(), template, 0, name, teamspeak.GroupRegular)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannelGroup(ctx, cgid, teamspeak.GroupDeleteOptions{Force: true})
	})

	return cgid
}

func TestIntegration_ChannelWhisperReachesMembersOnly(t *testing.T) {
	admin := requireAdmin(t)
	start := time.Now()
	sender := liveClient(t, "whisper-sender")
	member := liveClient(t, "whisper-member")
	outsider := liveClient(t, "whisper-outsider")
	memberHears, outsiderHears := hearing(member), hearing(outsider)

	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: fmt.Sprintf("whisper-room-%d", time.Now().UnixNano()%1e9),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	origin := member.ChannelID()
	requireNoErr(t, member.MoveClient(t.Context(), member.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = member.MoveClient(ctx, member.ClientID(), origin, teamspeak.ClientMoveOptions{})
	})
	time.Sleep(500 * time.Millisecond)

	whisperFor(t, func() error {
		targets := client.WhisperTargets{Channels: []teamspeak.ChannelID{cid}}

		return sender.SendWhisper(whisperFrame, targets, teamspeak.CodecOpusMusic)
	})
	if got := memberHears.heard(sender.ClientID()); got == 0 {
		t.Error("the channel's member heard nothing")
	} else {
		t.Logf("the member heard %d frames", got)
	}
	if got := outsiderHears.heard(sender.ClientID()); got != 0 {
		t.Errorf("the outsider heard %d frames", got)
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_ServerGroupWhisperReachesMembersOnly(t *testing.T) {
	admin := requireAdmin(t)
	start := time.Now()
	sender := liveClient(t, "gwhisper-sender")
	member := liveClient(t, "gwhisper-member")
	outsider := liveClient(t, "gwhisper-outsider")
	memberHears, outsiderHears := hearing(member), hearing(outsider)

	gid := guestCopy(t, admin, "whisper-group")
	dbid := dbIDOf(t, sender, member)
	requireNoErr(t, admin.AddClientToServerGroup(t.Context(), gid, dbid))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.RemoveClientFromServerGroup(ctx, gid, dbid)
	})
	time.Sleep(500 * time.Millisecond)

	whisperFor(t, func() error {
		target := client.WhisperToServerGroup(client.GroupWhisperAllChannels, gid)

		return sender.SendGroupWhisper(whisperFrame, target, teamspeak.CodecOpusMusic)
	})
	if memberHears.heard(sender.ClientID()) == 0 {
		t.Error("the group's member heard nothing")
	}
	if got := outsiderHears.heard(sender.ClientID()); got != 0 {
		t.Errorf("the outsider heard %d frames", got)
	}

	// The current-channel scope reaches the same member, who shares the channel.
	before := memberHears.heard(sender.ClientID())
	whisperFor(t, func() error {
		target := client.WhisperToServerGroup(client.GroupWhisperCurrentChannel, gid)

		return sender.SendGroupWhisper(whisperFrame, target, teamspeak.CodecOpusMusic)
	})
	if memberHears.heard(sender.ClientID()) == before {
		t.Error("the member heard nothing under the current-channel scope")
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_ChannelGroupWhisperReachesHoldersOnly(t *testing.T) {
	admin := requireAdmin(t)
	start := time.Now()
	sender := liveClient(t, "cgwhisper-sender")
	member := liveClient(t, "cgwhisper-member")
	outsider := liveClient(t, "cgwhisper-outsider")
	memberHears, outsiderHears := hearing(member), hearing(outsider)

	cgid := channelGroupCopy(t, admin, "whisper-cg")
	holder := dbIDOf(t, sender, member)
	requireNoErr(t, admin.SetClientChannelGroup(t.Context(), cgid, member.ChannelID(), holder))
	time.Sleep(500 * time.Millisecond)

	whisperFor(t, func() error {
		target := client.WhisperToChannelGroup(client.GroupWhisperAllChannels, cgid)

		return sender.SendGroupWhisper(whisperFrame, target, teamspeak.CodecOpusMusic)
	})
	if memberHears.heard(sender.ClientID()) == 0 {
		t.Error("the channel group's holder heard nothing")
	}
	if got := outsiderHears.heard(sender.ClientID()); got != 0 {
		t.Errorf("the outsider heard %d frames", got)
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_PrivilegeKeyJoinsWithItsGroupAndIsConsumed(t *testing.T) {
	admin := requireAdmin(t)
	start := time.Now()
	gid := guestCopy(t, admin, "key-group")
	keyOptions := teamspeak.PrivilegeKeyOptions{ServerGroupID: gid, Description: "voice-features"}
	token, err := admin.AddPrivilegeKey(t.Context(), keyOptions)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeletePrivilegeKey(ctx, token)
	})

	joiner := liveClient(t, "key-joiner", client.WithPrivilegeKey(token))
	members, err := admin.ListServerGroupClients(t.Context(), gid, teamspeak.ServerGroupClientListOptions{Names: true})
	requireNoErr(t, err)
	if !slices.ContainsFunc(members, func(m teamspeak.ServerGroupMember) bool { return m.UID == joiner.UID() }) {
		t.Errorf("the joiner is not in group %d: %+v", gid, members)
	}
	keys, err := admin.ListPrivilegeKeys(t.Context())
	requireNoErr(t, err)
	if slices.ContainsFunc(keys, func(k teamspeak.PrivilegeKey) bool { return k.Token == token }) {
		t.Error("the key is still listed after the join")
	}

	// A reconnection does not present the spent key, which the server would
	// refuse the join over.
	requireNoErr(t, joiner.Disconnect(t.Context()))
	requireNoErr(t, connectWithRetries(t.Context(), t, joiner))
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_MetaDataIsSeenOnEnterAndInUpdates(t *testing.T) {
	start := time.Now()
	observer := liveClient(t, "meta-observer")
	entered := listen(t, observer.OnClientEnter)
	updated := listen(t, observer.OnClientUpdated)

	joiner := liveClient(t, "meta-joiner", client.WithMetaData("first meta"))
	enter := await(t, entered, "the joiner's enter", func(e client.ClientEnterEvent) bool { return e.UID == joiner.UID() })
	if enter.MetaData != "first meta" {
		t.Errorf("MetaData on enter = %q, want %q", enter.MetaData, "first meta")
	}

	requireNoErr(t, joiner.UpdateClient(t.Context(), teamspeak.ClientUpdateOptions{MetaData: new("second meta")}))
	update := await(t, updated, "the meta data update", func(e client.ClientUpdatedEvent) bool {
		return e.ClientID == joiner.ClientID() && e.Changes.MetaData != nil
	})
	if *update.Changes.MetaData != "second meta" {
		t.Errorf("MetaData in the update = %q", *update.Changes.MetaData)
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_LeaveMessageReachesABystander(t *testing.T) {
	start := time.Now()
	observer := liveClient(t, "leave-observer")
	left := listen(t, observer.OnClientLeave)
	leaver := liveClient(t, "leave-leaver")
	id := leaver.ClientID()

	requireNoErr(t, leaver.DisconnectWithMessage(t.Context(), "see you later"))
	e := await(t, left, "the leaver's departure", func(e client.ClientLeaveEvent) bool { return e.ClientID == id })
	if e.ReasonMessage != "see you later" || e.Reason != teamspeak.ReasonDisconnect {
		t.Errorf("ClientLeave = reason %v, message %q", e.Reason, e.ReasonMessage)
	}

	// Disconnect without a message says Shutdown.
	quiet := liveClient(t, "leave-quiet")
	quietID := quiet.ClientID()
	requireNoErr(t, quiet.Disconnect(t.Context()))
	e = await(t, left, "the second departure", func(e client.ClientLeaveEvent) bool { return e.ClientID == quietID })
	if e.ReasonMessage != "Shutdown" {
		t.Errorf("default leave message = %q, want Shutdown", e.ReasonMessage)
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_ConnectionInfoIsAnsweredAndReadByAnotherClient(t *testing.T) {
	start := time.Now()
	subject := liveClient(t, "info-subject")
	reader := liveClient(t, "info-reader")

	// The server asks the subject for its figures when someone reads them, and
	// answers at once with what it has: poll until the subject's report is in.
	// The first keepalive round trip takes one ping interval.
	var info teamspeak.ClientConnectionInfo
	deadline := time.Now().Add(20 * time.Second)
	for {
		var err error
		info, err = reader.GetClientConnectionInfo(t.Context(), subject.ClientID())
		requireNoErr(t, err)
		if info.Ping > 0 && info.Sent.Control.Packets > 0 && info.Received.Keepalive.Packets > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete report from the subject within 20s: %+v", info)
		}
		time.Sleep(time.Second)
	}
	t.Logf("ping %s deviation %s connected %s idle %s ip %q port %d", info.Ping, info.PingDeviation,
		info.ConnectedTime, info.IdleTime, info.IP, info.Port)
	t.Logf("sent speech/keepalive/control packets %d/%d/%d bytes %d/%d/%d", info.Sent.Speech.Packets,
		info.Sent.Keepalive.Packets, info.Sent.Control.Packets, info.Sent.Speech.Bytes,
		info.Sent.Keepalive.Bytes, info.Sent.Control.Bytes)
	t.Logf("received speech/keepalive/control packets %d/%d/%d bytes %d/%d/%d", info.Received.Speech.Packets,
		info.Received.Keepalive.Packets, info.Received.Control.Packets, info.Received.Speech.Bytes,
		info.Received.Keepalive.Bytes, info.Received.Control.Bytes)
	if info.ID != subject.ClientID() {
		t.Errorf("ID = %d, want %d", info.ID, subject.ClientID())
	}
	if info.Ping <= 0 || info.Ping > 500*time.Millisecond {
		t.Errorf("Ping = %s, want a small positive round trip on loopback", info.Ping)
	}
	// A datagram is at least its header: 13 bytes with the tag going out, 11 coming in.
	if info.Sent.Control.Bytes < info.Sent.Control.Packets*13 ||
		info.Received.Control.Bytes < info.Received.Control.Packets*11 {
		t.Errorf("control bytes are below the headers of their packets: %+v", info)
	}
	if info.ConnectedTime <= 0 {
		t.Errorf("ConnectedTime = %s", info.ConnectedTime)
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_VerifyServerPassword(t *testing.T) {
	if integrationServerPassword == "" {
		t.Skip("the fixture sets no server password: nothing to verify")
	}
	c := liveClient(t, "verify-server")
	start := time.Now()
	ok, err := c.VerifyServerPassword(t.Context(), integrationServerPassword)
	requireNoErr(t, err)
	if !ok {
		t.Error("the server's own password did not verify")
	}
	ok, err = c.VerifyServerPassword(t.Context(), "not the password")
	requireNoErr(t, err)
	if ok {
		t.Error("a wrong password verified")
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

func TestIntegration_VerifyChannelPassword(t *testing.T) {
	name, password := os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL"), os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD")
	if name == "" || password == "" {
		t.Skip("the fixture provisions no password channel")
	}
	c := liveClient(t, "verify-channel")
	start := time.Now()
	channels, err := c.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	var cid teamspeak.ChannelID
	for _, ch := range channels {
		if ch.Name == name {
			cid = ch.ID
		}
	}
	if cid == 0 {
		t.Skipf("the server has no channel named %q", name)
	}
	before := c.ChannelID()
	ok, err := c.VerifyChannelPassword(t.Context(), cid, password)
	requireNoErr(t, err)
	if !ok {
		t.Error("the channel's own password did not verify")
	}
	ok, err = c.VerifyChannelPassword(t.Context(), cid, "not the password")
	requireNoErr(t, err)
	if ok {
		t.Error("a wrong password verified")
	}
	if c.ChannelID() != before {
		t.Errorf("verifying moved the client from channel %d to %d", before, c.ChannelID())
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}

// dropRows answers the named commands with no rows, as TeamSpeak 6's WebQuery
// sometimes answers a create that succeeded.
func dropRows(commands ...string) teamspeak.CommandMiddleware {
	return func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			rows, err := next.Send(ctx, req)
			if err == nil && slices.Contains(commands, req.Command()) {
				return nil, nil
			}

			return rows, err
		})
	}
}

// recovery is a ServerQuery administrator whose creating commands answer with
// no rows, and the ids it has seen made.
type recovery struct {
	admin *serverquery.Client
	t     *testing.T
	stamp int64
	runs  atomic.Int32
}

func newRecovery(t *testing.T) *recovery {
	t.Helper()
	r := &recovery{t: t, stamp: time.Now().UnixNano() % 1e9}
	creating := []string{"channelcreate", "servergroupadd", "servergroupcopy", "channelgroupadd", "channelgroupcopy"}
	counting := func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			if slices.Contains(creating, req.Command()) {
				r.runs.Add(1)
			}

			return next.Send(ctx, req)
		})
	}
	r.admin = requireAdminWith(t, serverquery.WithCommandMiddleware(counting, dropRows(creating...)))

	return r
}

// cleanup runs fn when the test ends, with a context of its own.
func (r *recovery) cleanup(fn func(context.Context)) {
	r.t.Cleanup(func() {
		c, cancel := cleanupContext()
		defer cancel()
		fn(c)
	})
}

func (r *recovery) channels() {
	t, ctx := r.t, r.t.Context()
	name := fmt.Sprintf("recover-%d", r.stamp)
	parent, err := r.admin.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: name})
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteChannel(c, parent, teamspeak.ChannelDeleteOptions{Force: true})
	})
	// The same name under another parent is another channel: the parent decides.
	child, err := r.admin.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: name, ParentID: parent})
	requireNoErr(t, err)
	if child == parent || child == 0 {
		t.Errorf("child = %d, parent = %d", child, parent)
	}
	channels, err := r.admin.ListChannels(ctx, teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	for _, ch := range channels {
		if ch.ID == child && ch.ParentID != parent {
			t.Errorf("the child's parent is %d, want %d", ch.ParentID, parent)
		}
	}
}

func (r *recovery) serverGroups() {
	t, ctx := r.t, r.t.Context()
	name := fmt.Sprintf("recover-group-%d", r.stamp)
	// A group of the name and another type exists first, and must not be the
	// one returned.
	other, err := r.admin.CreateServerGroup(ctx, name, teamspeak.GroupQuery)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteServerGroup(c, other, teamspeak.GroupDeleteOptions{Force: true})
	})
	sg, err := r.admin.CreateServerGroup(ctx, name, teamspeak.GroupRegular)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteServerGroup(c, sg, teamspeak.GroupDeleteOptions{Force: true})
	})
	if sg == other || sg == 0 {
		t.Errorf("server group = %d, the other type's = %d", sg, other)
	}
	groups, err := r.admin.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	for _, g := range groups {
		if g.ID == sg && (g.Name != name || g.Type != teamspeak.GroupRegular) {
			t.Errorf("recovered server group = %+v", g)
		}
	}
	copied, err := r.admin.CopyServerGroup(ctx, sg, 0, name+"-copy", teamspeak.GroupRegular)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteServerGroup(c, copied, teamspeak.GroupDeleteOptions{Force: true})
	})
	if copied == sg || copied == 0 {
		t.Errorf("copied server group = %d", copied)
	}
}

func (r *recovery) channelGroups() {
	t, ctx := r.t, r.t.Context()
	name := fmt.Sprintf("recover-group-%d", r.stamp)
	other, err := r.admin.CreateChannelGroup(ctx, name, teamspeak.GroupTemplate)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteChannelGroup(c, other, teamspeak.GroupDeleteOptions{Force: true})
	})
	cg, err := r.admin.CreateChannelGroup(ctx, name, teamspeak.GroupRegular)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteChannelGroup(c, cg, teamspeak.GroupDeleteOptions{Force: true})
	})
	if cg == other || cg == 0 {
		t.Errorf("channel group = %d, the other type's = %d", cg, other)
	}
	copied, err := r.admin.CopyChannelGroup(ctx, cg, 0, name+"-copy", teamspeak.GroupRegular)
	requireNoErr(t, err)
	r.cleanup(func(c context.Context) {
		_ = r.admin.DeleteChannelGroup(c, copied, teamspeak.GroupDeleteOptions{Force: true})
	})
	if copied == cg || copied == 0 {
		t.Errorf("copied channel group = %d", copied)
	}
}

func TestIntegration_CreateRecoversFromAnAnswerWithoutRows(t *testing.T) {
	start := time.Now()
	r := newRecovery(t)
	r.channels()
	r.serverGroups()
	r.channelGroups()
	if r.runs.Load() != 8 {
		t.Errorf("%d creating commands ran, want 8", r.runs.Load())
	}
	t.Logf("took %s", time.Since(start).Round(time.Millisecond))
}
