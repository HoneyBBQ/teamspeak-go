//go:build integration

package serverquery_test

// Integration tests for the commands that take several values in one call:
// kick, move and ban for several clients, server group membership, and the
// permission batches. Each runs over every query transport the environment
// provides and over the voice protocol, and makes what it needs under names of
// its own: voice clients as the targets, a scratch channel, groups and ban
// rules, all of which it removes again, whether the test passes or not.

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// noSuchClient is a client id no connection of these tests holds.
const (
	noSuchClient   teamspeak.ClientID   = 64000
	noSuchDatabase teamspeak.ClientDBID = 90000000
)

// batchActor is what both the query client and the voice client offer: the
// commands under test.
type batchActor interface {
	KickClients(
		ctx context.Context, clids []teamspeak.ClientID, reason teamspeak.Reason, opts teamspeak.KickClientsOptions,
	) error
	MoveClients(
		ctx context.Context, clids []teamspeak.ClientID, channelID teamspeak.ChannelID, opts teamspeak.MoveClientsOptions,
	) error
	BanClients(
		ctx context.Context, clids []teamspeak.ClientID, opts teamspeak.BanClientsOptions,
	) ([]teamspeak.BanID, error)
	AddClientsToServerGroup(
		ctx context.Context, group teamspeak.ServerGroupID, dbids []teamspeak.ClientDBID,
		opts teamspeak.ServerGroupMembersOptions,
	) error
	RemoveClientsFromServerGroup(
		ctx context.Context, group teamspeak.ServerGroupID, dbids []teamspeak.ClientDBID,
		opts teamspeak.ServerGroupMembersOptions,
	) error
}

// batchTarget is a voice client the batches act on.
type batchTarget struct {
	voice *client.Client
	id    teamspeak.ClientID
	dbid  teamspeak.ClientDBID
}

var (
	connectPace sync.Mutex
	lastConnect time.Time
)

// paceConnect keeps voice connects at most one a second: the servers limit new
// connections from one address.
func paceConnect() {
	connectPace.Lock()
	defer connectPace.Unlock()
	if wait := time.Second + 100*time.Millisecond - time.Since(lastConnect); wait > 0 {
		time.Sleep(wait)
	}
	lastConnect = time.Now()
}

// batchTargets connects n voice clients, paced, and removes them and their
// database entries at the end of the test.
func batchTargets(t *testing.T, c *serverquery.Client, n int, tag string) []batchTarget {
	t.Helper()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	out := make([]batchTarget, 0, n)
	for i := range n {
		paceConnect()
		nick := "tg-" + tag + strconv.Itoa(i) + stamp[len(stamp)-5:]
		voice := voiceClient(t, nick)
		ctx := adminCtx(t)
		target := batchTarget{voice: voice, id: voice.ClientID()}
		// The server lists a client a moment after it has connected.
		for deadline := time.Now().Add(10 * time.Second); target.dbid == 0 && time.Now().Before(deadline); {
			entries, err := c.ListClients(ctx, teamspeak.ClientListOptions{})
			if err != nil {
				t.Fatalf("ListClients: %v", err)
			}
			for _, e := range entries {
				if e.ID == target.id {
					target.dbid = e.DatabaseID
				}
			}
			if target.dbid == 0 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		if target.dbid == 0 {
			t.Fatalf("no database id for client %d: the server never listed it", target.id)
		}
		out = append(out, target)
		cleanup(t, "the target "+nick, func(ctx context.Context) error {
			_ = voice.Disconnect(ctx)
			waitGone(ctx, c, nick)
			err := c.DeleteClientDatabase(ctx, target.dbid)
			if errors.Is(err, errcode.ClientInvalidID) {
				return nil
			}

			return err
		})
	}

	return out
}

// waitGone waits for the server to notice a client left.
func waitGone(ctx context.Context, c *serverquery.Client, nick string) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		online, err := c.FindClients(ctx, nick)
		if err == nil && len(online) == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// channelsOf reads where each target is, by client id.
func channelsOf(
	t *testing.T, c *serverquery.Client, targets []batchTarget,
) map[teamspeak.ClientID]teamspeak.ChannelID {
	t.Helper()
	entries, err := c.ListClients(adminCtx(t), teamspeak.ClientListOptions{})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	out := map[teamspeak.ClientID]teamspeak.ChannelID{}
	for _, e := range entries {
		for _, target := range targets {
			if e.ID == target.id {
				out[e.ID] = e.ChannelID
			}
		}
	}

	return out
}

// everyChannel is channelsOf for targets that must all be online.
func everyChannel(
	t *testing.T, c *serverquery.Client, targets []batchTarget,
) map[teamspeak.ClientID]teamspeak.ChannelID {
	t.Helper()
	got := channelsOf(t, c, targets)
	if len(got) != len(targets) {
		t.Fatalf("%d of %d clients are online: %v", len(got), len(targets), got)
	}

	return got
}

// waitOnline waits until the clients named are online or gone, as want says.
func waitOnline(
	t *testing.T, c *serverquery.Client, targets []batchTarget, want bool,
) map[teamspeak.ClientID]teamspeak.ChannelID {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := channelsOf(t, c, targets)
		if (len(got) == len(targets)) == want && (want || len(got) == 0) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func ids(targets ...batchTarget) []teamspeak.ClientID {
	out := make([]teamspeak.ClientID, len(targets))
	for i, target := range targets {
		out[i] = target.id
	}

	return out
}

func dbids(targets ...batchTarget) []teamspeak.ClientDBID {
	out := make([]teamspeak.ClientDBID, len(targets))
	for i, target := range targets {
		out[i] = target.dbid
	}

	return out
}

func wantCode(t *testing.T, what string, err error, code errcode.Code) {
	t.Helper()
	if !errors.Is(err, code) {
		t.Errorf("%s: err = %v, want %v", what, err, code)
	}
}

// adminVoice connects a voice client that may kick, move, ban and edit groups:
// it joins the regular Server Admin group, which the end of the test undoes by
// removing the client's database entry.
func adminVoice(t *testing.T, c *serverquery.Client) *client.Client {
	t.Helper()
	groups, err := c.ListServerGroups(adminCtx(t), teamspeak.ServerGroupListOptions{})
	if err != nil {
		t.Fatalf("ListServerGroups: %v", err)
	}
	i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool {
		return g.Type == teamspeak.GroupRegular && g.Name == "Server Admin"
	})
	if i < 0 {
		t.Skip("no regular Server Admin group for a voice client to act with")
	}
	actors := batchTargets(t, c, 1, "ac")
	err = c.AddClientsToServerGroup(adminCtx(t), groups[i].ID, dbids(actors[0]), teamspeak.ServerGroupMembersOptions{})
	if err != nil {
		t.Fatalf("making the voice client an admin: %v", err)
	}

	return actors[0].voice
}

// Several clients are moved in one command, and one that cannot be moved
// decides what happens to the rest only as the server says: measured on both
// servers, without -continueonerror the whole command is refused, with it the
// others move and the answer is success.
func TestQueryMulti_MoveAndKickClients(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		runMoveAndKick(t, c, c, "q"+transport[:1])
	})
}

func TestVoiceMulti_MoveAndKickClients(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport != "ssh" {
			t.Skip("the voice variant runs once, beside the SSH connection")
		}
		voice := adminVoice(t, c)
		runMoveAndKick(t, voice, c, "v")
	})
}

//nolint:funlen // a short script of what the server did at each step
func runMoveAndKick(t *testing.T, actor batchActor, c *serverquery.Client, tag string) {
	t.Helper()
	ctx := adminCtx(t)
	a := scratchChannel(t, c, "ts-go-mv-a-")
	b := scratchChannel(t, c, "ts-go-mv-b-")
	targets := batchTargets(t, c, 3, tag)
	all := ids(targets...)

	err := actor.MoveClients(ctx, all, a, teamspeak.MoveClientsOptions{})
	if err != nil {
		t.Fatalf("MoveClients: %v", err)
	}
	for id, cid := range everyChannel(t, c, targets) {
		if cid != a {
			t.Errorf("after the move client %d is in channel %d, want %d", id, cid, a)
		}
	}

	// An unknown id refuses the whole command: nobody moves.
	err = actor.MoveClients(ctx, []teamspeak.ClientID{all[0], noSuchClient, all[1]}, b, teamspeak.MoveClientsOptions{})
	wantCode(t, "MoveClients with an unknown id", err, errcode.ClientInvalidID)
	for id, cid := range everyChannel(t, c, targets) {
		if cid != a {
			t.Errorf("after the refused move client %d is in channel %d, want it to stay in %d", id, cid, a)
		}
	}

	// With the flag the others move and the failure is not reported.
	err = actor.MoveClients(ctx, []teamspeak.ClientID{all[0], noSuchClient, all[1]}, b,
		teamspeak.MoveClientsOptions{ContinueOnError: true})
	if err != nil {
		t.Errorf("MoveClients with the flag: %v, want success", err)
	}
	got := everyChannel(t, c, targets)
	if got[all[0]] != b || got[all[1]] != b || got[all[2]] != a {
		t.Errorf("after the flagged move the clients are in %v, want the first two in %d and the third in %d", got, b, a)
	}

	// Kicks stop at the first id that fails, and the clients before it are gone.
	err = actor.KickClients(ctx, []teamspeak.ClientID{all[0], noSuchClient, all[1]}, teamspeak.ReasonKickServer,
		teamspeak.KickClientsOptions{ReasonMessage: "ts-go batch"})
	wantCode(t, "KickClients with an unknown id", err, errcode.ClientInvalidID)
	remaining := waitOnline(t, c, targets[:1], false)
	if len(remaining) != 0 {
		t.Errorf("the client before the unknown id is still online: %v", remaining)
	}
	if left := channelsOf(t, c, targets[1:]); len(left) != 2 {
		t.Errorf("clients after the unknown id: %v, want both still online", left)
	}

	// With the flag it goes on, and says nothing of the id it passed.
	err = actor.KickClients(ctx, []teamspeak.ClientID{noSuchClient, all[1], all[2]}, teamspeak.ReasonKickServer,
		teamspeak.KickClientsOptions{ContinueOnError: true})
	if err != nil {
		t.Errorf("KickClients with the flag: %v, want success", err)
	}
	if left := waitOnline(t, c, targets[1:], false); len(left) != 0 {
		t.Errorf("after the flagged kick clients are still online: %v", left)
	}
}

// Bans for several clients: the rules the call made are found by comparing the
// list before and after, because the ids the call returns can be fewer than the
// rules, and none over the voice protocol. Every rule the call created is
// removed before anything else connects, since a rule on the address refuses
// the next connection from it.
func TestQueryMulti_BanClients(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		runBanClients(t, c, c, "b"+transport[:1])
	})
}

func TestVoiceMulti_BanClients(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport != "ssh" {
			t.Skip("the voice variant runs once, beside the SSH connection")
		}
		voice := adminVoice(t, c)
		runBanClients(t, voice, c, "bv")
	})
}

func banIDs(t *testing.T, c *serverquery.Client) []teamspeak.BanID {
	t.Helper()
	bans, err := c.ListBans(adminCtx(t), teamspeak.BanListOptions{})
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}
	out := make([]teamspeak.BanID, len(bans))
	for i, ban := range bans {
		out[i] = ban.ID
	}

	return out
}

// removeNewBans deletes every ban that was not there before.
func removeNewBans(ctx context.Context, c *serverquery.Client, before []teamspeak.BanID) error {
	bans, err := c.ListBans(ctx, teamspeak.BanListOptions{})
	if err != nil {
		return err
	}
	for _, ban := range bans {
		if !slices.Contains(before, ban.ID) {
			err = c.DeleteBan(ctx, ban.ID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func runBanClients(t *testing.T, actor batchActor, c *serverquery.Client, tag string) {
	t.Helper()
	ctx := adminCtx(t)
	before := banIDs(t, c)
	// Registered before any ban exists, so a failure part way still removes
	// what was made.
	cleanup(t, "the bans the test made", func(ctx context.Context) error { return removeNewBans(ctx, c, before) })
	targets := batchTargets(t, c, 2, tag)
	all := ids(targets...)

	// An unknown id refuses the command before anyone is banned.
	_, err := actor.BanClients(ctx, []teamspeak.ClientID{all[0], noSuchClient, all[1]},
		teamspeak.BanClientsOptions{Reason: "ts-go batch", Duration: time.Minute})
	wantCode(t, "BanClients with an unknown id", err, errcode.ClientInvalidID)
	if made := banIDs(t, c); len(made) != len(before) {
		t.Fatalf("the refused command made bans: %v, before %v", made, before)
	}
	if got := channelsOf(t, c, targets); len(got) != 2 {
		t.Errorf("after the refused ban the clients online are %v, want both", got)
	}

	reported, err := actor.BanClients(ctx, []teamspeak.ClientID{all[0], noSuchClient, all[1]},
		teamspeak.BanClientsOptions{Reason: "ts-go batch", Duration: time.Minute, ContinueOnError: true})
	// The address rule must go before anything else connects, whatever came back.
	removeErr := removeNewBans(ctx, c, before)
	if err != nil {
		t.Fatalf("BanClients with the flag: %v, want success", err)
	}
	if removeErr != nil {
		t.Fatalf("removing the bans: %v", removeErr)
	}
	if left := waitOnline(t, c, targets, false); len(left) != 0 {
		t.Errorf("after the flagged ban clients are still online: %v", left)
	}
	t.Logf("BanClients reported %d ban ids", len(reported))
}

// Group membership for several clients, and what the server answers when one
// of them fails: measured, the first failure without the flag and the last
// failure with it, with every client that could be added or removed done.
func TestQueryMulti_ServerGroupMembers(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		runGroupMembers(t, c, c, "g"+transport[:1])
	})
}

func TestVoiceMulti_ServerGroupMembers(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport != "ssh" {
			t.Skip("the voice variant runs once, beside the SSH connection")
		}
		voice := adminVoice(t, c)
		runGroupMembers(t, voice, c, "gv")
	})
}

func membersOf(t *testing.T, c *serverquery.Client, group teamspeak.ServerGroupID) []teamspeak.ClientDBID {
	t.Helper()
	members, err := c.ListServerGroupClients(adminCtx(t), group, teamspeak.ServerGroupClientListOptions{})
	if err != nil {
		t.Fatalf("ListServerGroupClients: %v", err)
	}
	out := make([]teamspeak.ClientDBID, len(members))
	for i, m := range members {
		out[i] = m.DatabaseID
	}
	slices.Sort(out)

	return out
}

func sorted(in ...teamspeak.ClientDBID) []teamspeak.ClientDBID {
	slices.Sort(in)

	return in
}

//nolint:funlen // a short script of what the server did at each step
func runGroupMembers(t *testing.T, actor batchActor, c *serverquery.Client, tag string) {
	t.Helper()
	ctx := adminCtx(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	group, err := c.CreateServerGroup(ctx, "ts-go-mv-"+stamp, teamspeak.GroupRegular)
	if err != nil {
		t.Fatalf("CreateServerGroup: %v", err)
	}
	cleanup(t, "the scratch server group", func(ctx context.Context) error {
		return c.DeleteServerGroup(ctx, group, teamspeak.GroupDeleteOptions{Force: true})
	})
	// A group made through ServerQuery needs the power of its maker to change
	// its members; lowered, a voice client with the Server Admin group may.
	for _, name := range []string{perm.GroupNeededMemberAddPower, perm.GroupNeededMemberRemovePower} {
		err = c.AddServerGroupPermission(ctx, group, teamspeak.PermissionByName(name), 10,
			teamspeak.ServerGroupPermissionOptions{})
		if err != nil {
			t.Fatalf("lowering %s: %v", name, err)
		}
	}
	targets := batchTargets(t, c, 3, tag)
	a, b, d := targets[0].dbid, targets[1].dbid, targets[2].dbid
	flag := teamspeak.ServerGroupMembersOptions{ContinueOnError: true}
	none := teamspeak.ServerGroupMembersOptions{}

	// The first failure ends the command; the client before it was added.
	err = actor.AddClientsToServerGroup(ctx, group, []teamspeak.ClientDBID{a, noSuchDatabase, b}, none)
	wantCode(t, "adding with an unknown id", err, errcode.ClientInvalidID)
	if got := membersOf(t, c, group); !slices.Equal(got, sorted(a)) {
		t.Errorf("members after the stopped add = %v, want only %d", got, a)
	}

	// With the flag the answer is the last failure: a duplicate, then an unknown
	// id, then a client that can be added.
	err = actor.AddClientsToServerGroup(ctx, group, []teamspeak.ClientDBID{a, noSuchDatabase, d}, flag)
	wantCode(t, "adding with a duplicate before an unknown id", err, errcode.ClientInvalidID)
	if got := membersOf(t, c, group); !slices.Equal(got, sorted(a, d)) {
		t.Errorf("members after the flagged add = %v, want %d and %d", got, a, d)
	}
	err = actor.AddClientsToServerGroup(ctx, group, []teamspeak.ClientDBID{noSuchDatabase, a, b}, flag)
	wantCode(t, "adding with an unknown id before a duplicate", err, errcode.PermissionDuplicateEntry)
	if got := membersOf(t, c, group); !slices.Equal(got, sorted(a, b, d)) {
		t.Errorf("members after the second flagged add = %v, want all three", got)
	}

	// Removing: a client that is not a member fails, and the flag goes on past it.
	err = actor.RemoveClientsFromServerGroup(ctx, group, []teamspeak.ClientDBID{noSuchDatabase, a, b}, none)
	wantCode(t, "removing an unknown id first", err, errcode.PermissionEmptyResult)
	if got := membersOf(t, c, group); !slices.Equal(got, sorted(a, b, d)) {
		t.Errorf("members after the stopped removal = %v, want all three", got)
	}
	err = actor.RemoveClientsFromServerGroup(ctx, group, []teamspeak.ClientDBID{noSuchDatabase, a, b}, flag)
	wantCode(t, "removing with the flag past an unknown id", err, errcode.PermissionEmptyResult)
	if got := membersOf(t, c, group); !slices.Equal(got, sorted(d)) {
		t.Errorf("members after the flagged removal = %v, want only %d", got, d)
	}
	err = actor.RemoveClientsFromServerGroup(ctx, group, []teamspeak.ClientDBID{d}, none)
	if err != nil {
		t.Errorf("RemoveClientsFromServerGroup: %v", err)
	}
	if got := membersOf(t, c, group); len(got) != 0 {
		t.Errorf("members after removing the last = %v, want none", got)
	}
}

// batchHolder is one kind of thing the permission batches act on.
type batchHolder struct {
	add    func(entries []teamspeak.PermissionEntry, opts teamspeak.PermissionBatchOptions) error
	remove func() error
	list   func() ([]teamspeak.PermissionEntry, error)
	name   string
	// entries are set by the test: two permissions, with the flags the holder's
	// command takes.
	entries []teamspeak.PermissionEntry
}

// batchHolders makes the scratch holders and returns one batchHolder for each
// of the five commands' targets.
//
//nolint:funlen // five holders, one after another
func batchHolders(t *testing.T, c *serverquery.Client, join, subscribe teamspeak.Permission) []batchHolder {
	t.Helper()
	ctx := adminCtx(t)
	name := "ts-go-pb-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	cid := scratchChannel(t, c, "ts-go-pb-")
	cgid, err := c.CreateChannelGroup(ctx, name, teamspeak.GroupRegular)
	if err != nil {
		t.Fatalf("CreateChannelGroup: %v", err)
	}
	cleanup(t, "the scratch channel group", func(ctx context.Context) error {
		return c.DeleteChannelGroup(ctx, cgid, teamspeak.GroupDeleteOptions{Force: true})
	})
	sgid, err := c.CreateServerGroup(ctx, name, teamspeak.GroupRegular)
	if err != nil {
		t.Fatalf("CreateServerGroup: %v", err)
	}
	cleanup(t, "the scratch server group", func(ctx context.Context) error {
		return c.DeleteServerGroup(ctx, sgid, teamspeak.GroupDeleteOptions{Force: true})
	})
	dbid := batchTargets(t, c, 1, "pb")[0].dbid

	plain := []teamspeak.PermissionEntry{{Permission: join, Value: 37}, {Permission: subscribe, Value: 38}}
	names := []teamspeak.Permission{join, subscribe}
	flag := teamspeak.PermissionBatchOptions{ContinueOnError: true}

	return []batchHolder{
		{
			name:    "channel",
			entries: plain,
			add: func(e []teamspeak.PermissionEntry, o teamspeak.PermissionBatchOptions) error {
				return c.AddChannelPermissions(ctx, cid, e, o)
			},
			remove: func() error { return c.DeleteChannelPermissions(ctx, cid, names) },
			list:   func() ([]teamspeak.PermissionEntry, error) { return c.ListChannelPermissions(ctx, cid) },
		},
		{
			name:    "channel group",
			entries: plain,
			add: func(e []teamspeak.PermissionEntry, o teamspeak.PermissionBatchOptions) error {
				return c.AddChannelGroupPermissions(ctx, cgid, e, o)
			},
			remove: func() error { return c.DeleteChannelGroupPermissions(ctx, cgid, names, flag) },
			list:   func() ([]teamspeak.PermissionEntry, error) { return c.ListChannelGroupPermissions(ctx, cgid) },
		},
		{
			name:    "client",
			entries: []teamspeak.PermissionEntry{{Permission: join, Value: 37, Skip: true}, {Permission: subscribe, Value: 38}},
			add: func(e []teamspeak.PermissionEntry, o teamspeak.PermissionBatchOptions) error {
				return c.AddClientPermissions(ctx, dbid, e, o)
			},
			remove: func() error { return c.DeleteClientPermissions(ctx, dbid, names) },
			list:   func() ([]teamspeak.PermissionEntry, error) { return c.ListClientPermissions(ctx, dbid) },
		},
		{
			name:    "channel client",
			entries: plain,
			add: func(e []teamspeak.PermissionEntry, o teamspeak.PermissionBatchOptions) error {
				return c.AddChannelClientPermissions(ctx, cid, dbid, e, o)
			},
			remove: func() error { return c.DeleteChannelClientPermissions(ctx, cid, dbid, names) },
			list: func() ([]teamspeak.PermissionEntry, error) {
				return c.ListChannelClientPermissions(ctx, cid, dbid)
			},
		},
		{
			name: "server group",
			entries: []teamspeak.PermissionEntry{
				{Permission: join, Value: 37, Negated: true},
				{Permission: subscribe, Value: 38, Skip: true},
			},
			add: func(e []teamspeak.PermissionEntry, o teamspeak.PermissionBatchOptions) error {
				return c.AddServerGroupPermissions(ctx, sgid, e, o)
			},
			remove: func() error { return c.DeleteServerGroupPermissions(ctx, sgid, names, flag) },
			list:   func() ([]teamspeak.PermissionEntry, error) { return c.ListServerGroupPermissions(ctx, sgid) },
		},
	}
}

// The permission batches on every kind of holder: two permissions set in one
// command and read back, one that the server does not know refuses the batch
// with nothing applied, and both are removed in one command.
func TestQueryMulti_PermissionBatches(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		join := teamspeak.PermissionByName(perm.ChannelJoinPower)
		subscribe := teamspeak.PermissionByName(perm.ChannelSubscribePower)
		refs := [2]teamspeak.PermissionInfo{
			permissionRef(ctx, t, c, perm.ChannelJoinPower),
			permissionRef(ctx, t, c, perm.ChannelSubscribePower),
		}
		for _, h := range batchHolders(t, c, join, subscribe) {
			t.Run(h.name, func(t *testing.T) { runPermissionBatch(t, h, join, subscribe, refs) })
		}
	})
}

func runPermissionBatch(
	t *testing.T, h batchHolder, join, subscribe teamspeak.Permission, refs [2]teamspeak.PermissionInfo,
) {
	t.Helper()
	// Whatever a failure leaves is removed.
	t.Cleanup(func() { _ = h.remove() })
	held := func() (*teamspeak.PermissionEntry, *teamspeak.PermissionEntry) {
		listed, err := h.list()
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("list: %v", err)
		}

		return permissionIn(listed, refs[0]), permissionIn(listed, refs[1])
	}
	flag := teamspeak.PermissionBatchOptions{ContinueOnError: true}
	bad := []teamspeak.PermissionEntry{
		{Permission: join, Value: 39},
		{Permission: teamspeak.PermissionByName("b_ts_go_no_such_permission"), Value: 1},
		{Permission: subscribe, Value: 39},
	}

	// The unknown permission refuses the batch, with the flag or without.
	for _, opts := range []teamspeak.PermissionBatchOptions{{}, flag} {
		err := h.add(bad, opts)
		wantCode(t, "a batch with an unknown permission", err, errcode.PermissionInvalidPermID)
		if first, second := held(); first != nil || second != nil {
			t.Fatalf("the refused batch (flag %v) applied %+v and %+v", opts.ContinueOnError, first, second)
		}
	}

	err := h.add(h.entries, flag)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	first, second := held()
	if first == nil || second == nil {
		t.Fatalf("after the add the holder has %+v and %+v, want both", first, second)
	}
	for i, got := range []*teamspeak.PermissionEntry{first, second} {
		want := h.entries[i]
		if got.Value != want.Value || got.Negated != want.Negated || got.Skip != want.Skip {
			t.Errorf("entry %d = %+v, want value %d negated %v skip %v", i, got, want.Value, want.Negated, want.Skip)
		}
	}

	err = h.remove()
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if first, second := held(); first != nil || second != nil {
		t.Errorf("after the removal the holder still has %+v and %+v", first, second)
	}
}

// Permissions set on every server group of a kind and removed again leave the
// groups as they were: what the group held is read first and put back.
func TestQueryMulti_ServerGroupPermissionsByType(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		groups, err := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
		if err != nil {
			t.Fatalf("ListServerGroups: %v", err)
		}
		i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool {
			return g.Type == teamspeak.GroupRegular && g.Name == "Server Admin"
		})
		if i < 0 {
			t.Skip("no regular Server Admin group to look at")
		}
		group := groups[i]
		poke := teamspeak.PermissionByName(perm.ClientPokePower)
		move := teamspeak.PermissionByName(perm.ClientMovePower)
		pokeBefore := permissionOf(t, c, group.ID, perm.ClientPokePower)
		moveBefore := permissionOf(t, c, group.ID, perm.ClientMovePower)

		err = c.AddServerGroupPermissionsByType(ctx, teamspeak.GroupAutoUpdateServerAdmin, []teamspeak.PermissionEntry{
			{Permission: poke, Value: 33, Skip: true},
			{Permission: move, Value: 34},
		})
		skipUnlessAllowed(t, err, "AddServerGroupPermissionsByType")
		defer func() {
			bg := context.Background()
			deleteErr := c.DeleteServerGroupPermissionsByType(bg, teamspeak.GroupAutoUpdateServerAdmin,
				[]teamspeak.Permission{poke, move})
			if deleteErr != nil {
				t.Errorf("DeleteServerGroupPermissionsByType: %v", deleteErr)
			}
			before := map[string]*teamspeak.PermissionEntry{
				perm.ClientPokePower: pokeBefore,
				perm.ClientMovePower: moveBefore,
			}
			for name, entry := range before {
				if entry == nil {
					continue
				}
				putBack := c.AddServerGroupPermission(bg, group.ID, teamspeak.PermissionByName(name), entry.Value,
					teamspeak.ServerGroupPermissionOptions{Negated: entry.Negated, Skip: entry.Skip})
				if putBack != nil {
					t.Errorf("putting back %s: %v", name, putBack)
				}
			}
		}()
		if err != nil {
			t.Fatalf("AddServerGroupPermissionsByType: %v", err)
		}
		pokeNow := permissionOf(t, c, group.ID, perm.ClientPokePower)
		moveNow := permissionOf(t, c, group.ID, perm.ClientMovePower)
		if pokeNow == nil || pokeNow.Value != 33 || !pokeNow.Skip || moveNow == nil || moveNow.Value != 34 {
			t.Errorf("after the add the group holds %+v and %+v, want 33 with skip and 34", pokeNow, moveNow)
		}
	})
}
