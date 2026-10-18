//go:build integration

package serverquery_test

// An integration test for the permission commands on every kind of holder:
// one permission is added to and deleted from a scratch channel, channel
// group, client and channel-client pair, and a scratch server group, and each
// step is read back through every reader the library has.

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// scratchClientRecord makes a client database entry of its own: a voice client
// with a fresh identity connects, and leaves again so that the entry can be
// deleted, which the server refuses for a client that is online. The entry is
// removed at the end of the test.
func scratchClientRecord(t *testing.T, c *serverquery.Client, nickname string) teamspeak.ClientDBID {
	t.Helper()
	ctx := adminCtx(t)
	voice := voiceClient(t, nickname)
	name, err := c.GetClientNameByUID(ctx, voice.UID())
	if err != nil || name.DatabaseID == 0 {
		t.Fatalf("GetClientNameByUID(%s) = %+v, %v, want the new entry", voice.UID(), name, err)
	}
	cleanup(t, "the client database entry", func(ctx context.Context) error {
		delErr := c.DeleteClientDatabase(ctx, name.DatabaseID)
		if errors.Is(delErr, errcode.ClientInvalidID) {
			// 512: no such client database entry; the test deleted it.
			return nil
		}

		return delErr
	})
	err = voice.Disconnect(ctx)
	if err != nil {
		t.Fatalf("the scratch client's Disconnect: %v", err)
	}
	// The server notices the departure a moment after the disconnect.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		online, findErr := c.FindClients(ctx, nickname)
		if findErr == nil && len(online) == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	return name.DatabaseID
}

// permissionHolder is one kind of thing a permission is set on: how to add and
// delete it, how to list it, and where FindPermission and GetPermissionOverview
// report it.
type permissionHolder struct {
	add    func(ctx context.Context, p teamspeak.Permission, value int32) error
	remove func(ctx context.Context, p teamspeak.Permission) error
	list   func(ctx context.Context) ([]teamspeak.PermissionEntry, error)
	// at says whether a location is this holder's.
	at     func(loc teamspeak.PermissionLocation) bool
	name   string
	target teamspeak.PermissionTarget
}

// permissionIn finds a permission in a list by its name or its id, whichever
// the list carries: a reader that gives names and one that gives ids both count.
func permissionIn(entries []teamspeak.PermissionEntry, ref teamspeak.PermissionInfo) *teamspeak.PermissionEntry {
	i := slices.IndexFunc(entries, func(e teamspeak.PermissionEntry) bool {
		return e.Permission.Name() == ref.Name || (e.Permission.Name() == "" && e.Permission.ID() == ref.ID)
	})
	if i < 0 {
		return nil
	}

	return &entries[i]
}

// One permission is set and deleted on a channel, a channel group, a client, a
// client in a channel and a server group, and each reader reports it.
//
//nolint:funlen // five holders, set up one after another
func TestQueryAdmin_PermissionRoundTrip(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := strconv.FormatInt(time.Now().UnixNano(), 36)

		cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: "ts-go-perm-" + stamp, IsPermanent: new(true)})
		if err != nil {
			t.Fatalf("CreateChannel: %v", err)
		}
		cleanup(t, "the scratch channel", func(ctx context.Context) error {
			return deleteChannelsNamed(ctx, c, "ts-go-perm-"+stamp)
		})
		cgid, err := c.CreateChannelGroup(ctx, "ts-go-perm-"+stamp, teamspeak.GroupRegular)
		if err != nil {
			t.Fatalf("CreateChannelGroup: %v", err)
		}
		cleanup(t, "the scratch channel group", func(ctx context.Context) error {
			return c.DeleteChannelGroup(ctx, cgid, teamspeak.GroupDeleteOptions{Force: true})
		})
		sgid, err := c.CreateServerGroup(ctx, "ts-go-perm-"+stamp, teamspeak.GroupRegular)
		if err != nil {
			t.Fatalf("CreateServerGroup: %v", err)
		}
		cleanup(t, "the scratch server group", func(ctx context.Context) error {
			return c.DeleteServerGroup(ctx, sgid, teamspeak.GroupDeleteOptions{Force: true})
		})
		dbid := scratchClientRecord(t, c, "ts-go-perm-"+stamp[len(stamp)-6:])

		// The overview lists what applies to the client, so the client is put in
		// the scratch group in the scratch channel for the group's entry to be
		// among them.
		err = c.SetClientChannelGroup(ctx, cgid, cid, dbid)
		if err != nil {
			t.Fatalf("SetClientChannelGroup: %v", err)
		}
		members, err := c.ListChannelGroupClients(ctx, teamspeak.ChannelGroupClientListOptions{ChannelID: cid})
		want := teamspeak.ChannelGroupMembership{ChannelID: cid, DatabaseID: dbid, GroupID: cgid}
		if err != nil || !slices.Contains(members, want) {
			t.Errorf("ListChannelGroupClients = %+v, %v, want %+v among them", members, err, want)
		}

		// A channel-level permission is valid on every holder.
		permission := teamspeak.PermissionByName(perm.ChannelJoinPower)
		const value = 37
		ref := permissionRef(ctx, t, c, perm.ChannelJoinPower)

		holders := []permissionHolder{
			{
				name: "channel",
				add: func(ctx context.Context, p teamspeak.Permission, v int32) error {
					return c.AddChannelPermission(ctx, cid, p, v)
				},
				remove: func(ctx context.Context, p teamspeak.Permission) error {
					return c.DeleteChannelPermission(ctx, cid, p)
				},
				list: func(ctx context.Context) ([]teamspeak.PermissionEntry, error) {
					return c.ListChannelPermissions(ctx, cid)
				},
				target: teamspeak.PermissionTargetChannel,
				at:     func(l teamspeak.PermissionLocation) bool { return l.ChannelID == cid },
			},
			{
				name: "channel group",
				add: func(ctx context.Context, p teamspeak.Permission, v int32) error {
					return c.AddChannelGroupPermission(ctx, cgid, p, v)
				},
				remove: func(ctx context.Context, p teamspeak.Permission) error {
					return c.DeleteChannelGroupPermission(ctx, cgid, p)
				},
				list: func(ctx context.Context) ([]teamspeak.PermissionEntry, error) {
					return c.ListChannelGroupPermissions(ctx, cgid)
				},
				target: teamspeak.PermissionTargetChannelGroup,
				at:     func(l teamspeak.PermissionLocation) bool { return l.ChannelGroupID == cgid },
			},
			{
				name: "client",
				add: func(ctx context.Context, p teamspeak.Permission, v int32) error {
					return c.AddClientPermission(ctx, dbid, p, v, teamspeak.ClientPermissionOptions{})
				},
				remove: func(ctx context.Context, p teamspeak.Permission) error {
					return c.DeleteClientPermission(ctx, dbid, p)
				},
				list: func(ctx context.Context) ([]teamspeak.PermissionEntry, error) {
					return c.ListClientPermissions(ctx, dbid)
				},
				target: teamspeak.PermissionTargetClient,
				at:     func(l teamspeak.PermissionLocation) bool { return l.DatabaseID == dbid && l.ChannelID == 0 },
			},
			{
				name: "channel client",
				add: func(ctx context.Context, p teamspeak.Permission, v int32) error {
					return c.AddChannelClientPermission(ctx, cid, dbid, p, v)
				},
				remove: func(ctx context.Context, p teamspeak.Permission) error {
					return c.DeleteChannelClientPermission(ctx, cid, dbid, p)
				},
				list: func(ctx context.Context) ([]teamspeak.PermissionEntry, error) {
					return c.ListChannelClientPermissions(ctx, cid, dbid)
				},
				target: teamspeak.PermissionTargetChannelClient,
				at:     func(l teamspeak.PermissionLocation) bool { return l.ChannelID == cid && l.DatabaseID == dbid },
			},
			{
				name: "server group",
				add: func(ctx context.Context, p teamspeak.Permission, v int32) error {
					return c.AddServerGroupPermission(ctx, sgid, p, v, teamspeak.ServerGroupPermissionOptions{})
				},
				remove: func(ctx context.Context, p teamspeak.Permission) error {
					return c.DeleteServerGroupPermission(ctx, sgid, p)
				},
				list: func(ctx context.Context) ([]teamspeak.PermissionEntry, error) {
					return c.ListServerGroupPermissions(ctx, sgid)
				},
				target: teamspeak.PermissionTargetServerGroup,
				at:     func(l teamspeak.PermissionLocation) bool { return l.ServerGroupID == sgid },
			},
		}

		for _, h := range holders {
			t.Run(h.name, func(t *testing.T) {
				assertPermissionRoundTrip(ctx, t, c, h, permission, ref, cid, dbid, value)
			})
		}
	})
}

// permissionRef reads a permission's catalogue entry, which every reader's
// answer has to agree with.
func permissionRef(ctx context.Context, t *testing.T, c *serverquery.Client, name string) teamspeak.PermissionInfo {
	t.Helper()
	all, err := c.ListPermissions(ctx)
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	i := slices.IndexFunc(all, func(p teamspeak.PermissionInfo) bool { return p.Name == name })
	if i < 0 || all[i].ID == 0 {
		t.Fatalf("ListPermissions has no %s with an id among its %d entries", name, len(all))
	}

	return all[i]
}

//nolint:gocyclo,cyclop,funlen // one holder, step by step
func assertPermissionRoundTrip(
	ctx context.Context, t *testing.T, c *serverquery.Client, h permissionHolder,
	permission teamspeak.Permission, ref teamspeak.PermissionInfo,
	cid teamspeak.ChannelID, dbid teamspeak.ClientDBID, value int32,
) {
	t.Helper()
	// Where the holder is reported: the overview is read for the scratch
	// client in the scratch channel, which every holder here applies to
	// except the server group, which the client is not in.
	overview := func() []teamspeak.PermissionOverviewEntry {
		entries, err := c.GetPermissionOverview(ctx, cid, dbid)
		if err != nil {
			t.Fatalf("GetPermissionOverview: %v", err)
		}

		return entries
	}
	located := func(loc teamspeak.PermissionLocation) bool {
		return loc.Permission == ref.ID && loc.Target == h.target && h.at(loc)
	}

	err := h.add(ctx, permission, value)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Deleting a permission the holder does not have is not an error, so the
	// cleanup can run after the test has deleted it.
	//nolint:contextcheck // the cleanup has a context of its own: the test's may be done by then
	cleanup(t, h.name+" permission", func(ctx context.Context) error { return h.remove(ctx, permission) })

	entries, err := h.list(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := permissionIn(entries, ref)
	switch {
	case got == nil:
		t.Fatalf("the list = %+v, want %s among it", entries, ref.Name)
	case got.Value != value || got.Negated || got.Skip:
		t.Errorf("the listed permission = %+v, want value %d, not negated, not skipped", *got, value)
	}

	found, err := c.FindPermission(ctx, permission)
	if err != nil || !slices.ContainsFunc(found, located) {
		t.Errorf("FindPermission = %+v, %v, want a %v location for the holder", found, err, h.target)
	}
	if h.target != teamspeak.PermissionTargetServerGroup {
		i := slices.IndexFunc(overview(), func(e teamspeak.PermissionOverviewEntry) bool {
			return located(e.PermissionLocation)
		})
		if i < 0 {
			t.Errorf("GetPermissionOverview has no %v entry for %s", h.target, ref.Name)
		} else if got := overview()[i].Value; got != value {
			t.Errorf("the overview's value = %d, want %d", got, value)
		}
	}

	err = h.remove(ctx, permission)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	entries, err = h.list(ctx)
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		// A holder with none left answers with an empty result.
		t.Fatalf("list after the delete: %v", err)
	}
	if permissionIn(entries, ref) != nil {
		t.Errorf("after the delete the list = %+v, want %s gone", entries, ref.Name)
	}
	found, err = c.FindPermission(ctx, permission)
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		t.Fatalf("FindPermission after the delete: %v", err)
	}
	if slices.ContainsFunc(found, located) {
		t.Errorf("after the delete FindPermission still reports %+v", found)
	}
	if h.target != teamspeak.PermissionTargetServerGroup &&
		slices.ContainsFunc(overview(), func(e teamspeak.PermissionOverviewEntry) bool {
			return located(e.PermissionLocation)
		}) {
		t.Error("after the delete GetPermissionOverview still reports the holder")
	}
}
