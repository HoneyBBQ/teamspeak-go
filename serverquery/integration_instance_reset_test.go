//go:build integration

package serverquery_test

// An integration test for the one administrative command that cannot be put
// back: ResetPermissions. It is switched on with the other destructive
// instance tests, and sorts ahead of integration_instance_test.go so that it
// runs before StopInstance ends the server.

import (
	"context"
	"errors"
	"slices"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// resetDone is set by the first transport that resets, so only one does.
var resetDone bool

// Every permission the server holds goes back to its default, which takes a
// group the test made and the permission the test gave it, and a new
// administrator privilege key is made. What the fixture granted the default
// group goes too, so no test that needs it can run after this one.
//
//nolint:funlen // one reset, step by step
func TestInstanceResetPermissions(t *testing.T) {
	allowDestructive(t, "TEAMSPEAK_QUERY_DESTRUCTIVE")
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport == "web" || resetDone {
			t.Skip("one session transport is enough: the permissions are gone after the first run")
		}
		resetDone = true
		ctx := adminCtx(t)
		group, err := c.CreateServerGroup(ctx, "ts-go-reset-"+uniqueStamp(), teamspeak.GroupRegular)
		if err != nil {
			t.Fatalf("CreateServerGroup: %v", err)
		}
		cleanup(t, "the scratch group", func(ctx context.Context) error {
			delErr := c.DeleteServerGroup(ctx, group, teamspeak.GroupDeleteOptions{Force: true})
			if errors.Is(delErr, errcode.PermissionInvalidGroupID) {
				return nil
			}

			return delErr
		})
		err = c.AddServerGroupPermission(ctx, group, teamspeak.PermissionByName(perm.ChannelJoinPower), 41,
			teamspeak.ServerGroupPermissionOptions{})
		if err != nil {
			t.Fatalf("AddServerGroupPermission: %v", err)
		}
		keysBefore, err := c.ListPrivilegeKeys(ctx)
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListPrivilegeKeys: %v", err)
		}

		err = c.ResetPermissions(ctx)
		if err != nil {
			t.Fatalf("ResetPermissions: %v", err)
		}

		// The reset drops this connection's selection of the server, as a
		// snapshot deploy does.
		err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{})
		if err != nil {
			t.Fatalf("Use after the reset: %v", err)
		}
		groups, err := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
		if err != nil {
			t.Fatalf("ListServerGroups after the reset: %v", err)
		}
		if slices.ContainsFunc(groups, func(g teamspeak.ServerGroup) bool { return g.ID == group }) {
			t.Errorf("the scratch group %d survived ResetPermissions", group)
		}
		keysAfter, err := c.ListPrivilegeKeys(ctx)
		if err != nil {
			t.Fatalf("ListPrivilegeKeys after the reset: %v", err)
		}
		// The reset makes a new administrator key and the count stays one on
		// both generations (measured), so the keys are told apart by token.
		tokens := func(keys []teamspeak.PrivilegeKey) []string {
			out := make([]string, 0, len(keys))
			for _, k := range keys {
				out = append(out, k.Token)
			}
			slices.Sort(out)

			return out
		}
		if len(keysAfter) == 0 || slices.Equal(tokens(keysBefore), tokens(keysAfter)) {
			t.Errorf("privilege keys %v before and %v after ResetPermissions, want a new administrator key",
				tokens(keysBefore), tokens(keysAfter))
		}
	})
}
