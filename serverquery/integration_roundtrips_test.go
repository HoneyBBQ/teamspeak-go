//go:build integration

package serverquery_test

// Integration tests for the administrative commands that act on a second
// client or on records of the server: bans, client edits, the client database,
// complaints, temporary passwords, the log, offline-message flags and the
// read-only getters. Each makes what it needs under names of its own and puts
// everything back; the instance-wide ones that cannot be put back are in
// integration_instance_reset_test.go.

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/prop"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// uniqueStamp is a short string no other run shares.
func uniqueStamp() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }

// databaseIDOf finds the database id of a connected voice client.
func databaseIDOf(ctx context.Context, t *testing.T, c *serverquery.Client, voice *client.Client) teamspeak.ClientDBID {
	t.Helper()
	name, err := c.GetClientNameByUID(ctx, voice.UID())
	if err != nil || name.DatabaseID == 0 {
		t.Fatalf("GetClientNameByUID(%s) = %+v, %v, want the client's entry", voice.UID(), name, err)
	}

	return name.DatabaseID
}

// listBansIfAny reads the ban list, which the servers refuse as an empty
// result when there is none.
func listBansIfAny(ctx context.Context, t *testing.T, c *serverquery.Client) []teamspeak.BanEntry {
	t.Helper()
	bans, err := c.ListBans(ctx, teamspeak.BanListOptions{})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		t.Fatalf("ListBans: %v", err)
	}

	return bans
}

// removeBansSince deletes every ban that is not in before, whatever made it,
// and says which it removed. A ban of a connected client names its address as
// well as its uid, and the voice clients of these tests share the runner's
// address, so a rule left behind refuses every voice connect after it.
func removeBansSince(
	ctx context.Context, c *serverquery.Client, before []teamspeak.BanEntry,
) ([]teamspeak.BanID, error) {
	bans, err := c.ListBans(ctx, teamspeak.BanListOptions{})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		return nil, err
	}
	var removed []teamspeak.BanID
	for _, b := range bans {
		if banByID(before, b.ID) != nil {
			continue
		}
		delErr := c.DeleteBan(ctx, b.ID)
		if delErr != nil && !errors.Is(delErr, errcode.BanInvalidID) {
			return removed, delErr
		}
		removed = append(removed, b.ID)
	}

	return removed, nil
}

// A connected client is banned from the query connection, which kicks it and
// records a ban for each thing the server can identify it by: measured on TS3
// 3.13.8 and TS6 beta13.1, one for its uid and one for its address, and none
// for a MyTeamSpeak id when it has none. The ids BanClient returns are the
// server's own answer, which TS6 sometimes leaves empty (once in about a
// hundred calls over SSH and WebQuery) though both bans are made, so the test
// finds what was made by comparing the list before and after, and removes all
// of it, also when an assertion fails.
//
//nolint:gocognit,funlen // one scenario, step by step
func TestQueryAdmin_BanClient(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		voice := voiceClient(t, "ts-go-ban-"+uniqueStamp()[:6])
		before := listBansIfAny(ctx, t, c)
		cleanup(t, "the bans of the banned client", func(ctx context.Context) error {
			_, err := removeBansSince(ctx, c, before)
			if err != nil {
				return err
			}
			left, err := c.ListBans(ctx, teamspeak.BanListOptions{})
			if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
				return err
			}
			if len(left) != len(before) {
				t.Errorf("the ban list has %d entries, want the %d it started with", len(left), len(before))
			}

			return nil
		})

		ids, err := c.BanClient(ctx, voice.ClientID(), teamspeak.BanClientOptions{Reason: "ts-go-it", Duration: time.Hour})
		skipUnlessAllowed(t, err, "BanClient")
		if err != nil {
			t.Fatalf("BanClient: %v", err)
		}

		all := listBansIfAny(ctx, t, c)
		var made []teamspeak.BanEntry
		for _, b := range all {
			if banByID(before, b.ID) == nil {
				made = append(made, b)
			}
		}
		if len(made) == 0 {
			t.Fatal("BanClient made no ban the list shows")
		}
		for _, b := range made {
			if b.Reason != "ts-go-it" || b.Duration != time.Hour {
				t.Errorf("ban %d = %+v, want the reason and the hour that were given", b.ID, b)
			}
		}
		for _, id := range ids {
			if !slices.ContainsFunc(made, func(b teamspeak.BanEntry) bool { return b.ID == id }) {
				t.Errorf("BanClient returned id %d, which is not one of the new bans %+v", id, made)
			}
		}
		if !slices.ContainsFunc(made, func(b teamspeak.BanEntry) bool { return b.UID == voice.UID() }) {
			t.Errorf("no new ban names the client's uid %s: %+v", voice.UID(), made)
		}
		if !slices.ContainsFunc(made, func(b teamspeak.BanEntry) bool { return b.IP != "" }) {
			t.Errorf("no new ban names the client's address: %+v", made)
		}

		removed, err := removeBansSince(ctx, c, before)
		if err != nil {
			t.Fatalf("deleting the new bans: %v", err)
		}
		if len(removed) != len(made) {
			t.Errorf("removed %d bans, want the %d that were made", len(removed), len(made))
		}
		after := listBansIfAny(ctx, t, c)
		for _, b := range made {
			if banByID(after, b.ID) != nil {
				t.Errorf("ban %d is still listed after DeleteBan", b.ID)
			}
		}
	})
}

// DeleteAllBans empties the list. It runs only against the throwaway server
// of the job: another test's ban would go with it, which is why each test
// removes its own bans before it ends.
func TestQueryAdmin_DeleteAllBans(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := uniqueStamp()
		for _, suffix := range []string{"a", "b"} {
			id, _, err := c.AddBan(ctx, teamspeak.BanOptions{Name: "ts-go-all-" + suffix + stamp, Reason: "ts-go-it"})
			skipUnlessAllowed(t, err, "AddBan")
			if err != nil {
				t.Fatalf("AddBan: %v", err)
			}
			cleanup(t, "ban "+suffix, func(ctx context.Context) error {
				err := c.DeleteBan(ctx, id)
				if errors.Is(err, errcode.BanInvalidID) {
					return nil
				}

				return err
			})
		}

		err := c.DeleteAllBans(ctx)
		if err != nil {
			t.Fatalf("DeleteAllBans: %v", err)
		}
		left, err := c.ListBans(ctx, teamspeak.BanListOptions{})
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListBans: %v", err)
		}
		if len(left) != 0 {
			t.Errorf("after DeleteAllBans the list = %+v, want none", left)
		}
	})
}

// A second client's description is edited and read back, and the client is
// made a talker in a channel where talking needs power it lacks.
func TestQueryAdmin_EditClient(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := uniqueStamp()
		voice := voiceClient(t, "ts-go-edit-"+stamp[:6])
		clid := voice.ClientID()

		description := "ts-go description " + stamp
		err := c.EditClient(ctx, clid, teamspeak.ClientEditOptions{Description: &description})
		if err != nil {
			t.Fatalf("EditClient description: %v", err)
		}
		props, err := c.GetClientProperties(ctx, clid)
		if err != nil || props["client_description"] != description {
			t.Errorf("client_description = %q, %v, want %q", props["client_description"], err, description)
		}

		// The channel asks for more talk power than a guest has, so the client
		// is muted there until it is made a talker.
		cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
			Name: "ts-go-talk-" + stamp, IsPermanent: new(true), NeededTalkPower: new(int32(75)),
		})
		if err != nil {
			t.Fatalf("CreateChannel: %v", err)
		}
		cleanup(t, "the talk channel", func(ctx context.Context) error {
			return deleteChannelsNamed(ctx, c, "ts-go-talk-"+stamp)
		})
		err = c.MoveClient(ctx, clid, cid, teamspeak.ClientMoveOptions{})
		if err != nil {
			t.Fatalf("MoveClient: %v", err)
		}

		talker := func() bool {
			listed, listErr := c.ListClients(ctx, teamspeak.ClientListOptions{Voice: true})
			if listErr != nil {
				t.Fatalf("ListClients: %v", listErr)
			}
			i := slices.IndexFunc(listed, func(e teamspeak.ClientEntry) bool { return e.ID == clid })
			if i < 0 {
				t.Fatalf("the voice client %d is not in the client list", clid)
			}

			return listed[i].IsTalker != nil && *listed[i].IsTalker
		}
		if talker() {
			t.Fatal("the client is a talker in a channel that needs talk power it lacks")
		}
		err = c.EditClient(ctx, clid, teamspeak.ClientEditOptions{IsTalker: new(true)})
		if err != nil {
			t.Fatalf("EditClient IsTalker: %v", err)
		}
		if !talker() {
			t.Error("the client is not a talker after EditClient IsTalker=true")
		}
		err = c.EditClient(ctx, clid, teamspeak.ClientEditOptions{IsTalker: new(false)})
		if err != nil {
			t.Fatalf("EditClient IsTalker=false: %v", err)
		}
		if talker() {
			t.Error("the client is still a talker after EditClient IsTalker=false")
		}
	})
}

// The client database: an entry is read, found, listed and paged, edited, and
// deleted once its client has gone. The server groups it belongs to are read
// by database id.
//
//nolint:gocognit,gocyclo,cyclop,funlen // one scenario, step by step
func TestQueryAdmin_ClientDatabase(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		nickname := "ts-go-db-" + uniqueStamp()[:6]
		dbid := scratchClientRecord(t, c, nickname)

		// The connection count and address are written a moment after the
		// client has gone, so they are waited for.
		var info teamspeak.ClientDatabaseEntry
		deadline := time.Now().Add(10 * time.Second)
		for {
			var err error
			info, err = c.GetClientDatabaseInfo(ctx, dbid)
			if err != nil {
				t.Fatalf("GetClientDatabaseInfo: %v", err)
			}
			if info.TotalConnections >= 1 && info.LastIP != "" || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if info.DatabaseID != dbid || info.Nickname != nickname || info.UID == "" || info.TotalConnections < 1 ||
			info.LastIP == "" || info.Created.IsZero() || info.LastConnected.IsZero() {
			t.Errorf("GetClientDatabaseInfo = %+v, want the entry of %q with its uid, address, times and a connection",
				info, nickname)
		}

		found, err := c.FindClientDatabase(ctx, nickname)
		if err != nil || !slices.Contains(found, dbid) {
			t.Errorf("FindClientDatabase(%q) = %v, %v, want %d", nickname, found, err, dbid)
		}
		none, err := c.FindClientDatabase(ctx, "ts-go-nobody-"+uniqueStamp())
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Errorf("a pattern that matches nothing: %v", err)
		}
		if len(none) != 0 {
			t.Errorf("a pattern that matches nothing found %v", none)
		}

		assertFindByUID(ctx, t, c, info.UID, nickname, dbid)

		assertClientDatabaseListing(ctx, t, c, dbid)

		groups, err := c.GetServerGroupsByClient(ctx, dbid)
		if err != nil {
			t.Fatalf("GetServerGroupsByClient: %v", err)
		}
		if len(groups) == 0 {
			t.Errorf("GetServerGroupsByClient = none, want at least the default group")
		}
		for _, g := range groups {
			if g.ID == 0 || g.Name == "" {
				t.Errorf("a server group reference with no id or name: %+v", g)
			}
		}

		description := "edited " + nickname
		err = c.EditClientDatabase(ctx, dbid, teamspeak.ClientDatabaseEditOptions{Description: &description})
		if err != nil {
			t.Fatalf("EditClientDatabase: %v", err)
		}
		info, err = c.GetClientDatabaseInfo(ctx, dbid)
		if err != nil || info.Description != description {
			t.Errorf("after EditClientDatabase the description = %q, %v, want %q", info.Description, err, description)
		}

		err = c.DeleteClientDatabase(ctx, dbid)
		if err != nil {
			t.Fatalf("DeleteClientDatabase: %v", err)
		}
		_, err = c.GetClientDatabaseInfo(ctx, dbid)
		if err == nil {
			t.Error("the deleted entry can still be read")
		}
		t.Logf("reading a deleted entry: %v", err)
	})
}

// assertClientDatabaseListing reads the entry back through the list, the page
// and the iterator.
func assertClientDatabaseListing(ctx context.Context, t *testing.T, c *serverquery.Client, dbid teamspeak.ClientDBID) {
	t.Helper()
	isEntry := func(e teamspeak.ClientDatabaseEntry) bool { return e.DatabaseID == dbid }

	all, err := c.ListClientDatabase(ctx, teamspeak.ClientDatabasePageOptions{})
	// The server caps a page (25 entries, measured), so on a database with
	// more entries the new one is not on the first page; the iterator below
	// is what has to find it.
	if err != nil || len(all) == 0 {
		t.Errorf("ListClientDatabase = %d entries, %v, want a page of entries", len(all), err)
	}
	page, err := c.ListClientDatabase(ctx, teamspeak.ClientDatabasePageOptions{Limit: 1})
	if err != nil || len(page) != 1 {
		t.Errorf("a page of one = %+v, %v", page, err)
	}
	second, err := c.ListClientDatabase(ctx, teamspeak.ClientDatabasePageOptions{Start: 1, Limit: 1})
	if err != nil || len(second) != 1 || len(all) < 2 || second[0].DatabaseID != all[1].DatabaseID {
		t.Errorf("the second page = %+v, %v, want the list's second entry", second, err)
	}

	// A page size below the number of entries makes the iterator step.
	seen := 0
	hit := false
	for e, iterErr := range c.IterateClientDatabase(ctx, teamspeak.PagingOptions{PageSize: 2}) {
		if iterErr != nil {
			t.Fatalf("IterateClientDatabase: %v", iterErr)
		}
		seen++
		hit = hit || isEntry(e)
	}
	if !hit || seen < len(all) {
		t.Errorf("IterateClientDatabase gave %d entries (found %t), a page of ListClientDatabase %d", seen, hit, len(all))
	}
}

// Complaints are filed, listed by target and in all, withdrawn one at a time,
// and cleared for a client.
//
//nolint:gocognit,gocyclo,cyclop,funlen // one scenario, step by step
func TestQueryAdmin_Complaints(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := uniqueStamp()
		// The server refuses a complaint against a client that is not connected
		// (512, measured on both generations), so the target stays online.
		voice := voiceClient(t, "ts-go-cmp-"+stamp[:6])
		dbid := databaseIDOf(ctx, t, c, voice)
		me, err := c.WhoAmI(ctx)
		if err != nil || me.DatabaseID == 0 {
			t.Fatalf("WhoAmI = %+v, %v, want a database id", me, err)
		}
		cleanup(t, "the complaints", func(ctx context.Context) error {
			delErr := c.DeleteAllComplaints(ctx, dbid)
			if errors.Is(delErr, errcode.DatabaseEmptyResult) {
				return nil
			}

			return delErr
		})

		message := "ts-go complaint " + stamp
		err = c.AddComplaint(ctx, dbid, message)
		skipUnlessAllowed(t, err, "AddComplaint")
		if err != nil {
			t.Fatalf("AddComplaint: %v", err)
		}
		listed, err := c.ListComplaints(ctx, teamspeak.ComplaintListOptions{TargetDatabaseID: dbid})
		if err != nil || len(listed) != 1 {
			t.Fatalf("ListComplaints = %+v, %v, want the one complaint", listed, err)
		}
		if got := listed[0]; got.Message != message || got.TargetDatabaseID != dbid || got.FromDatabaseID != me.DatabaseID ||
			got.TargetName == "" || got.Created.IsZero() {
			t.Errorf("the complaint = %+v, want %q from %d against %d", got, message, me.DatabaseID, dbid)
		}
		every, err := c.ListComplaints(ctx, teamspeak.ComplaintListOptions{})
		if err != nil || !slices.ContainsFunc(every, func(x teamspeak.Complaint) bool { return x.Message == message }) {
			t.Errorf("ListComplaints without a target = %+v, %v, want the complaint among them", every, err)
		}

		err = c.DeleteComplaint(ctx, dbid, me.DatabaseID)
		if err != nil {
			t.Fatalf("DeleteComplaint: %v", err)
		}
		gone, err := c.ListComplaints(ctx, teamspeak.ComplaintListOptions{TargetDatabaseID: dbid})
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListComplaints after the delete: %v", err)
		}
		if len(gone) != 0 {
			t.Errorf("after DeleteComplaint the list = %+v, want none", gone)
		}

		// A second complaint from the same client replaces the first, so one
		// is enough to show that all of a target's are cleared.
		err = c.AddComplaint(ctx, dbid, message+" again")
		if err != nil {
			t.Fatalf("AddComplaint again: %v", err)
		}
		err = c.DeleteAllComplaints(ctx, dbid)
		if err != nil {
			t.Fatalf("DeleteAllComplaints: %v", err)
		}
		gone, err = c.ListComplaints(ctx, teamspeak.ComplaintListOptions{TargetDatabaseID: dbid})
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListComplaints after DeleteAllComplaints: %v", err)
		}
		if len(gone) != 0 {
			t.Errorf("after DeleteAllComplaints the list = %+v, want none", gone)
		}
	})
}

// A temporary password is made, listed with what it was made with, and
// deleted.
func TestQueryAdmin_TempPasswords(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := uniqueStamp()
		password := "tsgotmp" + stamp
		cid := channelIDByName(t, c, "Alpha")

		err := c.AddTempPassword(ctx, teamspeak.TempPasswordOptions{
			Password: password, Description: "ts-go-it " + stamp, Duration: time.Hour, TargetChannelID: cid,
		})
		skipUnlessAllowed(t, err, "AddTempPassword")
		if err != nil {
			t.Fatalf("AddTempPassword: %v", err)
		}
		cleanup(t, "the temporary password", func(ctx context.Context) error {
			delErr := c.DeleteTempPassword(ctx, password)
			if errors.Is(delErr, errcode.DatabaseEmptyResult) {
				return nil
			}

			return delErr
		})

		byDescription := func(list []teamspeak.TempPassword) int {
			return slices.IndexFunc(list, func(p teamspeak.TempPassword) bool { return p.Description == "ts-go-it "+stamp })
		}
		listed, err := c.ListTempPasswords(ctx)
		if err != nil {
			t.Fatalf("ListTempPasswords: %v", err)
		}
		i := byDescription(listed)
		if i < 0 {
			t.Fatalf("ListTempPasswords = %+v, want the new one", listed)
		}
		got := listed[i]
		if got.TargetChannelID != cid || got.Ends.Sub(got.Starts) != time.Hour {
			t.Errorf("the listed password = %+v, want channel %d and an hour", got, cid)
		}

		err = c.DeleteTempPassword(ctx, password)
		if err != nil {
			t.Fatalf("DeleteTempPassword: %v", err)
		}
		after, err := c.ListTempPasswords(ctx)
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListTempPasswords after the delete: %v", err)
		}
		if byDescription(after) >= 0 {
			t.Errorf("after the delete the list = %+v, want it gone", after)
		}
	})
}

// A line written to the server log is read back from it.
func TestQueryAdmin_Log(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		line := "ts-go log line " + uniqueStamp()

		// TeamSpeak 6 drops a custom log line written soon after another one
		// (measured: kept 300 ms apart, dropped 100 ms apart, never logged
		// later), and the previous subtest's line is that recent.
		time.Sleep(time.Second)
		err := c.AddLog(ctx, teamspeak.LogLevelInfo, line)
		skipUnlessAllowed(t, err, "AddLog")
		if err != nil {
			t.Fatalf("AddLog: %v", err)
		}
		// A line is read back after the server has written it.
		var page teamspeak.LogPage
		deadline := time.Now().Add(10 * time.Second)
		for {
			page, err = c.ViewLog(ctx, teamspeak.LogViewOptions{Lines: 100, Reverse: true})
			if err != nil {
				t.Fatalf("ViewLog: %v", err)
			}
			if slices.ContainsFunc(page.Lines, func(l string) bool { return strings.Contains(l, line) }) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the newest %d log lines do not hold %q within 10s", len(page.Lines), line)
			}
			time.Sleep(200 * time.Millisecond)
		}
		// Read backwards from the end, a page that reaches the start of a short
		// log stops at position 0 (measured on TS6), so only the size is checked.
		if page.FileSize == 0 {
			t.Errorf("ViewLog = %+v, want a file size", page)
		}
	})
}

// An offline message is marked read and unread again through its flag, by the
// client it was sent to. The query connection's own uid is not one a client can
// write to (512), so the recipient is a voice client and the flag is set on its
// connection.
func TestQueryAdmin_MessageFlag(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		voice := voiceClient(t, "ts-go-flag-"+uniqueStamp()[:6])
		subject := "ts-go-it " + uniqueStamp()
		err := c.SendOfflineMessage(ctx, voice.UID(), subject, "flag me")
		if err != nil {
			t.Fatalf("SendOfflineMessage: %v", err)
		}

		flagOf := func(id teamspeak.MessageID) bool {
			inbox, listErr := voice.ListMessages(ctx, teamspeak.MessageListOptions{})
			if listErr != nil {
				t.Fatalf("ListMessages: %v", listErr)
			}
			i := slices.IndexFunc(inbox, func(m teamspeak.OfflineMessage) bool { return m.ID == id })
			if i < 0 {
				t.Fatalf("the message %d is gone from the inbox", id)
			}

			return inbox[i].IsRead
		}
		inbox, err := voice.ListMessages(ctx, teamspeak.MessageListOptions{})
		if err != nil {
			t.Fatalf("ListMessages: %v", err)
		}
		i := slices.IndexFunc(inbox, func(m teamspeak.OfflineMessage) bool { return m.Subject == subject })
		if i < 0 {
			t.Fatalf("the inbox = %+v, want %q", inbox, subject)
		}
		id := inbox[i].ID
		cleanup(t, "the message", func(ctx context.Context) error { return voice.DeleteMessage(ctx, id) })
		if inbox[i].IsRead {
			t.Fatal("a new message is already read")
		}

		for _, read := range []bool{true, false} {
			err = voice.UpdateMessageFlag(ctx, id, teamspeak.MessageFlags{Read: read})
			if err != nil {
				t.Fatalf("UpdateMessageFlag(read=%t): %v", read, err)
			}
			if got := flagOf(id); got != read {
				t.Errorf("after UpdateMessageFlag(read=%t) the message's IsRead = %t", read, got)
			}
		}
	})
}

// SetQueryLogin renames the login of the connection that sends it and
// replaces its password. The connections here are the fixture's serveradmin,
// whose credentials every other test uses, so it is not run: there is no way
// to put the password back.
func TestQueryAdmin_SetQueryLoginIsNotRun(t *testing.T) {
	t.Skip("SetQueryLogin replaces the password of the login it runs under, which here is the fixture's serveradmin")
}

// The server-wide getters answer with the numbers and addresses of a running
// server, and a name or a port leads back to its id.
//
//nolint:gocognit,gocyclo,cyclop // one scenario, step by step
func TestQueryAdmin_Getters(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)

		conn, err := c.GetConnectionInfo(ctx)
		if err != nil {
			t.Fatalf("GetConnectionInfo: %v", err)
		}
		if conn.PacketsReceived == 0 && conn.BytesReceived == 0 && conn.ConnectedTime == 0 {
			t.Errorf("GetConnectionInfo = %+v, want the counters of a server that has been used", conn)
		}

		host, err := c.GetHostInfo(ctx)
		if err != nil {
			t.Fatalf("GetHostInfo: %v", err)
		}
		if host[prop.HostTimestampUTC] == "" {
			t.Errorf("GetHostInfo = %v, want properties", host)
		}

		matches, err := c.FindChannels(ctx, "Alph")
		isAlpha := func(m teamspeak.ChannelMatch) bool { return m.Name == "Alpha" && m.ID != 0 }
		if err != nil || !slices.ContainsFunc(matches, isAlpha) {
			t.Errorf("FindChannels(Alph) = %+v, %v, want Alpha", matches, err)
		}

		info, err := c.GetServerInfo(ctx)
		if err != nil {
			t.Fatalf("GetServerInfo: %v", err)
		}
		port, err := strconv.ParseUint(info[prop.VirtualServerPort], 10, 16)
		if err != nil {
			t.Fatalf("the server's port %q: %v", info[prop.VirtualServerPort], err)
		}
		id, err := c.GetServerIDByPort(ctx, uint16(port))
		if err != nil || id != 1 {
			t.Errorf("GetServerIDByPort(%d) = %d, %v, want server 1", port, id, err)
		}
		_, err = c.GetServerIDByPort(ctx, 1)
		if err == nil {
			t.Error("GetServerIDByPort of a port nothing serves succeeded")
		}

		bindings, err := c.ListBindings(ctx, teamspeak.BindingListOptions{})
		if err != nil || len(bindings) == 0 {
			t.Fatalf("ListBindings = %+v, %v, want the addresses the server listens on", bindings, err)
		}
		for _, b := range bindings {
			if b.Subsystem == "" || b.IP == "" {
				t.Errorf("a binding with no subsystem or address: %+v", b)
			}
		}
		voice, err := c.ListBindings(ctx, teamspeak.BindingListOptions{Subsystem: "voice"})
		if err != nil || len(voice) == 0 {
			t.Errorf("ListBindings(voice) = %+v, %v", voice, err)
		}
	})
}

// An instance setting is changed, read back, and put back to what it was. The
// bandwidth limit is one nothing else here depends on.
func TestQueryAdmin_EditInstance(t *testing.T) {
	forEachTransport(t, 0, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		const key = prop.ServerInstanceMaxDownloadTotalBandwidth

		before, err := c.GetInstanceInfo(ctx)
		if err != nil {
			t.Fatalf("GetInstanceInfo: %v", err)
		}
		original, ok := before[key]
		if !ok {
			t.Fatalf("GetInstanceInfo has no %s: %v", key, before)
		}
		cleanup(t, "the instance setting", func(ctx context.Context) error {
			return c.EditInstance(ctx, teamspeak.Properties{key: original})
		})

		changed := "123456789"
		if original == changed {
			changed = "123456790"
		}
		err = c.EditInstance(ctx, teamspeak.Properties{key: changed})
		skipUnlessAllowed(t, err, "EditInstance")
		if err != nil {
			t.Fatalf("EditInstance: %v", err)
		}
		after, err := c.GetInstanceInfo(ctx)
		if err != nil || after[key] != changed {
			t.Errorf("after EditInstance %s = %q, %v, want %q", key, after[key], err, changed)
		}

		err = c.EditInstance(ctx, teamspeak.Properties{key: original})
		if err != nil {
			t.Fatalf("EditInstance back: %v", err)
		}
		restored, err := c.GetInstanceInfo(ctx)
		if err != nil || restored[key] != original {
			t.Errorf("after putting it back %s = %q, %v, want %q", key, restored[key], err, original)
		}
	})
}

// assertFindByUID checks what clientdbfind -uid matches, as measured on both
// servers: the whole uid ignoring case, % and _ as wildcards, and nothing for a
// fragment without one or for a nickname.
func assertFindByUID(ctx context.Context, t *testing.T, finder interface {
	FindClientDatabaseByUID(ctx context.Context, pattern string) ([]teamspeak.ClientDBID, error)
}, clientUID teamspeak.UID, nickname string, dbid teamspeak.ClientDBID,
) {
	t.Helper()
	uid := string(clientUID)
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{uid, true},
		{strings.ToLower(uid), true},
		{uid[:8] + "%", true},
		{uid[:len(uid)-2] + "_=", true},
		{uid[:8], false},
		{nickname, false},
		{"ts-go-nobody-" + uniqueStamp(), false},
	} {
		found, err := finder.FindClientDatabaseByUID(ctx, tc.pattern)
		if err != nil {
			t.Errorf("FindClientDatabaseByUID(%q): %v", tc.pattern, err)

			continue
		}
		if got := slices.Contains(found, dbid); got != tc.want {
			t.Errorf("FindClientDatabaseByUID(%q) = %v, contains %d: %v, want %v", tc.pattern, found, dbid, got, tc.want)
		}
	}
}

// The voice protocol answers clientdbfind -uid with the same ids.
func TestVoiceDatabaseByUID(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport != "ssh" {
			t.Skip("the voice variant runs once, beside the SSH connection")
		}
		voice := adminVoice(t, c)
		name, err := c.GetClientNameByUID(adminCtx(t), voice.UID())
		if err != nil || name.DatabaseID == 0 {
			t.Fatalf("GetClientNameByUID(%s) = %+v, %v, want the voice client's entry", voice.UID(), name, err)
		}
		assertFindByUID(adminCtx(t), t, voice, voice.UID(), "ts-go-voice-nobody", name.DatabaseID)
	})
}
