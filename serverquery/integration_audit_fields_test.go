//go:build integration

package serverquery_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/notify"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

func stamp() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }

// What the database lookups, whoami and serverlist carry beyond what they
// used to be read for.
func TestQueryAdmin_LookupFields(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		voice := voiceClient(t, "audit-"+stamp())
		dbid, err := c.GetClientDBIDByUID(ctx, voice.UID())
		if err != nil {
			t.Fatalf("GetClientDBIDByUID: %v", err)
		}

		info, err := c.GetClientDatabaseInfo(ctx, dbid)
		if err != nil {
			t.Fatalf("GetClientDatabaseInfo: %v", err)
		}
		t.Logf("%s: dbinfo avatar=%q total up/down=%v/%v month up/down=%v/%v", transport, info.AvatarHash,
			info.TotalBytesUploaded, info.TotalBytesDownloaded, info.MonthBytesUploaded, info.MonthBytesDownloaded)
		if info.TotalBytesUploaded == nil || info.TotalBytesDownloaded == nil ||
			info.MonthBytesUploaded == nil || info.MonthBytesDownloaded == nil {
			t.Errorf("clientdbinfo left a byte count unset: %+v", info)
		}

		name, err := c.GetClientNameByDBID(ctx, dbid)
		if err != nil || name.UID != voice.UID() {
			t.Errorf("GetClientNameByDBID = %+v, %v, want uid %s", name, err, voice.UID())
		}
		lookup, err := c.GetClientUIDInfoByID(ctx, voice.ClientID())
		if err != nil || lookup.UID != voice.UID() || lookup.Nickname == "" || lookup.ClientID != voice.ClientID() {
			t.Errorf("GetClientUIDInfoByID = %+v, %v", lookup, err)
		}

		who, err := c.WhoAmI(ctx)
		if err != nil {
			t.Fatalf("WhoAmI: %v", err)
		}
		servers, err := c.ListServers(ctx, teamspeak.ServerListOptions{UID: true})
		if err != nil || len(servers) == 0 {
			t.Fatalf("ListServers = %v, %v", servers, err)
		}
		t.Logf("%s: whoami uuid=%q origin=%d; serverlist uuid=%q guest channels=%v homebase=%v weblist=%v", transport,
			who.ServerUUID, who.OriginServerID, servers[0].UUID, servers[0].GuestCanCreateChannels,
			servers[0].GuestCanCreateHomebase, servers[0].WeblistEnabled)
		isTS6 := family == teamspeak.ServerFamilyTS6
		if isTS6 != (who.ServerUUID != "") || isTS6 != (servers[0].UUID != "") {
			t.Errorf("uuid on %v: whoami %q, serverlist %q", family, who.ServerUUID, servers[0].UUID)
		}
		if isTS6 != (servers[0].GuestCanCreateChannels != nil) || isTS6 != (servers[0].WeblistEnabled != nil) {
			t.Errorf("the TeamSpeak 6 server fields on %v: %+v", family, servers[0])
		}
	})
}

// The query account name shows in the database list.
func TestQueryAdmin_DatabaseListLoginName(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		voice := voiceClient(t, "audit-"+stamp())
		dbid, err := c.GetClientDBIDByUID(ctx, voice.UID())
		if err != nil {
			t.Fatalf("GetClientDBIDByUID: %v", err)
		}
		login, err := c.AddQueryLogin(ctx, "tsgoaud"+stamp(), teamspeak.QueryLoginOptions{DatabaseID: dbid})
		skipUnlessAllowed(t, err, "AddQueryLogin")
		if err != nil {
			t.Fatalf("AddQueryLogin: %v", err)
		}
		cleanup(t, "the query login", func(ctx context.Context) error { return c.DeleteQueryLogin(ctx, dbid) })
		found := false
		for entry, err := range c.IterateClientDatabase(ctx, teamspeak.PagingOptions{}) {
			if err != nil {
				t.Fatalf("IterateClientDatabase: %v", err)
			}
			if entry.DatabaseID == dbid {
				found = true
				if entry.LoginName != login.Name {
					t.Errorf("LoginName = %q, want %q", entry.LoginName, login.Name)
				}
			}
		}
		if !found {
			t.Errorf("the client is not in the database list")
		}
	})
}

// An occupied channel reports no EmptyFor; an empty one counts up. The file
// fields come with channelinfo.
func TestQueryAdmin_ChannelEmptyForAndFiles(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
			Name: "ts-go-empty-" + stamp(), IsSemiPermanent: new(true),
		})
		skipUnlessAllowed(t, err, "CreateChannel")
		if err != nil {
			t.Fatal(err)
		}
		cleanup(t, "channel", func(ctx context.Context) error {
			return c.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		})
		time.Sleep(2 * time.Second)

		byID := func() teamspeak.Channel {
			t.Helper()
			channels, listErr := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
			if listErr != nil {
				t.Fatal(listErr)
			}
			for _, ch := range channels {
				if ch.ID == cid {
					return ch
				}
			}
			t.Fatalf("channel %d is not listed", cid)

			return teamspeak.Channel{}
		}
		listed := byID()
		if listed.EmptyFor == nil || *listed.EmptyFor < 2*time.Second || *listed.EmptyFor > time.Minute {
			t.Errorf("an empty channel's EmptyFor = %v, want a few seconds", listed.EmptyFor)
		}
		info, err := c.GetChannelInfo(ctx, cid)
		if err != nil {
			t.Fatal(err)
		}
		if info.EmptyFor == nil || info.FilePath == "" {
			t.Errorf("channelinfo EmptyFor = %v, FilePath = %q", info.EmptyFor, info.FilePath)
		}
		t.Logf("%s: empty for %v; file path %q; storage quota %v", transport, info.EmptyFor, info.FilePath, info.StorageQuota)
		if (family == teamspeak.ServerFamilyTS6) != (info.StorageQuota != nil) {
			t.Errorf("StorageQuota = %v on %v", info.StorageQuota, family)
		}

		voice := voiceClient(t, "audit-"+stamp())
		err = c.MoveClient(ctx, voice.ClientID(), cid, teamspeak.ClientMoveOptions{})
		if err != nil {
			t.Fatalf("MoveClient: %v", err)
		}
		if got := byID(); got.EmptyFor != nil || got.TotalClients == nil || *got.TotalClients != 1 {
			t.Errorf("an occupied channel: EmptyFor = %v, TotalClients = %v", got.EmptyFor, got.TotalClients)
		}
		occupied, err := c.GetChannelInfo(ctx, cid)
		if err != nil || occupied.EmptyFor != nil {
			t.Errorf("an occupied channel's channelinfo EmptyFor = %v, %v", occupied.EmptyFor, err)
		}
	})
}

// A temporary password's target channel password comes back in the list.
func TestQueryAdmin_TempPasswordTargetChannelPassword(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		pw := "ts-go-" + stamp()
		err := c.AddTempPassword(ctx, teamspeak.TempPasswordOptions{
			Password: pw, Description: "ts-go-it", Duration: time.Hour, TargetChannelID: 1, TargetChannelPassword: "chanpw",
		})
		skipUnlessAllowed(t, err, "AddTempPassword")
		if err != nil {
			t.Fatal(err)
		}
		cleanup(t, "temp password", func(ctx context.Context) error { return c.DeleteTempPassword(ctx, pw) })
		list, err := c.ListTempPasswords(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range list {
			if p.Password == pw {
				if p.TargetChannelPassword == "" {
					t.Errorf("TargetChannelPassword is empty: %+v", p)
				}

				return
			}
		}
		t.Errorf("the new password is not listed")
	})
}

// The query client's enter, move and leave events name the channels, over the
// transports that deliver events.
func TestQueryAdmin_EnterMoveLeaveChannels(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		if transport == "web" {
			t.Skip("WebQuery delivers no events")
		}
		ctx := adminCtx(t)
		enter := make(chan teamspeak.ClientEnterEvent, 8)
		moved := make(chan teamspeak.ClientMovedEvent, 8)
		left := make(chan teamspeak.ClientLeaveEvent, 8)
		c.OnClientEnter(func(e teamspeak.ClientEnterEvent) { enter <- e })
		c.OnClientMoved(func(e teamspeak.ClientMovedEvent) { moved <- e })
		c.OnClientLeave(func(e teamspeak.ClientLeaveEvent) { left <- e })

		cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
			Name: "ts-go-move-" + stamp(), IsSemiPermanent: new(true),
		})
		skipUnlessAllowed(t, err, "CreateChannel")
		if err != nil {
			t.Fatal(err)
		}
		cleanup(t, "channel", func(ctx context.Context) error {
			return c.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		})

		voice := voiceClient(t, "audit-"+stamp())
		first := awaitEvent(t, enter, "enter")
		t.Logf("%s: enter from %d reason %v in %d", transport, first.FromChannelID, first.Reason, first.ChannelID)
		if first.Reason != teamspeak.ReasonNone || first.FromChannelID != 0 {
			t.Errorf("a connect: from %d, reason %v", first.FromChannelID, first.Reason)
		}
		original := first.ChannelID

		err = c.MoveClient(ctx, voice.ClientID(), cid, teamspeak.ClientMoveOptions{})
		if err != nil {
			t.Fatalf("MoveClient: %v", err)
		}
		move := awaitEvent(t, moved, "move")
		t.Logf("%s: move from %d to %d", transport, move.FromChannelID, move.TargetChannelID)
		wantFrom := original
		if family == teamspeak.ServerFamilyTS3 {
			// TeamSpeak 3 names no origin on a move.
			wantFrom = 0
		}
		if move.TargetChannelID != cid || move.FromChannelID != wantFrom {
			t.Errorf("move = from %d to %d, want from %d to %d", move.FromChannelID, move.TargetChannelID, wantFrom, cid)
		}

		_ = voice.Disconnect(ctx)
		leave := awaitEvent(t, left, "leave")
		t.Logf("%s: leave from %d to %d reason %v", transport, leave.FromChannelID, leave.TargetChannelID, leave.Reason)
		if leave.FromChannelID != cid || leave.TargetChannelID != 0 || leave.Reason != teamspeak.ReasonDisconnect {
			t.Errorf("leave = %+v, want from %d to 0, a disconnect", leave, cid)
		}
	})
}

func awaitEvent[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s event", what)

		var zero T

		return zero
	}
}

// notifybanupdate reaches a query client registered for the bans category:
// the whole rule on an add, the id alone on a delete.
func TestQueryAdmin_BanUpdateNotification(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		if transport == "web" {
			t.Skip("WebQuery delivers no events")
		}
		if family != teamspeak.ServerFamilyTS6 {
			t.Skip("the bans category is TeamSpeak 6 only")
		}
		ctx := adminCtx(t)
		got := make(chan teamspeak.NotificationEvent, 16)
		c.OnNotification(func(n teamspeak.NotificationEvent) {
			if n.Name == notify.BanUpdate {
				got <- n
			}
		})
		err := c.RegisterNotifications(ctx, serverquery.CategoryBans, serverquery.NotificationOptions{})
		skipUnlessAllowed(t, err, "RegisterNotifications")
		if err != nil {
			t.Fatal(err)
		}

		id, _, err := c.AddBan(ctx, teamspeak.BanOptions{Name: "ts-go-ban-" + stamp(), Reason: "ts-go-it"})
		if err != nil {
			t.Fatalf("AddBan: %v", err)
		}
		cleanup(t, "ban", func(ctx context.Context) error {
			deleteErr := c.DeleteBan(ctx, id)
			if deleteErr != nil && serverCode(deleteErr) != 0 {
				return nil
			}

			return deleteErr
		})
		added := <-withinDeadline(t, got)
		if added.Name != notify.BanUpdate || added.Params["op"] != "add" || added.Params["banid"] != strconv.Itoa(int(id)) ||
			added.Params["enforcements"] != "0" {
			t.Errorf("add = %+v", added)
		}
		err = c.DeleteBan(ctx, id)
		if err != nil {
			t.Fatalf("DeleteBan: %v", err)
		}
		deleted := <-withinDeadline(t, got)
		if deleted.Params["op"] != "del" || deleted.Params["banid"] != strconv.Itoa(int(id)) || len(deleted.Params) != 2 {
			t.Errorf("delete = %+v", deleted)
		}
		t.Logf("%s: ban add carries %d keys, delete %v", transport, len(added.Params), deleted.Params)
	})
}

func withinDeadline[T any](t *testing.T, ch <-chan T) <-chan T {
	t.Helper()
	out := make(chan T, 1)
	go func() {
		select {
		case v := <-ch:
			out <- v
		case <-time.After(10 * time.Second):
			t.Error("the notification never arrived")
			var zero T
			out <- zero
		}
	}()

	return out
}

// A client redeeming a privilege key is heard, by a query client that named the
// tokenused category, as a notification carrying the key and who used it.
func TestQueryAdmin_TokenUsedNotification(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport == "web" {
			t.Skip("WebQuery delivers no events")
		}
		ctx := adminCtx(t)
		got := make(chan teamspeak.NotificationEvent, 4)
		c.OnNotification(func(n teamspeak.NotificationEvent) {
			if n.Name == notify.TokenUsed {
				got <- n
			}
		})
		err := c.RegisterNotifications(ctx, serverquery.CategoryTokenUsed, serverquery.NotificationOptions{})
		if err != nil {
			t.Fatalf("registering tokenused: %v", err)
		}
		token, err := c.AddPrivilegeKey(ctx, teamspeak.PrivilegeKeyOptions{
			ServerGroupID: groupToRedeem(ctx, t, c), Description: "ts-go-it tokenused",
		})
		skipUnlessAllowed(t, err, "AddPrivilegeKey")
		if err != nil {
			t.Fatalf("AddPrivilegeKey: %v", err)
		}
		cleanup(t, "the privilege key", func(ctx context.Context) error {
			deleteErr := c.DeletePrivilegeKey(ctx, token)
			if deleteErr != nil && serverCode(deleteErr) != 0 {
				return nil
			}

			return deleteErr
		})

		voice := voiceClient(t, "audit-"+stamp())
		err = voice.UsePrivilegeKey(ctx, token)
		if err != nil {
			t.Fatalf("UsePrivilegeKey: %v", err)
		}
		n := awaitEvent(t, got, "tokenused")
		if n.Params["token"] != token || n.Params["cluid"] != string(voice.UID()) {
			t.Errorf("notification = %+v", n.Params)
		}
	})
}
