//go:build integration

package serverquery_test

// Integration tests for the administrative commands, over each query
// transport the environment provides (see integration_test.go). They create
// what they need under names of their own and remove it again, and none of
// them stops, deletes or restores anything: the instance-level commands that
// do are in integration_instance_test.go, behind a switch of their own.

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/livetest"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
	"github.com/honeybbq/teamspeak-go/versions"
)

// adminBody is a test that runs on one open query connection.
type adminBody func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string)

// forEachTransport runs body on each query transport the environment
// provides, as a subtest named for it, connected to server (0 for the
// instance, with none selected). A transport the environment does not provide
// shows as a skipped subtest, so a run that exercised one of three says so.
func forEachTransport(t *testing.T, server teamspeak.ServerID, body adminBody) {
	t.Helper()

	run := func(name string, dialer func(t *testing.T) (serverquery.Dialer, []serverquery.Option, account)) {
		t.Run(name, func(t *testing.T) {
			d, opts, _ := dialer(t)
			waitForOtherSuites()
			if server != 0 {
				opts = append(opts, serverquery.WithServer(server))
			} else {
				// No server is selected, so there is nothing to register the
				// default notifications on: the server refuses that with 1024.
				opts = append(opts, serverquery.WithoutEvents())
			}
			c, err := serverquery.New(d, opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			open(t, c)
			body(t, c, c.ServerFamily(), name)
		})
	}

	run("tcp", tcpDialer)
	run("ssh", sshDialer)
	run("web", webDialer)
}

// account is the query account a dialer's connection is logged in as, which a
// test logs in as again by hand.
type account struct{ name, password string }

func tcpDialer(t *testing.T) (serverquery.Dialer, []serverquery.Option, account) {
	t.Helper()
	addr, login, password := tcpVars(t)

	return serverquery.TCPLogin(addr, login, password), nil, account{login, password}
}

func sshDialer(t *testing.T) (serverquery.Dialer, []serverquery.Option, account) {
	t.Helper()
	addr, user, password := sshVars(t)
	check, err := serverquery.KnownHosts(livetest.KnownHostsFor(t, addr))
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}

	return serverquery.SSHWith(addr, user, password, serverquery.SSHOptions{HostKeyCheck: check}), nil,
		account{user, password}
}

func webDialer(t *testing.T) (serverquery.Dialer, []serverquery.Option, account) {
	t.Helper()
	base, apiKey := webVars(t)

	return serverquery.Web(base, apiKey), nil, account{}
}

func adminCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// cleanup runs fn at the end of the test with a context of its own: the
// test's may be done by then.
func cleanup(t *testing.T, what string, fn func(ctx context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := fn(ctx)
		if err != nil {
			t.Errorf("cleaning up %s: %v", what, err)
		}
	})
}

// serverCode reports the code of a refusal from the server, or 0.
func serverCode(err error) uint32 {
	serverErr, ok := errors.AsType[*teamspeak.ServerError](err)
	if !ok {
		return 0
	}

	return uint32(serverErr.Code)
}

// skipUnlessAllowed skips a test the server's permissions or version do not
// let run, saying why: a silent pass is how a command stays untested.
func skipUnlessAllowed(t *testing.T, err error, what string) {
	t.Helper()
	if errors.Is(err, errcode.PermissionsClientInsufficient) || errors.Is(err, errcode.CommandNotFound) ||
		errors.Is(err, errcode.NotImplemented) {
		t.Skipf("%s: %v", what, err)
	}
}

// voiceClient connects a voice client with an identity of its own, skipping
// when no voice address is set, and disconnects it at the end of the test.
func voiceClient(t *testing.T, nickname string) *client.Client {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set, so no voice client can connect")
	}
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	options := []client.Option{client.WithVersion(versions.Windows_3_6_2_1695203293)}
	if password := os.Getenv("TEAMSPEAK_SERVER_PASSWORD"); password != "" {
		options = append(options, client.WithServerPassword(password))
	}
	if channel := os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"); channel != "" {
		options = append(options, client.WithDefaultChannel(channel))
	}
	voice, err := client.New(id, addr, nickname, options...)
	if err != nil {
		t.Fatalf("voice client New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	err = voice.Connect(ctx)
	if err != nil {
		t.Fatalf("voice client Connect: %v", err)
	}
	t.Cleanup(func() { _ = voice.Disconnect(context.Background()) })

	return voice
}

// API keys are made, listed, paged and deleted, on every transport; the key
// itself comes back once, from the add.
func TestQueryAdmin_APIKeys(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		day := 24 * time.Hour
		read, err := c.AddAPIKey(ctx, teamspeak.APIKeyOptions{Scope: teamspeak.APIKeyScopeRead, Lifetime: &day})
		if err != nil {
			t.Fatalf("AddAPIKey: %v", err)
		}
		cleanup(t, "the read key", func(ctx context.Context) error { return deleteAPIKeyIfThere(ctx, c, read.ID) })
		if read.Key == "" || read.ID == 0 || read.Scope != teamspeak.APIKeyScopeRead || read.Unlimited {
			t.Errorf("the new key = %+v, want a key with its value, id and read scope that expires", read)
		}
		if read.TimeLeft <= 0 || read.TimeLeft > day || !read.Expires.After(read.Created) {
			t.Errorf("the new key lasts %v until %v, want under a day", read.TimeLeft, read.Expires)
		}

		never := time.Duration(0)
		forever, err := c.AddAPIKey(ctx, teamspeak.APIKeyOptions{Scope: teamspeak.APIKeyScopeWrite, Lifetime: &never})
		if err != nil {
			t.Fatalf("AddAPIKey without expiry: %v", err)
		}
		cleanup(t, "the unlimited key", func(ctx context.Context) error { return deleteAPIKeyIfThere(ctx, c, forever.ID) })
		if !forever.Unlimited || !forever.Expires.IsZero() || forever.TimeLeft != 0 {
			t.Errorf("the unlimited key = %+v, want one that never expires", forever)
		}

		assertAPIKeyListing(ctx, t, c, read, forever)
		assertAPIKeyDeletion(ctx, t, c, read.ID)
	})
}

// deleteAPIKeyIfThere deletes a key the test may already have deleted: the
// server's 5123 says the id names none.
func deleteAPIKeyIfThere(ctx context.Context, c *serverquery.Client, id teamspeak.APIKeyID) error {
	err := c.DeleteAPIKey(ctx, id)
	if serverCode(err) == 5123 {
		return nil
	}

	return err
}

func apiKeyByID(keys []teamspeak.APIKey, id teamspeak.APIKeyID) *teamspeak.APIKey {
	i := slices.IndexFunc(keys, func(k teamspeak.APIKey) bool { return k.ID == id })
	if i < 0 {
		return nil
	}

	return &keys[i]
}

func assertAPIKeyListing(
	ctx context.Context, t *testing.T, c *serverquery.Client, read, forever teamspeak.APIKeyCreated,
) {
	t.Helper()
	listed, err := c.ListAPIKeys(ctx, teamspeak.APIKeyListOptions{})
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	got := apiKeyByID(listed, read.ID)
	if got == nil || got.Scope != teamspeak.APIKeyScopeRead {
		t.Errorf("the listed key = %+v, want the new key", got)
	} else if got.OwnerDatabaseID != read.OwnerDatabaseID {
		t.Errorf("the listed key's owner = %d, want %d", got.OwnerDatabaseID, read.OwnerDatabaseID)
	}
	if listedForever := apiKeyByID(listed, forever.ID); listedForever == nil || !listedForever.Unlimited {
		t.Errorf("the listed unlimited key = %+v", listedForever)
	}

	page, err := c.ListAPIKeys(ctx, teamspeak.APIKeyListOptions{Limit: 1})
	if err != nil || len(page) != 1 {
		t.Errorf("a page of one = %v, %v", page, err)
	}
	all, err := c.ListAPIKeys(ctx, teamspeak.APIKeyListOptions{AllOwners: true})
	if err != nil || apiKeyByID(all, read.ID) == nil {
		t.Errorf("every owner's keys = %v, %v, want the new key among them", all, err)
	}
}

func assertAPIKeyDeletion(ctx context.Context, t *testing.T, c *serverquery.Client, id teamspeak.APIKeyID) {
	t.Helper()
	err := c.DeleteAPIKey(ctx, id)
	if err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	after, err := c.ListAPIKeys(ctx, teamspeak.APIKeyListOptions{})
	if err != nil || apiKeyByID(after, id) != nil {
		t.Errorf("after the delete the list = %v, %v, want the key gone", after, err)
	}
	// 5123: the id names no key. Deleting it again is the check that the first
	// delete did what it said.
	if code := serverCode(c.DeleteAPIKey(ctx, id)); code != 5123 {
		t.Errorf("deleting a deleted key: code %d, want 5123", code)
	}
}

// A client's custom properties are set, read back, searched and deleted.
func TestQueryAdmin_CustomProperties(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		me, err := c.WhoAmI(ctx)
		if err != nil || me.DatabaseID == 0 {
			t.Skipf("no database id to hang a property on: %+v, %v", me, err)
		}
		ident := "ts_go_it_" + strconv.FormatInt(time.Now().UnixNano(), 36)
		cleanup(t, "the property", func(ctx context.Context) error {
			return c.DeleteCustomProperty(ctx, me.DatabaseID, ident)
		})

		err = c.SetCustomProperty(ctx, me.DatabaseID, ident, "John Doe | a=b")
		skipUnlessAllowed(t, err, "SetCustomProperty")
		if err != nil {
			t.Fatalf("SetCustomProperty: %v", err)
		}
		props, err := c.ListCustomProperties(ctx, me.DatabaseID)
		if err != nil || !slices.Contains(props, teamspeak.CustomProperty{Ident: ident, Value: "John Doe | a=b"}) {
			t.Errorf("ListCustomProperties = %v, %v, want the property with its value as written", props, err)
		}
		found, err := c.FindCustomProperty(ctx, ident, "john%")
		want := teamspeak.CustomPropertyMatch{DatabaseID: me.DatabaseID, Ident: ident, Value: "John Doe | a=b"}
		if err != nil || !slices.Contains(found, want) {
			t.Errorf("FindCustomProperty = %v, %v, want %+v", found, err, want)
		}
		none, err := c.FindCustomProperty(ctx, ident, "nobody")
		if err != nil || len(none) != 0 {
			t.Errorf("a pattern that matches nothing = %v, %v", none, err)
		}

		err = c.DeleteCustomProperty(ctx, me.DatabaseID, ident)
		if err != nil {
			t.Fatalf("DeleteCustomProperty: %v", err)
		}
		props, err = c.ListCustomProperties(ctx, me.DatabaseID)
		if err != nil || slices.ContainsFunc(props, func(p teamspeak.CustomProperty) bool { return p.Ident == ident }) {
			t.Errorf("after the delete ListCustomProperties = %v, %v", props, err)
		}
	})
}

// The connection's own permission is read by name and by id, and the server
// refuses one it does not know.
func TestQueryAdmin_OwnPermission(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		byName, err := c.GetOwnPermission(ctx, teamspeak.PermissionByName(perm.ClientBanList))
		skipUnlessAllowed(t, err, "GetOwnPermission")
		if err != nil {
			t.Fatalf("GetOwnPermission: %v", err)
		}
		if byName.Value < 1 || byName.Name != perm.ClientBanList || byName.ID == 0 {
			t.Errorf("the query admin's %s = %+v, want its name, its id and at least 1", perm.ClientBanList, byName)
		}

		byID, err := c.GetOwnPermission(ctx, teamspeak.PermissionByID(byName.ID))
		if err != nil || byID != byName {
			t.Errorf("by id %d = %+v, %v, want %+v as by name", byName.ID, byID, err, byName)
		}

		_, err = c.GetOwnPermission(ctx, teamspeak.PermissionByName("b_no_such_permission"))
		if code := serverCode(err); code != 2562 {
			t.Errorf("an unknown permission: %v, want code 2562", err)
		}
	})
}

// Bans carry a MyTeamSpeak id and a last nickname, page, and are found.
func TestQueryAdmin_Bans(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
		myts := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		ids := make([]teamspeak.BanID, 0, 3)
		for i, opts := range []teamspeak.BanOptions{
			{Name: "ts-go-it-a-" + stamp, LastNickname: "Mallory", Reason: "ts-go-it"},
			{Name: "ts-go-it-b-" + stamp, MyTSID: myts, Reason: "ts-go-it"},
			{Name: "ts-go-it-c-" + stamp, Reason: "ts-go-it"},
		} {
			id, found, err := c.AddBan(ctx, opts)
			skipUnlessAllowed(t, err, "AddBan")
			if err != nil || !found {
				t.Fatalf("AddBan %d: id %d, found %t, %v", i, id, found, err)
			}
			ids = append(ids, id)
			cleanup(t, "ban "+strconv.Itoa(int(id)), func(ctx context.Context) error { return c.DeleteBan(ctx, id) })
		}

		all, err := c.ListBans(ctx, teamspeak.BanListOptions{})
		if err != nil {
			t.Fatalf("ListBans: %v", err)
		}
		if b := banByID(all, ids[0]); b == nil || b.LastNickname != "Mallory" || b.Name == "" {
			t.Errorf("the ban with a last nickname = %+v", b)
		}
		if b := banByID(all, ids[1]); b == nil || b.MyTSID != myts {
			t.Errorf("the ban with a MyTeamSpeak id = %+v, want mytsid %q", b, myts)
		}

		assertBanPaging(ctx, t, c, all)

		switch {
		case family != teamspeak.ServerFamilyTS6:
			t.Log("banfind is TeamSpeak 6 only, so it is not run here")
		case transport == "web":
			t.Log("WebQuery refuses banfind, so it is not run here")
		default:
			found, err := c.FindBans(ctx, teamspeak.BanCriteria{MyTSID: myts})
			if err != nil || banByID(found, ids[1]) == nil {
				t.Errorf("FindBans by MyTeamSpeak id = %v, %v, want ban %d", found, err, ids[1])
			}
		}
	})
}

func banByID(bans []teamspeak.BanEntry, id teamspeak.BanID) *teamspeak.BanEntry {
	i := slices.IndexFunc(bans, func(b teamspeak.BanEntry) bool { return b.ID == id })
	if i < 0 {
		return nil
	}

	return &bans[i]
}

// assertBanPaging steps through the list a page of one at a time, and asks for
// a page past the end, which is empty rather than an error.
func assertBanPaging(ctx context.Context, t *testing.T, c *serverquery.Client, all []teamspeak.BanEntry) {
	t.Helper()
	first, err := c.ListBans(ctx, teamspeak.BanListOptions{Limit: 1})
	if err != nil || len(first) != 1 || first[0].ID != all[0].ID {
		t.Errorf("first page = %v, %v, want the list's first ban %d", first, err, all[0].ID)
	}
	second, err := c.ListBans(ctx, teamspeak.BanListOptions{Start: 1, Limit: 1})
	if err != nil || len(second) != 1 || len(all) < 2 || second[0].ID != all[1].ID {
		t.Errorf("second page = %v, %v, want the list's second ban", second, err)
	}
	past, err := c.ListBans(ctx, teamspeak.BanListOptions{Start: len(all) + 1000})
	if err != nil || len(past) != 0 {
		t.Errorf("a page past the end = %v, %v, want none", past, err)
	}
}

// banfind is TeamSpeak 6's; TeamSpeak 3 does not know it, and the typed method
// reports that as the server's refusal: 256 over raw TCP and SSH, where its
// WebQuery answers an unknown command with 1538, invalid parameter, as
// TeamSpeak 6's does.
func TestQueryAdmin_FindBansRefusedWhereItDoesNotExist(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		if family != teamspeak.ServerFamilyTS3 {
			t.Skip("TeamSpeak 3 is the server without banfind")
		}
		_, err := c.FindBans(adminCtx(t), teamspeak.BanCriteria{IP: "1.2.3.4"})
		want, wantName := errcode.CommandNotFound, "256, command not found"
		if transport == "web" {
			want, wantName = errcode.ParameterInvalid, "1538, invalid parameter"
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %s", transport, err, wantName)
		}
	})
}

// A query login is made without a server selected, so it is a global one,
// listed, found by pattern and deleted.
func TestQueryAdmin_QueryLogins(t *testing.T) {
	forEachTransport(t, 0, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, transport string) {
		if transport == "web" && family == teamspeak.ServerFamilyTS3 {
			// TS3's WebQuery runs every command on a virtual server, even with
			// none in the path, and there queryloginadd wants a client's
			// database id: 1539, parameter not found, for a global login.
			t.Skip("TeamSpeak 3's WebQuery has no instance level to make a global query login on")
		}
		ctx := adminCtx(t)
		name := "tsgoit" + strconv.FormatInt(time.Now().UnixNano(), 36)
		login, err := c.AddQueryLogin(ctx, name, teamspeak.QueryLoginOptions{})
		skipUnlessAllowed(t, err, "AddQueryLogin")
		if err != nil {
			t.Fatalf("AddQueryLogin: %v", err)
		}
		cleanup(t, "the query login", func(ctx context.Context) error {
			// The test deletes it too; 512 says it is gone.
			deleteErr := c.DeleteQueryLogin(ctx, login.DatabaseID)
			if errors.Is(deleteErr, errcode.ClientInvalidID) {
				return nil
			}

			return deleteErr
		})
		if login.Name != name || login.Password == "" || login.DatabaseID == 0 || login.ServerID != 0 {
			t.Errorf("the new login = %+v, want a global one named %s with a password", login, name)
		}

		_, err = c.AddQueryLogin(ctx, name, teamspeak.QueryLoginOptions{})
		if !errors.Is(err, errcode.DatabaseDuplicateEntry) {
			t.Errorf("adding the same name again: %v, want 1282, duplicate entry", err)
		}

		found, err := c.ListQueryLogins(ctx, teamspeak.QueryLoginListOptions{Pattern: name[:len(name)-2] + "%"})
		if err != nil || len(found) != 1 || found[0] != login.QueryLogin {
			t.Errorf("ListQueryLogins by pattern = %+v, %v, want %+v", found, err, login.QueryLogin)
		}
		paged, err := c.ListQueryLogins(ctx, teamspeak.QueryLoginListOptions{Limit: 1})
		if err != nil || len(paged) != 1 {
			t.Errorf("a page of one = %+v, %v", paged, err)
		}

		err = c.DeleteQueryLogin(ctx, login.DatabaseID)
		if err != nil {
			t.Fatalf("DeleteQueryLogin: %v", err)
		}
		found, err = c.ListQueryLogins(ctx, teamspeak.QueryLoginListOptions{Pattern: name})
		if err != nil || len(found) != 0 {
			t.Errorf("after the delete = %+v, %v, want none", found, err)
		}
	})
}

// An offline message to a client that has connected arrives in that client's
// inbox, which the client reads through the voice protocol.
func TestQueryAdmin_OfflineMessage(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		voice := voiceClient(t, "query-itest-inbox")
		subject := "ts-go-it " + strconv.FormatInt(time.Now().UnixNano(), 36)

		err := c.SendOfflineMessage(ctx, voice.UID(), subject, "Where are you?!?")
		if err != nil {
			t.Fatalf("SendOfflineMessage: %v", err)
		}

		messages, err := voice.ListMessages(ctx, teamspeak.MessageListOptions{})
		if err != nil {
			t.Fatalf("the recipient's ListMessages: %v", err)
		}
		i := slices.IndexFunc(messages, func(m teamspeak.OfflineMessage) bool { return m.Subject == subject })
		if i < 0 {
			t.Fatalf("the recipient's inbox = %+v, want the message %q", messages, subject)
		}
		cleanup(t, "the message", func(ctx context.Context) error { return voice.DeleteMessage(ctx, messages[i].ID) })
		got, err := voice.GetMessage(ctx, messages[i].ID)
		if err != nil || got.Message != "Where are you?!?" {
			t.Errorf("GetMessage = %+v, %v, want the body as sent", got, err)
		}
	})
}

// A privilege key carries a custom set, which lists back as the pairs it was
// made from and lands on the client that redeems the key — a value with a
// space or a pipe whole.
func TestQueryAdmin_PrivilegeKeyCustomSet(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		group := groupToRedeem(ctx, t, c)

		set := []teamspeak.CustomProperty{
			{Ident: "forum_user", Value: "Sven Paulsen"},
			{Ident: "forum_id", Value: "123"},
			{Ident: "note", Value: "a|b = c"},
		}
		token, err := c.AddPrivilegeKey(ctx, teamspeak.PrivilegeKeyOptions{
			ServerGroupID: group, Description: "ts-go-it custom set", CustomSet: set,
		})
		skipUnlessAllowed(t, err, "AddPrivilegeKey")
		if err != nil {
			t.Fatalf("AddPrivilegeKey: %v", err)
		}
		cleanup(t, "the privilege key", func(ctx context.Context) error {
			// A redeemed key is gone already, which the server answers with 3,
			// "ok" without an update.
			deleteErr := c.DeletePrivilegeKey(ctx, token)
			if errors.Is(deleteErr, errcode.OKNoUpdate) {
				return nil
			}

			return deleteErr
		})

		keys, err := c.ListPrivilegeKeys(ctx)
		if err != nil {
			t.Fatalf("ListPrivilegeKeys: %v", err)
		}
		i := slices.IndexFunc(keys, func(k teamspeak.PrivilegeKey) bool { return k.Token == token })
		if i < 0 {
			t.Fatalf("the new key is not in the list of %d", len(keys))
		}
		if !slices.Equal(keys[i].CustomSet, set) {
			t.Errorf("the key's custom set = %+v, want %+v", keys[i].CustomSet, set)
		}
		assertRedeemedSet(t, c, token, set)
	})
}

// assertRedeemedSet has a voice client redeem the key, which is what a custom
// set is for: it lands on the client's record, each value as written.
func assertRedeemedSet(t *testing.T, c *serverquery.Client, token string, set []teamspeak.CustomProperty) {
	t.Helper()
	ctx := adminCtx(t)
	voice := voiceClient(t, "query-itest-redeem")
	err := voice.UsePrivilegeKey(ctx, token)
	if err != nil {
		t.Skipf("the voice client could not redeem the key: %v", err)
	}
	info, err := voice.GetClientProperties(ctx, voice.ClientID())
	if err != nil {
		t.Fatalf("GetClientProperties: %v", err)
	}
	raw, err := strconv.ParseUint(info["client_database_id"], 10, 64)
	if err != nil {
		t.Fatalf("no database id for the voice client: %v", err)
	}
	dbid := teamspeak.ClientDBID(raw)
	cleanup(t, "the redeemed properties", func(ctx context.Context) error {
		for _, prop := range set {
			deleteErr := c.DeleteCustomProperty(ctx, dbid, prop.Ident)
			if deleteErr != nil {
				return deleteErr
			}
		}

		return nil
	})
	got, err := c.ListCustomProperties(ctx, dbid)
	if err != nil || !slices.Equal(got, set) {
		t.Errorf("the redeeming client's properties = %+v, %v, want %+v", got, err, set)
	}
}

// groupToRedeem picks a regular server group a key may grant: the Normal one
// where the server has it, otherwise the server's default group.
func groupToRedeem(ctx context.Context, t *testing.T, c *serverquery.Client) teamspeak.ServerGroupID {
	t.Helper()
	groups, err := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
	if err != nil {
		t.Fatalf("ListServerGroups: %v", err)
	}
	if i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool {
		return g.Type == teamspeak.GroupRegular && g.Name == "Normal"
	}); i >= 0 {
		return groups[i].ID
	}
	info, err := c.GetServerInfo(ctx)
	if err != nil {
		t.Fatalf("GetServerInfo: %v", err)
	}
	id, err := strconv.ParseUint(info["virtualserver_default_server_group"], 10, 64)
	if err != nil {
		t.Skipf("the server reported no default server group: %v", err)
	}

	return teamspeak.ServerGroupID(id)
}

// FindClientsWith reports the channel on TeamSpeak 6 and leaves it out on
// TeamSpeak 3, which takes the flags and ignores them.
func TestQueryAdmin_FindClientsWith(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		nickname := "query-itest-find"
		voice := voiceClient(t, nickname)

		plain, err := c.FindClients(ctx, nickname)
		if err != nil || len(plain) != 1 || plain[0].ID != voice.ClientID() || plain[0].ChannelID != 0 {
			t.Fatalf("FindClients = %+v, %v, want the voice client %d with no channel", plain, err, voice.ClientID())
		}
		// -icon is accepted, and each client then carries its icon id, 0 for none.
		listed, err := c.ListClients(ctx, teamspeak.ClientListOptions{Icon: true})
		isVoice := func(e teamspeak.ClientEntry) bool { return e.ID == voice.ClientID() }
		if err != nil || !slices.ContainsFunc(listed, isVoice) {
			t.Errorf("ListClients with Icon = %+v, %v, want the voice client among them", listed, err)
		}
		with, err := c.FindClientsWith(ctx, nickname, teamspeak.ClientFindOptions{ChannelID: true, ChannelUID: true})
		if err != nil || len(with) != 1 || with[0].ID != voice.ClientID() {
			t.Fatalf("FindClientsWith = %+v, %v, want the voice client %d", with, err, voice.ClientID())
		}
		if family != teamspeak.ServerFamilyTS6 {
			t.Logf("TeamSpeak 3 answers neither -cid nor -chuid: channel %d, uid %q", with[0].ChannelID, with[0].ChannelUID)
			if with[0].ChannelID != 0 || with[0].ChannelUID != "" {
				t.Errorf("TeamSpeak 3 reported a channel after all: %+v", with[0])
			}

			return
		}
		// The voice client learns its own channel from the enter-view
		// notification, which can arrive just after Connect returns.
		deadline := time.Now().Add(5 * time.Second)
		for voice.ChannelID() == 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if with[0].ChannelID != voice.ChannelID() || with[0].ChannelUID == "" {
			t.Errorf("channel %d (%q), want %d and a unique id", with[0].ChannelID, with[0].ChannelUID, voice.ChannelID())
		}
	})
}

// The instance's servers are listed, whole and short, and a global message
// goes out.
func TestQueryAdmin_ListServersAndGlobalMessage(t *testing.T) {
	forEachTransport(t, 0, func(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		servers, err := c.ListServers(ctx, teamspeak.ServerListOptions{UID: true})
		skipUnlessAllowed(t, err, "ListServers")
		if err != nil || len(servers) == 0 {
			t.Fatalf("ListServers = %+v, %v, want the server the fixture provisioned", servers, err)
		}
		first := servers[0]
		if first.ID == 0 || first.Port == 0 || first.Status == "" || first.Name == "" || first.UID == "" {
			t.Errorf("the first server = %+v, want every field of a full listing", first)
		}
		if first.MaxClients == 0 {
			t.Errorf("the first server = %+v, want its slots", first)
		}

		short, err := c.ListServers(ctx, teamspeak.ServerListOptions{Short: true})
		if err != nil || len(short) != len(servers) || short[0].ID != first.ID || short[0].Port != first.Port {
			t.Errorf("a short listing = %+v, %v, want the same servers", short, err)
		} else if short[0].Name != "" {
			t.Errorf("a short listing names the server %q", short[0].Name)
		}
		offline, err := c.ListServers(ctx, teamspeak.ServerListOptions{OnlyOffline: true})
		if err != nil {
			t.Errorf("an offline-only listing: %v", err)
		}
		for _, s := range offline {
			if s.Status != "offline" {
				t.Errorf("an offline-only listing holds %+v", s)
			}
		}

		err = c.SendGlobalMessage(ctx, "ts-go integration test on "+family.String())
		if err != nil {
			t.Errorf("SendGlobalMessage: %v", err)
		}
	})
}

// A permission added to every server group of a kind, and removed again,
// leaves the groups as they were. The permission is one the group does not
// hold to begin with, so removing it restores it; where it did hold one, the
// test puts that back.
func TestQueryAdmin_ServerGroupPermissionByType(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		groups, err := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
		if err != nil {
			t.Fatalf("ListServerGroups: %v", err)
		}
		// The regular Server Admin group is the one of that kind on this server.
		i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool {
			return g.Type == teamspeak.GroupRegular && g.Name == "Server Admin"
		})
		if i < 0 {
			t.Skip("no regular Server Admin group to look at")
		}
		group := groups[i]
		target := teamspeak.PermissionByName(perm.ClientPokePower)
		heldBefore := permissionOf(t, c, group.ID, perm.ClientPokePower)

		const value = 33
		err = c.AddServerGroupPermissionByType(ctx, teamspeak.GroupAutoUpdateServerAdmin, target, value,
			teamspeak.ServerGroupPermissionOptions{Skip: true})
		skipUnlessAllowed(t, err, "AddServerGroupPermissionByType")
		if err != nil {
			t.Fatalf("AddServerGroupPermissionByType: %v", err)
		}
		restore := func() {
			deleteErr := c.DeleteServerGroupPermissionByType(context.Background(), teamspeak.GroupAutoUpdateServerAdmin, target)
			if deleteErr != nil {
				t.Errorf("DeleteServerGroupPermissionByType: %v", deleteErr)
			}
			if heldBefore != nil {
				putBack := c.AddServerGroupPermission(context.Background(), group.ID, target, heldBefore.Value,
					teamspeak.ServerGroupPermissionOptions{Negated: heldBefore.Negated, Skip: heldBefore.Skip})
				if putBack != nil {
					t.Errorf("putting back %s on group %d: %v", perm.ClientPokePower, group.ID, putBack)
				}
			}
		}
		defer restore()

		now := permissionOf(t, c, group.ID, perm.ClientPokePower)
		if now == nil || now.Value != value || !now.Skip {
			t.Errorf("after the add the group holds %+v, want value %d with skip", now, value)
		}
	})
}

// permissionOf reads one permission off a server group, nil when it holds none.
func permissionOf(
	t *testing.T, c *serverquery.Client, group teamspeak.ServerGroupID, name string,
) *teamspeak.PermissionEntry {
	t.Helper()
	// The list names permissions by id, since it is asked for them that way, so
	// the name is resolved to one.
	ctx := adminCtx(t)
	id, known, err := c.GetPermissionIDByName(ctx, name)
	if err != nil || !known {
		t.Fatalf("no id for %s: %v", name, err)
	}
	entries, err := c.ListServerGroupPermissions(ctx, group)
	if err != nil {
		t.Fatalf("ListServerGroupPermissions: %v", err)
	}
	for _, entry := range entries {
		if entry.Permission.ID() == id || entry.Permission.Name() == name {
			return &entry
		}
	}

	return nil
}

// A snapshot of the server is read, with and without a password, and only the
// one with a password has a salt. Restoring one is in the instance tests.
func TestQueryAdmin_CreateServerSnapshot(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		plain, err := c.CreateServerSnapshot(ctx, teamspeak.SnapshotCreateOptions{})
		skipUnlessAllowed(t, err, "CreateServerSnapshot")
		if err != nil {
			t.Fatalf("CreateServerSnapshot: %v", err)
		}
		if plain.Data == "" || plain.Version == 0 || plain.Salt != "" {
			t.Errorf("an unencrypted snapshot = %v with %d bytes of data and salt %q", plain, len(plain.Data), plain.Salt)
		}
		sealed, err := c.CreateServerSnapshot(ctx, teamspeak.SnapshotCreateOptions{Password: "ts-go-it"})
		if err != nil {
			t.Fatalf("CreateServerSnapshot with a password: %v", err)
		}
		if sealed.Data == "" || sealed.Salt == "" {
			t.Errorf("an encrypted snapshot = %v, want data and a salt", sealed)
		}
		if sealed.Data == plain.Data {
			t.Errorf("the encrypted data equals the plain data")
		}
	})
}

// A session moves between a login, a server and its notifications by hand,
// over the transports that have a session — raw TCP and SSH — where all of it
// exists: the commands the client runs at Connect are the same ones, run
// mid-session.
func TestQuerySession_LoginUseAndNotificationsByHand(t *testing.T) {
	for name, dialer := range map[string]func(t *testing.T) (serverquery.Dialer, []serverquery.Option, account){
		"tcp": tcpDialer, "ssh": sshDialer,
	} {
		t.Run(name, func(t *testing.T) {
			d, opts, who := dialer(t)
			waitForOtherSuites()
			c, err := serverquery.New(d, append(opts, serverquery.WithServer(1), serverquery.WithoutEvents())...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			open(t, c)
			ctx := adminCtx(t)

			assertNotificationsByHand(t, c)
			assertUseByHand(ctx, t, c)
			assertLogoutAndLogin(ctx, t, c, who)
		})
	}
}

// assertNotificationsByHand registers, unregisters and registers again, and
// checks what a text message from a voice client does each time.
func assertNotificationsByHand(t *testing.T, c *serverquery.Client) {
	t.Helper()
	ctx := adminCtx(t)
	heard := make(chan string, 8)
	c.OnTextMessage(func(e teamspeak.TextMessageEvent) { heard <- e.Message })
	grantGuestPermission(t, c, perm.ClientServerTextMessageSend)
	voice := voiceClient(t, "query-itest-say")
	say := func(message string, want bool) {
		t.Helper()
		err := voice.SendServerMessage(ctx, message)
		if err != nil {
			t.Fatalf("SendServerMessage: %v", err)
		}
		select {
		case got := <-heard:
			if !want || got != message {
				t.Errorf("heard %q, want %q (heard at all: %t)", got, message, want)
			}
		case <-time.After(5 * time.Second):
			if want {
				t.Errorf("the message %q never arrived", message)
			}
		}
	}

	// WithoutEvents registered nothing, so a message is not heard until the
	// client asks.
	say("before", false)
	err := c.RegisterNotifications(ctx, serverquery.CategoryTextServer, serverquery.NotificationOptions{})
	if err != nil {
		t.Fatalf("RegisterNotifications: %v", err)
	}
	say("registered", true)
	err = c.UnregisterNotifications(ctx, serverquery.UnregisterNotificationsOptions{})
	if err != nil {
		t.Fatalf("UnregisterNotifications: %v", err)
	}
	say("unregistered", false)

	// The server refuses `channel` without an id, and takes it with 0, which is
	// every channel.
	err = c.RegisterNotifications(ctx, serverquery.CategoryChannel, serverquery.NotificationOptions{})
	if code := serverCode(err); code != 1539 {
		t.Errorf("channel without an id: %v, want 1539", err)
	}
	all := teamspeak.ChannelID(0)
	err = c.RegisterNotifications(ctx, serverquery.CategoryChannel, serverquery.NotificationOptions{ChannelID: &all})
	if err != nil {
		t.Errorf("channel with id 0: %v", err)
	}
}

// assertUseByHand asks for a server that is not there, which leaves the
// connection on none, and then selects the real one under a nickname.
func assertUseByHand(ctx context.Context, t *testing.T, c *serverquery.Client) {
	t.Helper()
	err := c.Use(ctx, serverquery.ByID(9999), serverquery.UseOptions{})
	if err == nil {
		t.Fatal("Use of a server that does not exist succeeded")
	}
	gone, err := c.WhoAmI(ctx)
	if err != nil || gone.ServerID != 0 {
		t.Errorf("after a refused Use: %+v, %v, want no server", gone, err)
	}
	err = c.Use(ctx, serverquery.ServerSelector{}, serverquery.UseOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) {
		t.Errorf("Use with a selector that names nothing: %v, want ErrInvalidCommand", err)
	}

	// A selection of the server the connection is already on changes nothing,
	// the nickname included, so it is the fresh selection that takes one.
	err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{Nickname: "query-itest-used"})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	after, err := c.WhoAmI(ctx)
	if err != nil || after.ServerID != 1 || after.Nickname != "query-itest-used" || after.ClientID == 0 {
		t.Errorf("after Use: %+v, %v, want server 1 under the new nickname", after, err)
	}
}

// assertLogoutAndLogin ends the login, which leaves the connection open and
// without rights, and logs in again.
func assertLogoutAndLogin(ctx context.Context, t *testing.T, c *serverquery.Client, who account) {
	t.Helper()
	err := c.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{})
	if err != nil {
		t.Errorf("Use after Logout: %v, want a client with no account on the server", err)
	}
	anonymous, err := c.WhoAmI(ctx)
	if err != nil || anonymous.LoginName != "" || anonymous.ServerID != 1 {
		t.Errorf("after Logout and Use: %+v, %v, want server 1 and no login name", anonymous, err)
	}
	_, err = c.ListQueryLogins(ctx, teamspeak.QueryLoginListOptions{})
	if !errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Errorf("a command that needs rights after Logout: %v, want 2568", err)
	}
	// A wrong password is not tried here: the server counts failed logins and
	// bans the address that makes them, for ten minutes, which would lock the
	// rest of the suite out.
	err = c.Login(ctx, who.name, who.password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{})
	if err != nil {
		t.Fatalf("Use after Login: %v", err)
	}
	_, err = c.ListQueryLogins(ctx, teamspeak.QueryLoginListOptions{})
	if err != nil {
		t.Errorf("a command that needs rights after logging in again: %v", err)
	}
	back, err := c.WhoAmI(ctx)
	if err != nil || back.LoginName != who.name || back.ServerID != 1 {
		t.Errorf("after Login and Use: %+v, %v, want %s on server 1", back, err, who.name)
	}
}

// WebQuery has no session: the api key is the login, so the session commands
// that need one are refused with 5120, "out of scope".
func TestQuerySession_WebQueryRefusesWhatNeedsASession(t *testing.T) {
	base, apiKey := webVars(t)
	waitForOtherSuites()
	c, err := serverquery.New(serverquery.Web(base, apiKey), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)
	ctx := adminCtx(t)

	if code := serverCode(c.Logout(ctx)); code != 5120 {
		t.Errorf("Logout: code %d, want 5120", code)
	}
	if code := serverCode(c.Login(ctx, "serveradmin", "x")); code != 5120 {
		t.Errorf("Login: code %d, want 5120", code)
	}
	err = c.UnregisterNotifications(ctx, serverquery.UnregisterNotificationsOptions{})
	if code := serverCode(err); code != 5120 {
		t.Errorf("UnregisterNotifications: %v, want 5120", err)
	}
	// Use is the transport's own: it addresses the server named, and a later
	// command shows it.
	me, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	err = c.Use(ctx, serverquery.ByPort(me.ServerPort), serverquery.UseOptions{})
	if err != nil {
		t.Errorf("Use by port: %v", err)
	}
	again, err := c.WhoAmI(ctx)
	if err != nil || again.ServerID != me.ServerID {
		t.Errorf("after Use by port %d: %+v, %v, want server %d", me.ServerPort, again, err, me.ServerID)
	}
}
