//go:build integration

package client_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/perm"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// These answer with a notification rather than data rows. The SDK used to
// collect only data rows and report an empty success for every one of them.
func TestLive_ClientLookupsAnswerWithTheirData(t *testing.T) {
	c := requireSharedClient(t)
	clid := c.ClientID()
	me, err := c.GetClientProperties(t.Context(), clid)
	requireNoErr(t, err)
	uid := teamspeak.UID(me["client_unique_identifier"])
	rawDBID, err := strconv.ParseUint(me["client_database_id"], 10, 64)
	requireNoErr(t, err)
	dbid := teamspeak.ClientDBID(rawDBID)
	nickname := me["client_nickname"]

	gotUID, err := c.GetClientUIDByID(t.Context(), clid)
	requireNoErr(t, err)
	gotDBID, err := c.GetClientDBIDByUID(t.Context(), uid)
	requireNoErr(t, err)
	byDBID, err := c.GetClientNameByDBID(t.Context(), dbid)
	requireNoErr(t, err)
	byUID, err := c.GetClientNameByUID(t.Context(), uid)
	requireNoErr(t, err)
	ids, err := c.GetClientIDs(t.Context(), uid)
	requireNoErr(t, err)

	want := teamspeak.ClientDatabaseName{DatabaseID: dbid, Name: nickname}
	// The lookup by database id answers the uid as well; the one by uid was
	// asked it.
	wantByDBID := teamspeak.ClientDatabaseName{DatabaseID: dbid, Name: nickname, UID: uid}
	if gotUID != uid || gotDBID != dbid || byDBID != wantByDBID || byUID != want {
		t.Errorf("lookups = uid %q dbid %d names %+v/%+v, want %q %d %+v/%+v",
			gotUID, gotDBID, byDBID, byUID, uid, dbid, wantByDBID, want)
	}
	if !slices.ContainsFunc(ids, func(m teamspeak.ClientMatch) bool { return m.ID == clid && m.Nickname == nickname }) {
		t.Errorf("GetClientIDs = %v, want it to contain %d", ids, clid)
	}
}

func TestLive_ServerGroupsIncludeTheDefaultGroup(t *testing.T) {
	c := requireSharedClient(t)
	groups, err := c.ListServerGroups(t.Context(), teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	info, err := c.GetServerInfo(t.Context())
	requireNoErr(t, err)
	rawDefault, err := strconv.ParseUint(info["virtualserver_default_server_group"], 10, 64)
	requireNoErr(t, err)
	defaultGroup := teamspeak.ServerGroupID(rawDefault)

	if !slices.ContainsFunc(groups, func(g teamspeak.ServerGroup) bool { return g.ID == defaultGroup }) {
		t.Errorf("ListServerGroups = %d groups without the default %d", len(groups), defaultGroup)
	}
}

// The voice protocol answers channelcreate with notifychannelcreated, not a cid
// row, so the id came back as 0.
func TestLive_CreateChannelReturnsTheNewID(t *testing.T) {
	c := requireSharedClient(t)
	before := c.ChannelID()
	name := fmt.Sprintf("ts-go-%d", time.Now().UnixNano())

	cid, err := c.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{Name: name})
	requireNoErr(t, err)
	// Creating a channel over the voice protocol moves the creator into it, and
	// the server deletes a temporary channel once its last client leaves — so
	// moving back is the cleanup.
	t.Cleanup(func() {
		_ = c.MoveClient(context.WithoutCancel(t.Context()), c.ClientID(), before, teamspeak.ClientMoveOptions{})
	})

	if cid == 0 {
		t.Fatal("CreateChannel returned cid 0")
	}
	info, err := c.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	if info.Name != name {
		t.Errorf("channel %d is %q, want %q", cid, info.Name, name)
	}
}

// The key arrives in a notification after the command has already returned;
// without it there is nothing to dial.
//
//nolint:funlen // one round trip, step by step
func TestLive_FileTransferRoundTrip(t *testing.T) {
	c := requireSharedClient(t)
	addr := requireTeamSpeakAddr(t)
	host, _, err := net.SplitHostPort(addr)
	requireNoErr(t, err)
	cid := c.ChannelID()
	path := fmt.Sprintf("/ts-go-%d.bin", time.Now().UnixNano())
	payload := []byte("hello over file transfer")

	opts := teamspeak.FileUploadOptions{Overwrite: true}
	upload, err := c.InitFileUpload(t.Context(), cid, path, uint64(len(payload)), opts)
	requireNoErr(t, err)
	if upload.FileTransferKey == "" {
		t.Fatal("upload negotiated without a key")
	}
	var steps traceSteps
	requireNoErr(t, teamspeak.UploadFileData(t.Context(), host, upload,
		bytes.NewReader(payload), teamspeak.FileTransferOptions{Trace: steps.trace()}))
	steps.require(t, int64(len(payload)))
	t.Cleanup(func() {
		_ = c.DeleteFile(context.WithoutCancel(t.Context()), cid, []string{path}, teamspeak.FileOptions{})
	})

	files, err := c.ListFiles(t.Context(), cid, "/", teamspeak.FileOptions{})
	requireNoErr(t, err)
	idx := slices.IndexFunc(files, func(f teamspeak.FileEntry) bool { return "/"+f.Name == path })
	if idx < 0 {
		t.Fatalf("ListFiles = %v, want %s", files, path)
	}
	checkUploadedFile(t, c, cid, path, files[idx], uint64(len(payload)))

	download, err := c.InitFileDownload(t.Context(), cid, path, teamspeak.FileDownloadOptions{})
	requireNoErr(t, err)
	var got bytes.Buffer
	var downSteps traceSteps
	requireNoErr(t, teamspeak.DownloadFileData(t.Context(), host, download, &got,
		teamspeak.FileTransferOptions{Trace: downSteps.trace()}))
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("downloaded %q, want %q", got.Bytes(), payload)
	}
	downSteps.require(t, int64(len(payload)))
	if downSteps.lastTotal != int64(len(payload)) {
		t.Errorf("download Progress.Total = %d, want %d", downSteps.lastTotal, len(payload))
	}
}

// traceSteps records a FileTransferTrace for the round trip.
type traceSteps struct {
	failedWith error
	order      []string
	lastBytes  int64
	lastTotal  int64
	doneBytes  int64
}

func (s *traceSteps) trace() *teamspeak.FileTransferTrace {
	return &teamspeak.FileTransferTrace{
		DialStart: func(teamspeak.FileTransferDialStartInfo) { s.order = append(s.order, "DialStart") },
		DialDone:  func(teamspeak.FileTransferDialDoneInfo) { s.order = append(s.order, "DialDone") },
		Progress: func(i teamspeak.FileTransferProgressInfo) {
			s.order = append(s.order, "Progress")
			s.lastBytes, s.lastTotal = i.Bytes, i.Total
		},
		Done: func(i teamspeak.FileTransferDoneInfo) {
			s.order = append(s.order, "Done")
			s.doneBytes = i.Bytes
		},
		Failed: func(i teamspeak.FileTransferFailedInfo) {
			s.order = append(s.order, "Failed")
			s.failedWith = i.Err
		},
	}
}

// require checks the order of the milestones and that the last Progress and
// Done count size bytes.
func (s *traceSteps) require(t *testing.T, size int64) {
	t.Helper()
	if len(s.order) < 4 || s.order[0] != "DialStart" || s.order[1] != "DialDone" ||
		s.order[len(s.order)-1] != "Done" || s.order[len(s.order)-2] != "Progress" {
		t.Fatalf("trace = %v (failed with %v), want DialStart, DialDone, Progress and Done", s.order, s.failedWith)
	}
	if s.lastBytes != size || s.doneBytes != size {
		t.Errorf("final Progress.Bytes = %d, Done.Bytes = %d, want %d", s.lastBytes, s.doneBytes, size)
	}
}

// checkUploadedFile checks the dates the server reports for a file just
// uploaded. TS3 sends the listing's datetime in seconds and TS6 in
// milliseconds — and GetFileInfo's in nanoseconds — so a reader assuming
// seconds dated the file tens of thousands of years from now.
func checkUploadedFile(
	t *testing.T, c *client.Client, cid teamspeak.ChannelID, path string, listed teamspeak.FileEntry, size uint64,
) {
	t.Helper()
	if since := time.Since(listed.Modified).Abs(); since > time.Hour || listed.IsDirectory {
		t.Errorf("ListFiles entry = %+v, want a file modified just now", listed)
	}
	info, err := c.GetFileInfo(t.Context(), cid, path, teamspeak.FileOptions{})
	requireNoErr(t, err)
	if since := time.Since(info.Modified).Abs(); since > time.Hour || info.Size != size {
		t.Errorf("GetFileInfo = %+v, want %d bytes modified just now", info, size)
	}
}

// Deleting several files is one command with a row group; both must go.
func TestIntegration_DeleteFileRemovesEveryPath(t *testing.T) {
	c := requireSharedClient(t)
	host, _, err := net.SplitHostPort(requireTeamSpeakAddr(t))
	requireNoErr(t, err)
	me, err := c.WhoAmI(t.Context())
	requireNoErr(t, err)
	cid := me.ChannelID
	stamp := time.Now().UnixNano()
	paths := []string{fmt.Sprintf("/ts-go-del-a-%d.bin", stamp), fmt.Sprintf("/ts-go-del-b-%d.bin", stamp)}
	for _, path := range paths {
		upload, uploadErr := c.InitFileUpload(t.Context(), cid, path, 1, teamspeak.FileUploadOptions{Overwrite: true})
		requireNoErr(t, uploadErr)
		requireNoErr(t, teamspeak.UploadFileData(t.Context(), host, upload,
			bytes.NewReader([]byte{1}), teamspeak.FileTransferOptions{}))
	}

	requireNoErr(t, c.DeleteFile(t.Context(), cid, paths, teamspeak.FileOptions{}))

	files, err := c.ListFiles(t.Context(), cid, "/", teamspeak.FileOptions{})
	requireNoErr(t, err)
	for _, f := range files {
		if slices.Contains(paths, "/"+f.Name) {
			t.Errorf("%s is still there after DeleteFile", f.Name)
		}
	}
}

// skipIfDenied skips a test when the server refused the command for the
// connection's rights, saying which, so a run against a server the fixture has
// not granted them to shows the gap instead of passing over it.
func skipIfDenied(t *testing.T, err error, what string) {
	t.Helper()
	if errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Skipf("%s: %v — the default group lacks the right this needs, so the command cannot be run here", what, err)
	}
}

// The voice protocol answers these with notifications the response table pairs
// with the command, so a raw Exec returns their rows. Each needs no right the
// default group lacks.
func TestLive_VoiceAnswersCarryRows(t *testing.T) {
	c := requireSharedClient(t)
	clid := strconv.Itoa(int(c.ClientID()))

	for _, tc := range []struct {
		command string
		key     string
	}{
		{"clientgetvariables clid=" + clid, "client_version"},
		{"getconnectioninfo clid=" + clid, "connection_client_ip"},
		{"servergetvariables", "virtualserver_maxclients"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			rows, err := c.Exec(t.Context(), tc.command)
			skipIfDenied(t, err, tc.command)
			requireNoErr(t, err)
			if len(rows) == 0 {
				t.Fatalf("%s returned no rows: the answer arrives as a notification", tc.command)
			}
			// A broadcast about the same client can fall in the same window as the
			// answer, so the answer is looked for among the rows.
			answered := slices.ContainsFunc(rows, func(row map[string]string) bool {
				_, ok := row[tc.key]

				return ok
			})
			if !answered {
				t.Errorf("%s: no row has %s: %v", tc.command, tc.key, rows)
			}
		})
	}
}

// permget answers a nameless row on TeamSpeak 3 and a notifypermget on
// TeamSpeak 6; GetOwnPermission reads either.
func TestLive_GetOwnPermission(t *testing.T) {
	c := requireSharedClient(t)

	got, err := c.GetOwnPermission(t.Context(), teamspeak.PermissionByName(perm.ClientPermissionOverviewOwn))
	skipIfDenied(t, err, "permget")
	requireNoErr(t, err)
	if got.Name != perm.ClientPermissionOverviewOwn || got.ID == 0 || got.Value < 1 {
		t.Errorf("%s = %+v, want its name, its id and at least the 1 the fixture grants",
			perm.ClientPermissionOverviewOwn, got)
	}

	_, err = c.GetOwnPermission(t.Context(), teamspeak.PermissionByName("b_no_such_permission"))
	if !errors.Is(err, errcode.PermissionInvalidPermID) {
		t.Errorf("an unknown permission: %v, want 2562", err)
	}
}

// An API key made over the voice protocol comes back from a notification, and
// lists and deletes like one made over ServerQuery.
func TestLive_APIKeys(t *testing.T) {
	c := requireSharedClient(t)
	day := 24 * time.Hour

	key, err := c.AddAPIKey(t.Context(), teamspeak.APIKeyOptions{Scope: teamspeak.APIKeyScopeRead, Lifetime: &day})
	skipIfDenied(t, err, "apikeyadd")
	requireNoErr(t, err)
	t.Cleanup(func() { _ = c.DeleteAPIKey(context.WithoutCancel(t.Context()), key.ID) })
	if key.Key == "" || key.ID == 0 || key.Scope != teamspeak.APIKeyScopeRead {
		t.Fatalf("the new key = %+v, want its value, id and scope", key)
	}

	listed, err := c.ListAPIKeys(t.Context(), teamspeak.APIKeyListOptions{})
	requireNoErr(t, err)
	if !slices.ContainsFunc(listed, func(k teamspeak.APIKey) bool { return k.ID == key.ID }) {
		t.Errorf("ListAPIKeys = %v, want key %d", listed, key.ID)
	}
	requireNoErr(t, c.DeleteAPIKey(t.Context(), key.ID))
}

// Custom properties are set on the client's own record and read back.
func TestLive_CustomProperties(t *testing.T) {
	c := requireSharedClient(t)
	me, err := c.GetClientProperties(t.Context(), c.ClientID())
	requireNoErr(t, err)
	rawDBID, err := strconv.ParseUint(me["client_database_id"], 10, 64)
	requireNoErr(t, err)
	dbid := teamspeak.ClientDBID(rawDBID)
	ident := fmt.Sprintf("ts_go_live_%d", time.Now().UnixNano())

	err = c.SetCustomProperty(t.Context(), dbid, ident, "a value")
	skipIfDenied(t, err, "customset")
	requireNoErr(t, err)
	t.Cleanup(func() { _ = c.DeleteCustomProperty(context.WithoutCancel(t.Context()), dbid, ident) })

	// A guest voice client is refused reading them on both servers.
	props, err := c.ListCustomProperties(t.Context(), dbid)
	skipIfDenied(t, err, "custominfo")
	requireNoErr(t, err)
	if !slices.Contains(props, teamspeak.CustomProperty{Ident: ident, Value: "a value"}) {
		t.Errorf("ListCustomProperties = %v, want %s", props, ident)
	}
	found, err := c.FindCustomProperty(t.Context(), ident, "a%")
	requireNoErr(t, err)
	if !slices.Contains(found, teamspeak.CustomPropertyMatch{DatabaseID: dbid, Ident: ident, Value: "a value"}) {
		t.Errorf("FindCustomProperty = %v, want client %d", found, dbid)
	}
	requireNoErr(t, c.DeleteCustomProperty(t.Context(), dbid, ident))
	props, err = c.ListCustomProperties(t.Context(), dbid)
	requireNoErr(t, err)
	if slices.ContainsFunc(props, func(p teamspeak.CustomProperty) bool { return p.Ident == ident }) {
		t.Errorf("the property is still there after the delete: %v", props)
	}
}

// banfind is TeamSpeak 6's: its answer is a notifybanfind over the voice
// protocol, and TeamSpeak 3 never answers at all.
func TestLive_FindBans(t *testing.T) {
	c := requireSharedClient(t)
	if family := c.ServerCapabilities().Family; family != teamspeak.ServerFamilyTS6 {
		t.Skipf("banfind is TeamSpeak 6 only, and %v never answers it over the voice protocol", family)
	}
	ip := "203.0.113." + strconv.Itoa(int(time.Now().UnixNano()%200)+1)

	_, _, err := c.AddBan(t.Context(), teamspeak.BanOptions{IP: ip, Reason: "ts-go live test", LastNickname: "Mallory"})
	skipIfDenied(t, err, "banadd")
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		bans, listErr := c.ListBans(ctx, teamspeak.BanListOptions{})
		if listErr != nil {
			return
		}
		for _, b := range bans {
			if b.IP == ip {
				_ = c.DeleteBan(ctx, b.ID)
			}
		}
	})

	bans, err := c.FindBans(t.Context(), teamspeak.BanCriteria{IP: ip})
	requireNoErr(t, err)
	if len(bans) != 1 || bans[0].IP != ip || bans[0].LastNickname != "Mallory" {
		t.Errorf("FindBans(%s) = %+v, want the ban just made", ip, bans)
	}
	none, err := c.FindBans(t.Context(), teamspeak.BanCriteria{IP: "198.51.100.1"})
	requireNoErr(t, err)
	if len(none) != 0 {
		t.Errorf("FindBans for an address nobody banned = %+v", none)
	}
}

// An offline message sent over the voice protocol lands in the recipient's
// inbox, which the recipient reads with the same protocol.
func TestLive_SendOfflineMessage(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	c := requireSharedClient(t)
	peer := requireIntegrationPeer(t, addr)
	subject := fmt.Sprintf("ts-go live %d", time.Now().UnixNano())

	err := c.SendOfflineMessage(t.Context(), peer.UID(), subject, "Where are you?!?")
	skipIfDenied(t, err, "messageadd")
	requireNoErr(t, err)

	messages, err := peer.ListMessages(t.Context(), teamspeak.MessageListOptions{})
	requireNoErr(t, err)
	i := slices.IndexFunc(messages, func(m teamspeak.OfflineMessage) bool { return m.Subject == subject })
	if i < 0 {
		t.Fatalf("the recipient's inbox = %+v, want the message %q", messages, subject)
	}
	t.Cleanup(func() { _ = peer.DeleteMessage(context.WithoutCancel(t.Context()), messages[i].ID) })

	got, err := peer.GetMessage(t.Context(), messages[i].ID)
	requireNoErr(t, err)
	if got.Message != "Where are you?!?" || got.UID != c.UID() {
		t.Errorf("GetMessage = %+v, want the body as sent, from %q", got, c.UID())
	}
}
