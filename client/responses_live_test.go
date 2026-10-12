//go:build integration

package client_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// These answer with a notification rather than data rows. The SDK used to
// collect only data rows and report an empty success for every one of them.
func TestLive_ClientLookupsAnswerWithTheirData(t *testing.T) {
	c := requireSharedClient(t)
	clid := c.ClientID()
	me, err := c.GetClientInfo(t.Context(), clid)
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
	nameDBID, byUID, err := c.GetClientNameByUID(t.Context(), uid)
	requireNoErr(t, err)
	ids, err := c.GetClientIDs(t.Context(), uid)
	requireNoErr(t, err)

	if gotUID != uid || gotDBID != dbid || byDBID != nickname || byUID != nickname || nameDBID != dbid {
		t.Errorf("lookups = uid %q dbid %d names %q/%q (dbid %d), want %q %d %q",
			gotUID, gotDBID, byDBID, byUID, nameDBID, uid, dbid, nickname)
	}
	if !slices.Contains(ids, clid) {
		t.Errorf("GetClientIDs = %v, want it to contain %d", ids, clid)
	}
}

func TestLive_ServerGroupsIncludeTheDefaultGroup(t *testing.T) {
	c := requireSharedClient(t)
	groups, err := c.ListServerGroups(t.Context())
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

	cid, err := c.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{ChannelName: name})
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
	requireNoErr(t, teamspeak.UploadFileData(t.Context(), host, upload, bytes.NewReader(payload), nil))
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
	requireNoErr(t, teamspeak.DownloadFileData(t.Context(), host, download, &got, nil))
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("downloaded %q, want %q", got.Bytes(), payload)
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
	if since := time.Since(listed.ModifiedAt).Abs(); since > time.Hour || listed.IsDirectory {
		t.Errorf("ListFiles entry = %+v, want a file modified just now", listed)
	}
	info, err := c.GetFileInfo(t.Context(), cid, path, teamspeak.FileOptions{})
	requireNoErr(t, err)
	if since := time.Since(info.ModifiedAt).Abs(); since > time.Hour || info.Size != size {
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
		requireNoErr(t, teamspeak.UploadFileData(t.Context(), host, upload, bytes.NewReader([]byte{1}), nil))
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
