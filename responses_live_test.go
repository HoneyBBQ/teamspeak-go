//go:build integration

package teamspeak_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// These answer with a notification rather than data rows. The SDK used to
// collect only data rows and report an empty success for every one of them.
func TestLive_ClientLookupsAnswerWithTheirData(t *testing.T) {
	c := requireSharedClient(t)
	clid := c.ClientID()
	me, err := c.GetClientInfo(t.Context(), clid)
	requireNoErr(t, err)
	uid := me["client_unique_identifier"]
	dbid, err := strconv.ParseUint(me["client_database_id"], 10, 64)
	requireNoErr(t, err)
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
	defaultGroup, err := strconv.ParseUint(info["virtualserver_default_server_group"], 10, 64)
	requireNoErr(t, err)

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
	t.Cleanup(func() { _ = c.MoveClient(context.WithoutCancel(t.Context()), c.ClientID(), before, "") })

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

	upload, err := c.InitFileUpload(t.Context(), cid, path, uint64(len(payload)), "", true)
	requireNoErr(t, err)
	if upload.FileTransferKey == "" {
		t.Fatal("upload negotiated without a key")
	}
	requireNoErr(t, teamspeak.UploadFileData(host, upload, bytes.NewReader(payload), nil))
	t.Cleanup(func() { _ = c.DeleteFile(context.WithoutCancel(t.Context()), cid, []string{path}, "") })

	files, err := c.ListFiles(t.Context(), cid, "/", "")
	requireNoErr(t, err)
	if !slices.ContainsFunc(files, func(f teamspeak.FileEntry) bool { return "/"+f.Name == path }) {
		t.Errorf("ListFiles = %v, want %s", files, path)
	}

	download, err := c.InitFileDownload(t.Context(), cid, path, "", 0)
	requireNoErr(t, err)
	var got bytes.Buffer
	requireNoErr(t, teamspeak.DownloadFileData(host, download, &got, nil))
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("downloaded %q, want %q", got.Bytes(), payload)
	}
}
