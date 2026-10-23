//go:build integration

package client_test

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // an avatar's wire name is its MD5
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// requireServerAdmin puts the shared client in the Server Admin group for the
// test, which an icon upload needs (b_icon_manage), and takes it out again.
func requireServerAdmin(t *testing.T, p livePair) {
	t.Helper()
	admin := requireAdmin(t)
	groups, err := admin.ListServerGroups(t.Context(), teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	re := regexp.MustCompile(`(?i)server admin`)
	for _, g := range groups {
		if g.Type == teamspeak.GroupRegular && re.MatchString(g.Name) {
			requireNoErr(t, admin.AddClientToServerGroup(t.Context(), g.ID, p.subjectDBID))
			t.Cleanup(func() {
				ctx, cancel := cleanupContext()
				defer cancel()
				_ = admin.RemoveClientFromServerGroup(ctx, g.ID, p.subjectDBID)
			})

			return
		}
	}
	t.Skip("the server has no regular Server Admin group")
}

func TestLive_AvatarUploadSeenAndDownloadedByABystander(t *testing.T) {
	p := requireLivePair(t)
	requireServerAdmin(t, p)
	updated := listen(t, p.observer.OnClientUpdated)
	data := []byte(fmt.Sprintf("not really a picture %d", time.Now().UnixNano()))
	sum := md5.Sum(data) //nolint:gosec // see the import
	want := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_, _ = p.subject.RemoveAvatar(ctx)
	})

	got, err := p.subject.UploadAvatar(t.Context(), data, teamspeak.FileTransferOptions{})
	requireNoErr(t, err)
	if got != want {
		t.Fatalf("UploadAvatar = %q, want the MD5 %q", got, want)
	}
	await(t, updated, "the avatar flag in clientUpdated", func(e teamspeak.ClientUpdatedEvent) bool {
		return e.ClientID == p.subject.ClientID() && e.Changes.Avatar != nil && *e.Changes.Avatar == want
	})

	name, err := teamspeak.AvatarFileName(p.subject.UID())
	requireNoErr(t, err)
	files, err := p.subject.ListFiles(t.Context(), 0, "/", teamspeak.FileOptions{})
	requireNoErr(t, err)
	found := false
	for _, f := range files {
		found = found || f.Name == name
	}
	if !found {
		t.Errorf("channel 0 holds no %s: %v", name, files)
	}

	blob, ok, err := p.observer.DownloadAvatar(t.Context(), p.subject.UID(), teamspeak.FileTransferOptions{})
	requireNoErr(t, err)
	if !ok || !bytes.Equal(blob, data) {
		t.Fatalf("DownloadAvatar = %q, %v, want the uploaded bytes", blob, ok)
	}

	removed, err := p.subject.RemoveAvatar(t.Context())
	requireNoErr(t, err)
	if !removed {
		t.Error("RemoveAvatar found nothing to remove")
	}
	requireAvatarGone(t, p)
}

// requireAvatarGone checks the subject's avatar is absent, and that removing
// it again finds nothing.
func requireAvatarGone(t *testing.T, p livePair) {
	t.Helper()
	_, ok, err := p.observer.DownloadAvatar(t.Context(), p.subject.UID(), teamspeak.FileTransferOptions{})
	requireNoErr(t, err)
	if ok {
		t.Error("after removal DownloadAvatar still found the avatar")
	}
	removed, err := p.subject.RemoveAvatar(t.Context())
	requireNoErr(t, err)
	if removed {
		t.Error("a second RemoveAvatar removed something")
	}
}

func TestLive_AvatarOverTheSizeLimitIsRefused(t *testing.T) {
	p := requireLivePair(t)
	requireServerAdmin(t, p)
	_, err := p.subject.UploadAvatar(t.Context(), make([]byte, 200_001), teamspeak.FileTransferOptions{})
	if !errors.Is(err, errcode.PermissionInvalidSize) {
		t.Errorf("UploadAvatar over the limit = %v, want error 2565", err)
	}
}

func TestLive_IconUploadSetOnAChannelAndReadBack(t *testing.T) {
	p := requireLivePair(t)
	requireServerAdmin(t, p)
	admin := requireAdmin(t)
	data := []byte(fmt.Sprintf("\x89PNG icon %d", time.Now().UnixNano()))

	id, err := p.subject.UploadIcon(t.Context(), data, teamspeak.FileTransferOptions{})
	requireNoErr(t, err)
	if id != teamspeak.IconIDOf(data) {
		t.Fatalf("UploadIcon = %d, want %d", id, teamspeak.IconIDOf(data))
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.subject.RemoveIcon(ctx, id)
	})
	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: fmt.Sprintf("ts-go-icon-%d", time.Now().UnixNano()%1e6),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})

	requireNoErr(t, admin.SetChannelIcon(t.Context(), cid, id))
	ch, err := admin.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	if ch.IconID != id {
		t.Errorf("the channel's IconID = %d, want %d", ch.IconID, id)
	}
	blob, ok, err := p.observer.DownloadIcon(t.Context(), id, teamspeak.FileTransferOptions{})
	requireNoErr(t, err)
	if !ok || !bytes.Equal(blob, data) {
		t.Errorf("DownloadIcon = %q, %v", blob, ok)
	}
	requireNoErr(t, admin.SetChannelIcon(t.Context(), cid, 0))
	ch, err = admin.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	if ch.IconID != 0 {
		t.Errorf("after clearing, IconID = %d", ch.IconID)
	}
}

func TestLive_IconOverTheSizeLimitIsRefused(t *testing.T) {
	p := requireLivePair(t)
	requireServerAdmin(t, p)
	_, err := p.subject.UploadIcon(t.Context(), make([]byte, 8193), teamspeak.FileTransferOptions{})
	if !errors.Is(err, errcode.PermissionInvalidSize) {
		t.Errorf("UploadIcon over the limit = %v, want error 2565", err)
	}
}

// The server sends one icon id in three forms: unsigned in channelinfo, signed
// in servergrouplist, and sign-extended to 64 bits in the voice protocol's
// notifychanneledited. An id above 2^31 shows them apart.
func TestLive_IconAbove2To31ReadsTheSameThroughAnEditAndAQuery(t *testing.T) {
	p := requireLivePair(t)
	admin := requireAdmin(t)
	const id = teamspeak.IconID(3009859579)
	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name: fmt.Sprintf("ts-go-iconf-%d", time.Now().UnixNano()%1e6),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	edited := listen(t, p.observer.OnChannelEdited)

	requireNoErr(t, admin.SetChannelIcon(t.Context(), cid, id))
	e := await(t, edited, "the icon in channelEdited", func(e teamspeak.ChannelEditedEvent) bool {
		return e.ChannelID == cid && e.Changes.IconID != nil
	})
	if *e.Changes.IconID != id {
		t.Errorf("channelEdited IconID = %d, want %d", *e.Changes.IconID, id)
	}
	if ch, ok := p.observer.View().Channel(cid); !ok || ch.IconID != id {
		t.Errorf("the view's IconID = %d (held %v), want %d", ch.IconID, ok, id)
	}
	ch, err := admin.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	if ch.IconID != id {
		t.Errorf("channelinfo IconID = %d, want %d", ch.IconID, id)
	}
}
