//go:build integration

package client_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// The handler drops every command packet that claims to be unencrypted, since
// the fake signature that would authenticate it is public. A full session
// must not need one: commands answer, a text message to self arrives, and a
// file goes up and comes back down.
func TestLive_SessionNeedsNoUnencryptedCommands(t *testing.T) {
	c := requireSharedClient(t)
	addr := requireTeamSpeakAddr(t)
	host, _, err := net.SplitHostPort(addr)
	requireNoErr(t, err)

	_, err = c.GetClientInfo(t.Context(), c.ClientID())
	requireNoErr(t, err)

	text := fmt.Sprintf("encrypted-only-%d", time.Now().UnixNano())
	got := make(chan client.TextMessageEvent, 1)
	defer c.OnTextMessage(func(msg client.TextMessageEvent) {
		if msg.Message == text {
			select {
			case got <- msg:
			default:
			}
		}
	})()
	requireNoErr(t, c.SendPrivateMessage(t.Context(), c.ClientID(), text))
	awaitLive(t, got, "the text message to self")

	cid := c.ChannelID()
	path := fmt.Sprintf("/ts-go-enc-%d.bin", time.Now().UnixNano())
	payload := []byte("only encrypted commands")
	opts := teamspeak.FileUploadOptions{Overwrite: true}
	upload, err := c.InitFileUpload(t.Context(), cid, path, uint64(len(payload)), opts)
	requireNoErr(t, err)
	requireNoErr(t, teamspeak.UploadFileData(t.Context(), host, upload,
		bytes.NewReader(payload), teamspeak.FileTransferOptions{}))
	t.Cleanup(func() {
		_ = c.DeleteFile(context.WithoutCancel(t.Context()), cid, []string{path}, teamspeak.FileOptions{})
	})
	download, err := c.InitFileDownload(t.Context(), cid, path, teamspeak.FileDownloadOptions{})
	requireNoErr(t, err)
	var back bytes.Buffer
	requireNoErr(t, teamspeak.DownloadFileData(t.Context(), host, download, &back, teamspeak.FileTransferOptions{}))
	if !bytes.Equal(back.Bytes(), payload) {
		t.Errorf("downloaded %q, want %q", back.Bytes(), payload)
	}
}
