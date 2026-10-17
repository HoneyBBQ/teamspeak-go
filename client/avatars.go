package client

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the avatar's name on the wire is its MD5, not a security use
	"encoding/hex"
	"errors"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/discovery"
)

// Host is the host this client connects to, as it was given, without the
// port: where the file transfer port is, for UploadFileData and the avatar and
// icon helpers.
func (c *Client) Host() string {
	host, _ := discovery.SplitHostPortOrDefault(c.addr, "9987")

	return host
}

// upload negotiates an upload into channel 0 and sends data.
func (c *Client) upload(ctx context.Context, name string, data []byte, opts teamspeak.FileTransferOptions) error {
	info, err := c.InitFileUpload(ctx, 0, name, uint64(len(data)), teamspeak.FileUploadOptions{Overwrite: true})
	if err != nil {
		return err
	}

	return teamspeak.UploadFileData(ctx, c.Host(), info, bytes.NewReader(data), opts)
}

// download fetches a file of channel 0. The bool is false when there is no
// such file (error 2051 on TeamSpeak 6, 2054 on TeamSpeak 3).
func (c *Client) download(
	ctx context.Context, name string, opts teamspeak.FileTransferOptions,
) ([]byte, bool, error) {
	info, err := c.InitFileDownload(ctx, 0, name, teamspeak.FileDownloadOptions{})
	if errors.Is(err, errcode.FileNotFound) || errors.Is(err, errcode.FileInvalidPath) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	var buf bytes.Buffer
	err = teamspeak.DownloadFileData(ctx, c.Host(), info, &buf, opts)
	if err != nil {
		return nil, false, err
	}

	return buf.Bytes(), true, nil
}

// UploadAvatar uploads data as this client's avatar and sets
// client_flag_avatar to its MD5, so that other clients see the change in a
// ClientUpdatedEvent. It returns the MD5, lower-case hex.
//
// On the wire: ftinitupload cid=0 name=/avatar_<md5 hex> with overwrite=1, the
// bytes over the file transfer port, then clientupdate
// client_flag_avatar=<md5>. The server does not keep the file under the MD5
// name: it stores it as teamspeak.AvatarFileName of the client's unique id (20
// bytes of SHA-1 on TeamSpeak 3, 32 of SHA-256 on TeamSpeak 6).
//
// The size limit is the permission i_client_max_avatar_filesize, 200000 bytes
// for a Server Admin; over it the negotiation fails with a ServerError whose
// code is errcode.PermissionInvalidSize (2565), and nothing is sent or
// changed. A file of exactly the limit passes.
func (c *Client) UploadAvatar(ctx context.Context, data []byte, opts teamspeak.FileTransferOptions) (string, error) {
	sum := md5.Sum(data) //nolint:gosec // see the import
	digest := hex.EncodeToString(sum[:])
	err := c.upload(ctx, "/avatar_"+digest, data, opts)
	if err != nil {
		return "", err
	}
	err = c.UpdateClient(ctx, teamspeak.ClientUpdateOptions{Avatar: &digest})
	if err != nil {
		return "", err
	}

	return digest, nil
}

// DownloadAvatar returns the avatar of the client with this unique
// identifier. The bool is false when the server has none for it (ftinitdownload
// cid=0 with the name from teamspeak.AvatarFileName answers 2051 on TeamSpeak
// 6, 2054 on TeamSpeak 3). Setting the flag empty alone leaves the file in place; RemoveAvatar
// deletes it.
func (c *Client) DownloadAvatar(
	ctx context.Context, uid teamspeak.UID, opts teamspeak.FileTransferOptions,
) ([]byte, bool, error) {
	name, err := teamspeak.AvatarFileName(uid)
	if err != nil {
		return nil, false, err
	}

	return c.download(ctx, "/"+name, opts)
}

// UploadIcon uploads data as an icon and returns its id, the CRC-32 of the
// bytes (teamspeak.IconIDOf).
//
// On the wire: ftinitupload cid=0 name=/icon_<id> with overwrite=1, then the
// bytes; the server keeps it in channel 0's icons directory. The id is not
// checked by the server against the bytes, and the file does not reference
// anything by itself: pass it to SetChannelIcon, SetServerGroupIcon, SetChannelGroupIcon,
// SetClientIcon or SetServerIcon.
//
// Needs b_icon_manage (error 2568 without it). The size limit is
// i_max_icon_filesize, 8192 bytes for a Server Admin; over it the negotiation
// fails with errcode.PermissionInvalidSize (2565).
func (c *Client) UploadIcon(
	ctx context.Context, data []byte, opts teamspeak.FileTransferOptions,
) (teamspeak.IconID, error) {
	id := teamspeak.IconIDOf(data)
	err := c.upload(ctx, teamspeak.IconFileName(id), data, opts)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// DownloadIcon returns an icon's bytes. The bool is false when the server has
// no file for the id.
func (c *Client) DownloadIcon(
	ctx context.Context, id teamspeak.IconID, opts teamspeak.FileTransferOptions,
) ([]byte, bool, error) {
	return c.download(ctx, teamspeak.IconFileName(id), opts)
}
