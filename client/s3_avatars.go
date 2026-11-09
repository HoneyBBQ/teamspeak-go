package client

import (
	"context"
	"crypto/md5" //nolint:gosec // the avatar's flag on the wire is its MD5, not a security use
	"encoding/hex"
	"errors"
	"net/http"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// Avatars and icons on a TeamSpeak 6 server with S3 file transfer: the S3
// transfers behind them, in channel 0's S3 file area.
//
// Measured on TeamSpeak 6 6.0.0-beta13.1. In channel 0 the server signs an
// upload only for a name that starts with avatar_ or icon_, and keeps the file
// under the name it is given: unlike the classic upload, which the server
// stores under the uploader's teamspeak.AvatarFileName whatever it was asked,
// an avatar here has to be uploaded under that name for others to find it. The
// classic avatars and icons are a separate store: one uploaded one way is not
// found the other.

// s3Download is the bytes at path in channel 0, and false when the storage has
// no file there (its 404).
func (c *Client) s3Download(ctx context.Context, path string, opts S3TransferOptions) ([]byte, bool, error) {
	data, err := c.DownloadS3File(ctx, 0, path, DownloadS3FileOptions{Transfer: opts})
	var failure *S3TransferError
	if errors.As(err, &failure) && failure.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	return data, true, nil
}

// ownAvatarPath is the path of this client's avatar in channel 0. Its own uid
// is the base64 of a hash, which AvatarFileName always takes.
func (c *Client) ownAvatarPath() string {
	name, _ := teamspeak.AvatarFileName(c.UID())

	return "/" + name
}

// UploadS3Avatar uploads data as this client's avatar over S3 and sets
// client_flag_avatar to its MD5, so that other clients see the change in a
// ClientUpdatedEvent. It returns the MD5, lower-case hex.
//
// On the wire: an upload signed for /<teamspeak.AvatarFileName(uid)> in channel
// 0, the bytes to the storage, the server told the upload is done, then
// clientupdate client_flag_avatar=<md5>. An avatar already there is replaced.
//
// The size limit is the permission i_client_max_avatar_filesize, 200000 bytes
// by default; over it, the signing is refused with 2049 (invalid file
// permissions) and nothing is sent or changed. A file of exactly the limit
// passes.
func (c *Client) UploadS3Avatar(ctx context.Context, data []byte, opts S3TransferOptions) (string, error) {
	sum := md5.Sum(data) //nolint:gosec // see the import
	digest := hex.EncodeToString(sum[:])
	err := c.UploadS3File(ctx, 0, c.ownAvatarPath(), data, UploadS3FileOptions{Transfer: opts})
	if err != nil {
		return "", err
	}
	err = c.UpdateClient(ctx, teamspeak.ClientUpdateOptions{Avatar: &digest})
	if err != nil {
		return "", err
	}

	return digest, nil
}

// DownloadS3Avatar returns the S3 avatar of the client with this unique
// identifier. The bool is false when the storage has none for it (a download of
// /<teamspeak.AvatarFileName(uid)> in channel 0, answered 404).
func (c *Client) DownloadS3Avatar(
	ctx context.Context, uid teamspeak.UID, opts S3TransferOptions,
) ([]byte, bool, error) {
	name, err := teamspeak.AvatarFileName(uid)
	if err != nil {
		return nil, false, err
	}

	return c.s3Download(ctx, "/"+name, opts)
}

// RemoveS3Avatar removes this client's own S3 avatar: it deletes
// /<teamspeak.AvatarFileName(uid)> in channel 0, then empties
// client_flag_avatar, which the delete leaves as it was. A client may delete
// its own avatar only: another's is refused with 2568. It succeeds whether or
// not there was an avatar, as the storage's delete does. It takes no transfer
// options: a delete goes through the server, not to the storage.
func (c *Client) RemoveS3Avatar(ctx context.Context) error {
	err := c.DeleteS3File(ctx, 0, c.ownAvatarPath(), S3FileOptions{})
	if err != nil {
		return err
	}
	empty := ""

	return c.UpdateClient(ctx, teamspeak.ClientUpdateOptions{Avatar: &empty})
}

// UploadS3Icon uploads data as an icon over S3 and returns its id, the CRC-32 of
// the bytes (teamspeak.IconIDOf): an upload signed for /icon_<id> in channel 0,
// the bytes to the storage, and the server told the upload is done. Pass the id
// to SetChannelIcon, SetServerGroupIcon, SetChannelGroupIcon, SetClientIcon or
// SetServerIcon.
//
// Needs b_icon_manage, and the size limit is i_max_icon_filesize, 8192 bytes
// for a Server Admin: without the one, or over the other, the signing is
// refused with 2049 (invalid file permissions).
func (c *Client) UploadS3Icon(ctx context.Context, data []byte, opts S3TransferOptions) (teamspeak.IconID, error) {
	id := teamspeak.IconIDOf(data)
	err := c.UploadS3File(ctx, 0, teamspeak.IconFileName(id), data, UploadS3FileOptions{Transfer: opts})
	if err != nil {
		return 0, err
	}

	return id, nil
}

// DownloadS3Icon returns an S3 icon's bytes. The bool is false when the storage
// has no file for the id.
func (c *Client) DownloadS3Icon(
	ctx context.Context, id teamspeak.IconID, opts S3TransferOptions,
) ([]byte, bool, error) {
	return c.s3Download(ctx, teamspeak.IconFileName(id), opts)
}

// DeleteS3Icon deletes an S3 icon's file (/icon_<id> in channel 0). Needs
// b_icon_manage (2568 without it). A channel, group or client that still names
// the icon keeps the id; deleting a file that is not there succeeds. It takes
// no transfer options, as RemoveS3Avatar.
func (c *Client) DeleteS3Icon(ctx context.Context, id teamspeak.IconID) error {
	return c.DeleteS3File(ctx, 0, teamspeak.IconFileName(id), S3FileOptions{})
}
