package teamspeak

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Avatars and icons.
//
// Both are files in channel 0's file area. The client package moves the bytes
// (UploadAvatar, UploadIcon and their downloads); what is here names the files
// and runs the commands that point a record at an icon.

// avatarLetters spells a nibble: 'a' for 0 up to 'p' for 15.
const avatarLetters = "abcdefghijklmnop"

// ErrInvalidUID is wrapped by the error AvatarFileName returns for a unique
// identifier that is not base64.
var ErrInvalidUID = errors.New("invalid unique identifier")

// AvatarFileName is the name the server stores a client's avatar under in
// channel 0's file area, without a leading slash: "avatar_" followed by the
// client's unique identifier spelled in the letters a to p.
//
// The unique identifier is base64 of a hash of the client's public key, 20
// bytes (SHA-1) on TeamSpeak 3 and 32 bytes (SHA-256) on TeamSpeak 6. Each
// byte becomes two letters, high nibble first, each nibble 'a' plus its value,
// so the name carries 40 letters on TeamSpeak 3 and 64 on TeamSpeak 6. It is
// the value the server reports as client_base64HashClientUID.
//
// It is never the MD5 name an avatar is uploaded under (/avatar_<md5>):
// downloading by that name fails with error 2051 on TeamSpeak 6 and 2054 on
// TeamSpeak 3. An error is returned for a uid that is not base64.
func AvatarFileName(uid UID) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(string(uid))
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("%w: %q is not base64", ErrInvalidUID, string(uid))
	}

	name := make([]byte, 0, len("avatar_")+2*len(raw))
	name = append(name, "avatar_"...)
	for _, b := range raw {
		name = append(name, avatarLetters[b>>4], avatarLetters[b&15])
	}

	return string(name), nil
}

// RemoveAvatar deletes this connection's own avatar (ftdeletefile cid=0
// name=/avatar_), which, as measured on both servers, deletes the caller's
// stored avatar file and empties client_flag_avatar. Deleting the file by its
// stored name was refused with 1540, and TeamSpeak 6's clientavatardeleted
// (given cluid) answered OK without removing it; this is the removal that
// worked. It reports whether an
// avatar was removed; false means there was none (error 2054).
func (c *Commands) RemoveAvatar(ctx context.Context) (bool, error) {
	err := c.DeleteFile(ctx, 0, []string{"/avatar_"}, FileOptions{})
	if errors.Is(err, errcode.FileInvalidPath) {
		return false, nil
	}

	return err == nil, err
}

// IconIDOf is the id an icon is known by: the CRC-32 of its bytes, the
// standard one (IEEE polynomial, as in hash/crc32).
//
// The SDK names an icon this way so that the same image always gets the same
// id, and uploading it twice reuses one file. The server accepts any number as
// the id in /icon_<id> and does not check it against the bytes. The id set on
// a channel, group, client or server (i_icon_id, virtualserver_icon_id) is
// stored exactly as given and names the file /icon_<id>, so an icon uploaded
// under another scheme works as long as the id set matches its file name.
// Whether other clients use this CRC-32 as well is not something the SDK can
// promise.
func IconIDOf(data []byte) IconID {
	return IconID(crc32.ChecksumIEEE(data))
}

// IconFileName is the name an icon is uploaded and downloaded under in
// channel 0, with a leading slash: /icon_<id>. A listing of channel 0's /icons
// directory shows it as icon_<id>.
func IconFileName(id IconID) string {
	return "/icon_" + strconv.FormatUint(uint64(id), 10)
}

// RemoveIcon deletes an icon's file (ftdeletefile cid=0 name=/icon_<id>).
// Needs b_icon_manage. A record that still names the icon keeps naming it.
func (c *Commands) RemoveIcon(ctx context.Context, id IconID) error {
	return c.DeleteFile(ctx, 0, []string{IconFileName(id)}, FileOptions{})
}

var iconPermission = PermissionByName("i_icon_id")

// iconPermissionValue is the id as the signed 32-bit value the server stores.
func iconPermissionValue(id IconID) int32 {
	return int32(id) //nolint:gosec // a CRC-32 reinterpreted, as the server does
}

// SetChannelIcon gives a channel an icon, or takes it away with 0
// (channeladdperm or channeldelperm with i_icon_id). channeledit cannot do
// this: both servers answer channel_icon_id with error 1538. The new id shows
// in the channel's IconID.
func (c *Commands) SetChannelIcon(ctx context.Context, cid ChannelID, icon IconID) error {
	if icon == 0 {
		return c.DeleteChannelPermission(ctx, cid, iconPermission)
	}

	return c.AddChannelPermission(ctx, cid, iconPermission, iconPermissionValue(icon))
}

// SetServerGroupIcon gives a server group an icon, or takes it away with 0
// (i_icon_id).
func (c *Commands) SetServerGroupIcon(ctx context.Context, sgid ServerGroupID, icon IconID) error {
	if icon == 0 {
		return c.DeleteServerGroupPermission(ctx, sgid, iconPermission)
	}

	return c.AddServerGroupPermission(ctx, sgid, iconPermission, iconPermissionValue(icon),
		ServerGroupPermissionOptions{})
}

// SetChannelGroupIcon gives a channel group an icon, or takes it away with 0
// (i_icon_id).
func (c *Commands) SetChannelGroupIcon(ctx context.Context, cgid ChannelGroupID, icon IconID) error {
	if icon == 0 {
		return c.DeleteChannelGroupPermission(ctx, cgid, iconPermission)
	}

	return c.AddChannelGroupPermission(ctx, cgid, iconPermission, iconPermissionValue(icon))
}

// SetClientIcon gives a client an icon, or takes it away with 0 (i_icon_id on
// the client's database record). clientedit documents client_icon_id, but both
// servers answer it with error 1538.
func (c *Commands) SetClientIcon(ctx context.Context, cldbid ClientDBID, icon IconID) error {
	if icon == 0 {
		return c.DeleteClientPermission(ctx, cldbid, iconPermission)
	}

	return c.AddClientPermission(ctx, cldbid, iconPermission, iconPermissionValue(icon),
		ClientPermissionOptions{})
}

// SetServerIcon gives the virtual server an icon, or takes it away with 0
// (serveredit virtualserver_icon_id). Needs b_virtualserver_modify_icon_id.
func (c *Commands) SetServerIcon(ctx context.Context, icon IconID) error {
	return c.EditServer(ctx, Properties{"virtualserver_icon_id": strconv.FormatUint(uint64(icon), 10)})
}
