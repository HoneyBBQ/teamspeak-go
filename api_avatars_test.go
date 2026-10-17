package teamspeak

import (
	"errors"
	"hash/crc32"
	"testing"
)

// Each pair is a unique id and the name the server listed for that client's
// avatar in channel 0 (also its client_base64HashClientUID).
func TestAvatarFileName(t *testing.T) {
	cases := map[string]struct{ uid, want string }{
		"TeamSpeak 3, 20 bytes": {
			"KqXRNkJgnzjGFbp0GTCPJN1ODJY=", "avatar_ckkfnbdgecgajpdimgbflkhebjdaipcenneoamjg",
		},
		"TeamSpeak 6, 32 bytes": {
			"HYqkXu981igdjfxleVv2aYOmdkdumh2pFrkTSLRHG5k=",
			"avatar_bnikkefoophmngcibninpmgfhjflpggjidkghgehgojkbnkjbgljbdeileehbljj",
		},
	}
	for name, tc := range cases {
		got, err := AvatarFileName(UID(tc.uid))
		if err != nil || got != tc.want {
			t.Errorf("%s: AvatarFileName = %q, %v, want %q", name, got, err, tc.want)
		}
	}
	for _, bad := range []UID{"", "not base64!"} {
		_, err := AvatarFileName(bad)
		if !errors.Is(err, ErrInvalidUID) {
			t.Errorf("AvatarFileName(%q) accepted it", bad)
		}
	}
}

func TestIconIDOf(t *testing.T) {
	if got := IconIDOf([]byte("123456789")); got != 0xcbf43926 {
		t.Errorf("IconIDOf(check string) = %#x, want 0xcbf43926", uint32(got))
	}
	data := []byte("\x89PNG icon data")
	if got := IconIDOf(data); uint32(got) != crc32.ChecksumIEEE(data) {
		t.Errorf("IconIDOf = %d", got)
	}
	if got := IconFileName(3009859579); got != "/icon_3009859579" {
		t.Errorf("IconFileName = %q", got)
	}
}

// The server lists icon 3009859579 as -1285107717.
func TestIconSettersSendTheSignedPermissionValue(t *testing.T) {
	cases := map[string]struct {
		run  func(c *Commands) error
		want string
	}{
		"channel": {func(c *Commands) error { return c.SetChannelIcon(t.Context(), 4, 3009859579) },
			"channeladdperm cid=4 permsid=i_icon_id permvalue=-1285107717"},
		"channel cleared": {func(c *Commands) error { return c.SetChannelIcon(t.Context(), 4, 0) },
			"channeldelperm cid=4 permsid=i_icon_id"},
		"server group": {func(c *Commands) error { return c.SetServerGroupIcon(t.Context(), 5, 3009859579) },
			"servergroupaddperm sgid=5 permsid=i_icon_id permvalue=-1285107717 permnegated=0 permskip=0"},
		"channel group": {func(c *Commands) error { return c.SetChannelGroupIcon(t.Context(), 6, 3009859579) },
			"channelgroupaddperm cgid=6 permsid=i_icon_id permvalue=-1285107717"},
		"client": {func(c *Commands) error { return c.SetClientIcon(t.Context(), 7, 3009859579) },
			"clientaddperm cldbid=7 permsid=i_icon_id permvalue=-1285107717 permskip=0"},
		"server": {func(c *Commands) error { return c.SetServerIcon(t.Context(), 3009859579) },
			"serveredit virtualserver_icon_id=3009859579"},
		"server cleared": {func(c *Commands) error { return c.SetServerIcon(t.Context(), 0) },
			"serveredit virtualserver_icon_id=0"},
		"remove icon": {func(c *Commands) error { return c.RemoveIcon(t.Context(), 5) },
			`ftdeletefile cid=0 cpw= name=\/icon_5`},
	}
	for name, tc := range cases {
		if got := encoded(t, tc.run); got != tc.want {
			t.Errorf("%s: sent %q, want %q", name, got, tc.want)
		}
	}
}
