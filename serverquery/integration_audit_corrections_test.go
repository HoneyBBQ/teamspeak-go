//go:build integration

package serverquery_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/serverquery"
	"github.com/honeybbq/teamspeak-go/versions"
)

// A ban reports how many times it turned a client away.
func TestQueryAdmin_BanEnforcements(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		addr := voiceAddr(t)
		ctx := adminCtx(t)
		name := "ts-go-enf-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		id, found, err := c.AddBan(ctx, teamspeak.BanOptions{Name: name, Reason: "ts-go-it"})
		skipUnlessAllowed(t, err, "AddBan")
		if err != nil || !found {
			t.Fatalf("AddBan: %d, %t, %v", id, found, err)
		}
		cleanup(t, "ban", func(ctx context.Context) error { return c.DeleteBan(ctx, id) })

		bans, err := c.ListBans(ctx, teamspeak.BanListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if b := banByID(bans, id); b == nil || b.Enforcements != 0 {
			t.Fatalf("a new ban = %+v, want 0 enforcements", b)
		}

		ident, err := identity.Generate(ctx, 8)
		if err != nil {
			t.Fatal(err)
		}
		var failed []client.AttemptFailedInfo
		banned, err := client.New(ident, addr, name, client.WithVersion(versions.Windows_3_6_2_1695203293),
			client.WithTrace(&client.Trace{AttemptFailed: func(i client.AttemptFailedInfo) { failed = append(failed, i) }}))
		if err != nil {
			t.Fatal(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		err = banned.Connect(cctx)
		if err == nil {
			_ = banned.Disconnect(ctx)
			t.Fatal("a client with a banned nickname was let in")
		}

		bans, err = c.ListBans(ctx, teamspeak.BanListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		b := banByID(bans, id)
		if b == nil {
			t.Fatal("the ban is gone")
		}
		if len(failed) != 1 || failed[0].WaitingFor == "" {
			t.Errorf("AttemptFailed = %+v, want one with WaitingFor set", failed)
		} else {
			t.Logf("%s: refused attempt was waiting for %q (phase %v)", transport, failed[0].WaitingFor, failed[0].Phase)
		}
		t.Logf("%s: enforcements after one refused connect = %d", transport, b.Enforcements)
		if b.Enforcements == 0 {
			t.Errorf("Enforcements = 0 after the ban turned a client away")
		}
	})
}

// A temporary password names who made it.
func TestQueryAdmin_TempPasswordCreator(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		pw := "ts-go-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		err := c.AddTempPassword(ctx, teamspeak.TempPasswordOptions{
			Password: pw, Description: "ts-go-it", Duration: time.Hour,
		})
		skipUnlessAllowed(t, err, "AddTempPassword")
		if err != nil {
			t.Fatal(err)
		}
		cleanup(t, "temp password", func(ctx context.Context) error { return c.DeleteTempPassword(ctx, pw) })
		list, err := c.ListTempPasswords(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range list {
			if p.Password == pw {
				t.Logf("%s: creator %q / %q", transport, p.CreatorNickname, p.CreatorUID)
				if p.CreatorNickname == "" || p.CreatorUID == "" {
					t.Errorf("the creator is missing: %+v", p)
				}

				return
			}
		}
		t.Errorf("the new password is not listed")
	})
}

// The banner and the settings Channel reads can be written, and read back.
func TestQueryAdmin_ChannelBannerAndOptionsRoundTrip(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		url := "https://example.com/banner.png"
		mode, factor, on := int32(1), int32(3), true
		cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
			Name: "ts-go-banner-" + strconv.FormatInt(time.Now().UnixNano(), 36), BannerURL: &url, BannerMode: &mode,
		})
		skipUnlessAllowed(t, err, "CreateChannel")
		if err != nil {
			t.Fatal(err)
		}
		cleanup(t, "channel", func(ctx context.Context) error {
			return c.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		})
		ch, err := c.GetChannelInfo(ctx, cid)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: banner %q", transport, ch.BannerURL)
		if ch.BannerURL != url {
			t.Errorf("BannerURL = %q after create, want %q", ch.BannerURL, url)
		}

		other := "https://example.com/other.png"
		mode2 := int32(2)
		err = c.EditChannel(ctx, cid, teamspeak.ChannelEditOptions{
			BannerURL: &other, BannerMode: &mode2, CodecLatencyFactor: &factor,
			IsUnencrypted: &on, IsMaxClientsUnlimited: &on, IsMaxFamilyClientsUnlimited: &on,
		})
		if err != nil {
			t.Fatalf("EditChannel: %v", err)
		}
		ch, err = c.GetChannelInfo(ctx, cid)
		if err != nil {
			t.Fatal(err)
		}
		if ch.BannerURL != other || ch.BannerMode == nil || *ch.BannerMode != mode2 {
			t.Errorf("banner after edit = %q %v, want %q %d", ch.BannerURL, ch.BannerMode, other, mode2)
		}
		if ch.CodecLatencyFactor == nil || *ch.CodecLatencyFactor != factor {
			t.Errorf("CodecLatencyFactor = %v, want %d", ch.CodecLatencyFactor, factor)
		}
		for name, got := range map[string]*bool{
			"IsUnencrypted": ch.IsUnencrypted, "IsMaxClientsUnlimited": ch.IsMaxClientsUnlimited,
			"IsMaxFamilyClientsUnlimited": ch.IsMaxFamilyClientsUnlimited,
		} {
			if got == nil || !*got {
				t.Errorf("%s = %v after setting it", name, got)
			}
		}
	})
}

func voiceAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set, so no voice client can connect")
	}

	return addr
}
