//go:build integration

package teamspeak_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

func TestIntegration_ListChannelsExposesOrder(t *testing.T) {
	c := requireSharedClient(t)

	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	orders := make(map[uint64]struct{}, len(channels))
	for _, ch := range channels {
		orders[ch.Order] = struct{}{}
	}
	t.Logf("channel orders: %d distinct across %d channels", len(orders), len(channels))
	// The default channel is order 0; a server with more than one channel must
	// not report the same order for all of them, which is what happened when
	// channel_order was parsed and discarded.
	if len(channels) > 1 && len(orders) < 2 {
		t.Errorf("expected distinct channel orders, all %d were %v", len(channels), orders)
	}
}

func TestIntegration_ChannelIDReportsOwnChannel(t *testing.T) {
	c := requireSharedClient(t)

	select {
	case info := <-sharedClientEnter:
		if got := c.ChannelID(); got != info.ChannelID {
			t.Errorf("ChannelID() = %d, want %d from our own clientEnter", got, info.ChannelID)
		} else {
			t.Logf("ChannelID() = %d", got)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for clientEnter")
	}
}

func TestIntegration_BatchedEnterInheritsOmittedFields(t *testing.T) {
	// TeamSpeak omits, in each row of a pipe-separated batch, any field that
	// repeats the previous row, so a second client joining the same channel
	// arrives with no ctid at all. The shared client plus the peer in the same
	// channel produce exactly that batch for a newly subscribing observer.
	addr := requireTeamSpeakAddr(t)
	requireSharedClient(t)
	peer := requireIntegrationPeer(t, addr)
	if peer == nil {
		t.Fatal("peer unavailable")
	}

	// Reuse the peer as the observer: TS3 only tolerates about three rapid
	// connections per IP, and the suite already spends them on the shared
	// client, the peer and the disconnect test.
	requireSharedClient(t)
	observer := requireIntegrationPeer(t, addr)

	seen := make(map[string]uint64)
	observer.OnClientEnter(func(info teamspeak.ClientInfo) {
		seen[info.Nickname] = info.ChannelID
	})
	time.Sleep(2 * time.Second)

	shared, okShared := seen["teamspeak-go-integ"]
	peerCid, okPeer := seen["teamspeak-go-peer"]
	t.Logf("batched enter: shared cid=%d (seen=%t) peer cid=%d (seen=%t)", shared, okShared, peerCid, okPeer)

	if !okShared || !okPeer {
		t.Skipf("observer did not see both clients yet: %v", seen)
	}
	if shared == 0 {
		t.Error("expected a non-zero channel ID for the first row of the batch")
	}
	if peerCid != shared {
		t.Errorf("second row reported cid=%d, want %d (inherited from the first row)", peerCid, shared)
	}
}

func TestIntegration_ClientMoveIntoPasswordProtectedChannel(t *testing.T) {
	// Opt-in: needs a password-protected channel the bot cannot bypass.
	channel := os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL")
	password := os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD")
	if channel == "" || password == "" {
		t.Skip("TEAMSPEAK_PASSWORD_CHANNEL/_PASSWORD not set")
	}

	c := requireSharedClient(t)

	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	var target uint64
	for _, ch := range channels {
		if ch.Name == channel {
			target = ch.ID
		}
	}
	if target == 0 {
		t.Fatalf("channel %q not found", channel)
	}

	// The shared client is reused across the whole suite, so leaving it in the
	// password channel made every later test that asserts on its channel depend
	// on run order.
	origin := c.ChannelID()
	if origin == 0 {
		t.Fatal("shared client has no channel to return to")
	}

	// A plain-text password is rejected with error 781; the digest is required.
	hideErr := c.MoveClient(t.Context(), c.ClientID(), target, password)
	if hideErr != nil {
		t.Fatalf("ClientMove into %q with the channel password: %v", channel, hideErr)
	}

	// Cleanup runs in LIFO order at the end of this test, so the client is back
	// in its original channel before the next test starts.
	t.Cleanup(func() {
		if moveErr := c.MoveClient(context.WithoutCancel(t.Context()), c.ClientID(), origin, ""); moveErr != nil {
			t.Errorf("moving back to channel %d: %v", origin, moveErr)
		}
	})
}

func TestIntegration_SendWhisperReachesAnotherChannel(t *testing.T) {
	// Whisper bypasses channel routing, so a listener in another channel proves
	// the frame is correct: ordinary voice would not reach it. Needs
	// i_client_whisper_power on the bot's server group.
	addr := requireTeamSpeakAddr(t)
	sender := requireSharedClient(t)
	// Reuse the peer as the listener to stay within the connection budget.
	listener := requireIntegrationPeer(t, addr)

	got := make(chan teamspeak.VoiceData, 1)
	listener.OnVoiceData(func(vd teamspeak.VoiceData) {
		select {
		case got <- vd:
		default:
		}
	})
	time.Sleep(500 * time.Millisecond)

	frame := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for range 12 {
		sendErr := sender.SendWhisper(frame, []uint16{listener.ClientID()}, 5)
		if sendErr != nil {
			t.Fatalf("SendWhisper: %v", sendErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case vd := <-got:
		t.Logf("whisper received: speaker=%d codec=%d bytes=%d", vd.ClientID, vd.Codec, len(vd.Data))
		if vd.ClientID != sender.ClientID() {
			t.Errorf("speaker = %d, want %d", vd.ClientID, sender.ClientID())
		}
		if len(vd.Data) != len(frame) {
			t.Errorf("audio = %d bytes, want %d", len(vd.Data), len(frame))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the whisper on the listener")
	}
}

func TestIntegration_ReportsHandshakeFailureAndDisconnects(t *testing.T) {
	// Opt-in: needs a server that actually has a password set.
	if os.Getenv("TEAMSPEAK_SERVER_HAS_PASSWORD") != "1" {
		t.Skip("TEAMSPEAK_SERVER_HAS_PASSWORD not set")
	}
	addr := requireTeamSpeakAddr(t)

	id, err := crypto.GenerateIdentity(8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	rejected := teamspeak.NewClient(
		id, addr, "teamspeak-go-bad-password",
		teamspeak.WithServerPassword("definitely-not-the-password"),
	)
	disconnected := make(chan error, 1)
	rejected.OnDisconnected(func(err error) { disconnected <- err })
	t.Cleanup(func() { _ = rejected.Disconnect() })

	err = rejected.Connect()
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err = rejected.WaitConnected(ctx)
	// The cause must be the server's rejection, not the caller's own timeout.
	if err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("WaitConnected = %v, want the server's password rejection", err)
	}
	if rejected.Status() != teamspeak.StatusDisconnected {
		t.Errorf("status = %v after a rejected handshake, want StatusDisconnected", rejected.Status())
	}
	select {
	case got := <-disconnected:
		if got == nil {
			t.Error("disconnected handler got a nil error for a rejected handshake")
		}
	case <-time.After(3 * time.Second):
		t.Error("disconnected handler was not called after the handshake failed")
	}
}

// Capabilities come from initserver, so they must be populated as soon as the
// handshake completes — and the reported uid hash has to be the one the server
// actually applies, not just a claim about it.
func TestIntegration_ServerCapabilities(t *testing.T) {
	c := requireSharedClient(t)

	caps := c.ServerCapabilities()
	t.Logf("capabilities: version=%q family=%q uid=%q", caps.Version, caps.Family, caps.UIDAlgorithm)

	if caps.Version == "" {
		t.Error("expected a version string from initserver")
	}
	if caps.Family != teamspeak.ServerFamilyTS3 && caps.Family != teamspeak.ServerFamilyTS6 {
		t.Errorf("Family = %q, want ts3 or ts6", caps.Family)
	}
	want := crypto.UidSha1
	if caps.Family == teamspeak.ServerFamilyTS6 {
		want = crypto.UidSha256
	}
	if caps.UIDAlgorithm != want {
		t.Errorf("UIDAlgorithm = %q, want %q for family %q", caps.UIDAlgorithm, want, caps.Family)
	}
}
