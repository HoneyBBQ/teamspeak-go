//go:build integration

package client_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
)

func TestIntegration_ListChannelsExposesOrder(t *testing.T) {
	c := requireSharedClient(t)

	channels, err := c.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	orders := make(map[teamspeak.ChannelID]struct{}, len(channels))
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
	// repeats the previous row, so a second client in the same channel
	// arrives with no ctid at all. The shared client and the peer, in the same
	// channel, produce exactly that batch in the welcome of a client joining
	// after them, so the observer's handler is registered before it connects.
	addr := requireTeamSpeakAddr(t)
	requireSharedClient(t)
	requireIntegrationPeer(t, addr)

	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	observer := newClient(t, id, addr, "teamspeak-go-observer", integrationClientOptions(nil)...)
	var mu sync.Mutex
	seen := make(map[string]teamspeak.ChannelID)
	welcomed := make(chan struct{})
	observer.OnClientEnter(func(info client.ClientEnterEvent) {
		mu.Lock()
		defer mu.Unlock()
		seen[info.Nickname] = info.ChannelID
		_, shared := seen["teamspeak-go-integ"]
		_, peer := seen["teamspeak-go-peer"]
		if shared && peer {
			select {
			case <-welcomed:
			default:
				close(welcomed)
			}
		}
	})
	err = connectWithRetries(t.Context(), t, observer)
	if err != nil {
		t.Fatalf("observer Connect: %v", err)
	}
	t.Cleanup(func() { _ = observer.Disconnect(context.Background()) })

	select {
	case <-welcomed:
	case <-time.After(10 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("the observer's welcome did not show both clients: %v", seen)
	}

	mu.Lock()
	shared, peerCid := seen["teamspeak-go-integ"], seen["teamspeak-go-peer"]
	mu.Unlock()
	t.Logf("batched enter: shared cid=%d peer cid=%d", shared, peerCid)
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

	channels, err := c.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	var target teamspeak.ChannelID
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
	hideErr := c.MoveClient(t.Context(), c.ClientID(), target, teamspeak.ClientMoveOptions{Password: password})
	if hideErr != nil {
		t.Fatalf("ClientMove into %q with the channel password: %v", channel, hideErr)
	}

	// Cleanup runs in LIFO order at the end of this test, so the client is back
	// in its original channel before the next test starts.
	t.Cleanup(func() {
		moveErr := c.MoveClient(context.WithoutCancel(t.Context()), c.ClientID(), origin, teamspeak.ClientMoveOptions{})
		if moveErr != nil {
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

	got := make(chan client.VoiceDataEvent, 1)
	listener.OnVoiceData(func(vd client.VoiceDataEvent) {
		select {
		case got <- vd:
		default:
		}
	})
	time.Sleep(500 * time.Millisecond)

	frame := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for range 12 {
		targets := client.WhisperTargets{Clients: []teamspeak.ClientID{listener.ClientID()}}
		sendErr := sender.SendWhisper(frame, targets, teamspeak.CodecOpusMusic)
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

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	// While TeamSpeak 6 is under protection (the integration job always is, and
	// it was measured to answer a wrong password in 30 ms there), it now and
	// then leaves a handshake unanswered after its key exchange, whatever
	// the password: one to three of the suite's 35 connects per run in the CI logs. Such an attempt
	// ends on the caller's deadline with no word from the server, and is tried
	// again on a new client. Only an answer counts: the rejection is still what
	// each attempt has to end in, and a client that is never answered, three
	// times, fails the test.
	const attempts = 3
	var (
		rejected     *client.Client
		disconnected chan error
	)
	for attempt := 1; ; attempt++ {
		rejected = newClient(t,
			id, addr, "teamspeak-go-bad-password",
			client.WithServerPassword("definitely-not-the-password"),
		)
		disconnected = make(chan error, 1)
		rejected.OnDisconnected(func(e client.DisconnectedEvent) { disconnected <- e.Err })
		t.Cleanup(func() { _ = rejected.Disconnect(context.Background()) })

		// Paced before the deadline starts: waiting for the server's budget is
		// not part of what the 8 seconds measure.
		requireNoErr(t, paceConnect(t.Context()))
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		err = rejected.Connect(ctx)
		unanswered := errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil
		cancel()
		if !unanswered || attempt == attempts {
			break
		}
		t.Logf("attempt %d of %d: no answer from the server within 8s", attempt, attempts)
	}
	// The cause must be the server's rejection, not the caller's own timeout.
	if !errors.Is(err, errcode.ServerInvalidPassword) {
		t.Fatalf("Connect = %v, want the server's password rejection", err)
	}
	if rejected.Status() != client.StatusDisconnected {
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
	if caps.Family != client.ServerFamilyTS3 && caps.Family != client.ServerFamilyTS6 {
		t.Errorf("Family = %q, want ts3 or ts6", caps.Family)
	}
	want := identity.UIDSHA1
	if caps.Family == client.ServerFamilyTS6 {
		want = identity.UIDSHA256
	}
	if caps.UIDAlgorithm != want {
		t.Errorf("UIDAlgorithm = %q, want %q for family %q", caps.UIDAlgorithm, want, caps.Family)
	}
	// Every virtual server has a name; initserver carries it.
	if caps.Name == "" {
		t.Error("expected the virtual server's name from initserver")
	}
	t.Logf("server info: name=%q icon=%d banner=%q welcome=%q",
		caps.Name, caps.IconID, caps.HostBannerImageURL, caps.WelcomeMessage)
}
