//go:build integration && integration_voice

// Scaffolding of live measurements: it favours readable output over the style
// limits.

//nolint:govet,lll
package client_test

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// What the server relays, measured on TeamSpeak 3 (3.13.8) and TeamSpeak 6
// (6.0.0-beta13.1): which voice and whispers reach a listener, and which
// clients it is shown. A speaker S and a listener L are two voice clients;
// whatever a test changes on the server it restores when the test ends, so a
// failed assertion leaves it clean.

const relayFrames = 20

// relayCount sends relayFrames frames from s, 20 ms apart, as voice or as a
// whisper to l, and returns how many packets l's receiver got from s with the
// matching whisper flag.
func relayCount(t *testing.T, s, l *x5Peer, whisper bool) int {
	t.Helper()
	l.reset()
	send := s.sendVoice(teamspeak.CodecOpusVoice)
	if whisper {
		send = s.sendWhisper(client.WhisperTargets{Clients: []teamspeak.ClientID{l.c.ClientID()}})
	}
	x5Send(t, relayFrames, 0, x5Interval, send)
	time.Sleep(500 * time.Millisecond)

	return len(vrFrom(l.packets(), s.c.ClientID(), whisper))
}

// relayHeard is relayCount for a check that wants packets: it tries up to
// three times, since a state change the server has answered may take a moment
// to reach its relay. A check that wants none counts once: no packet is the
// state to hold, and a retry would only hide one that got through.
func relayHeard(t *testing.T, s, l *x5Peer, whisper bool) int {
	t.Helper()
	got := 0
	for attempt := 1; attempt <= 3; attempt++ {
		got = relayCount(t, s, l, whisper)
		if got > 0 {
			if attempt > 1 {
				t.Logf("relayed on attempt %d", attempt)
			}

			return got
		}
		time.Sleep(500 * time.Millisecond)
	}

	return got
}

// relayExpect counts both kinds of packet and checks each against want.
func relayExpect(t *testing.T, what string, s, l *x5Peer, wantVoice, wantWhisper bool) {
	t.Helper()
	for _, whisper := range []bool{false, true} {
		want := wantVoice
		kind := "voice"
		if whisper {
			want, kind = wantWhisper, "whisper"
		}
		var got int
		if want {
			got = relayHeard(t, s, l, whisper)
		} else {
			got = relayCount(t, s, l, whisper)
		}
		switch {
		case want && got == 0:
			t.Errorf("%s: no %s was relayed, want some", what, kind)
		case !want && got != 0:
			t.Errorf("%s: %d %s packets were relayed, want 0", what, got, kind)
		}
	}
}

// relayState applies set to p's own client state and returns a function that
// applies reset and reports a failure to; reset also runs when the test ends,
// if it has not run.
func relayState(t *testing.T, p *x5Peer, set, reset teamspeak.ClientUpdateOptions) func() {
	t.Helper()
	done := false
	apply := func() error {
		if done {
			return nil
		}
		done = true
		ctx, cancel := cleanupContext()
		defer cancel()
		err := p.c.UpdateClient(ctx, reset)
		time.Sleep(300 * time.Millisecond)

		return err
	}
	t.Cleanup(func() { _ = apply() })
	restore := func() {
		err := apply()
		if err != nil {
			t.Errorf("resetting the client state: %v", err)
		}
	}
	requireNoErr(t, p.c.UpdateClient(t.Context(), set))
	time.Sleep(300 * time.Millisecond)

	return restore
}

// relayChannel creates a temporary channel, deleted when the test ends.
func relayChannel(t *testing.T, admin *serverquery.Client, neededTalkPower *int32) teamspeak.ChannelID {
	t.Helper()
	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name:            fmt.Sprintf("relay-%d", time.Now().UnixNano()%1e9),
		NeededTalkPower: neededTalkPower,
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})

	return cid
}

// relayMove moves p into cid and moves it back to where it was when the test
// ends. Register it after the channel's creation: cleanups run in reverse.
func relayMove(t *testing.T, p *x5Peer, cid teamspeak.ChannelID) {
	t.Helper()
	origin := p.c.ChannelID()
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = p.c.MoveClient(ctx, p.c.ClientID(), origin, teamspeak.ClientMoveOptions{})
	})
	requireNoErr(t, p.c.MoveClient(t.Context(), p.c.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	time.Sleep(500 * time.Millisecond)
}

func relayPair(t *testing.T, name string) (*x5Peer, *x5Peer) {
	t.Helper()
	s, l := x5Connect(t, name+"-s"), x5Connect(t, name+"-l")
	relayWaitKnown(t, s, l)

	return s, l
}

func relayWaitKnown(t *testing.T, s, l *x5Peer) {
	t.Helper()
	if s.c.ChannelID() != l.c.ChannelID() {
		t.Skipf("the speaker is in channel %d and the listener in %d: they need the same channel", s.c.ChannelID(), l.c.ChannelID())
	}
	// The listener must know the speaker, or nothing it hears can be told from it.
	known := false
	for deadline := time.Now().Add(liveEventWait); !known && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, known = l.c.View().Client(s.c.ClientID())
	}
	if !known {
		t.Fatalf("the listener (id %d, channel %d, %s) does not know the speaker (id %d, channel %d, %s) after %s",
			l.c.ClientID(), l.c.ChannelID(), l.c.Status(), s.c.ClientID(), s.c.ChannelID(), s.c.Status(), liveEventWait)
	}
	time.Sleep(500 * time.Millisecond)
}

func TestIntegration_VoiceRelay_DefaultRelaysVoiceAndWhispers(t *testing.T) {
	s, l := relayPair(t, "relay-default")
	relayExpect(t, "same channel, no state set", s, l, true, true)
}

func TestIntegration_VoiceRelay_SpeakerStateStopsIt(t *testing.T) {
	s, l := relayPair(t, "relay-spk")
	yes, no := true, false
	for _, tc := range []struct {
		name       string
		set, reset teamspeak.ClientUpdateOptions
	}{
		{"away", teamspeak.ClientUpdateOptions{IsAway: &yes}, teamspeak.ClientUpdateOptions{IsAway: &no}},
		{"input muted", teamspeak.ClientUpdateOptions{IsInputMuted: &yes}, teamspeak.ClientUpdateOptions{IsInputMuted: &no}},
		{"no input hardware", teamspeak.ClientUpdateOptions{HasInputHardware: &no}, teamspeak.ClientUpdateOptions{HasInputHardware: &yes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := relayState(t, s, tc.set, tc.reset)
			relayExpect(t, "speaker "+tc.name, s, l, false, false)
			restore()
			if got := relayHeard(t, s, l, false); got == 0 {
				t.Errorf("after the reset no voice was relayed")
			}
		})
	}
}

func TestIntegration_VoiceRelay_ListenerStateStopsIt(t *testing.T) {
	s, l := relayPair(t, "relay-lst")
	yes, no := true, false
	for _, tc := range []struct {
		name       string
		set, reset teamspeak.ClientUpdateOptions
		stops      bool
	}{
		{"output muted", teamspeak.ClientUpdateOptions{IsOutputMuted: &yes}, teamspeak.ClientUpdateOptions{IsOutputMuted: &no}, true},
		{"no output hardware", teamspeak.ClientUpdateOptions{HasOutputHardware: &no}, teamspeak.ClientUpdateOptions{HasOutputHardware: &yes}, true},
		{"away", teamspeak.ClientUpdateOptions{IsAway: &yes}, teamspeak.ClientUpdateOptions{IsAway: &no}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := relayState(t, l, tc.set, tc.reset)
			if tc.stops {
				relayExpect(t, "listener "+tc.name, s, l, false, false)
			} else if got := relayHeard(t, s, l, false); got == 0 {
				t.Errorf("listener %s: no voice was relayed, want some", tc.name)
			}
			restore()
		})
	}
}

func TestIntegration_VoiceRelay_TalkPower(t *testing.T) {
	admin := requireAdmin(t)
	s, l := relayPair(t, "relay-tp")
	need := int32(50)
	cid := relayChannel(t, admin, &need)
	relayMove(t, s, cid)
	relayMove(t, l, cid)
	dbid := dbIDOf(t, s.c, s.c)

	if got := relayCount(t, s, l, false); got != 0 {
		t.Errorf("without talk power %d voice packets were relayed, want 0", got)
	}
	if got := relayHeard(t, s, l, true); got == 0 {
		t.Errorf("without talk power no whisper was relayed, want some: a whisper needs none")
	}

	priority := teamspeak.PermissionByName(perm.ClientIsPrioritySpeaker)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeleteClientPermission(ctx, dbid, priority)
	})
	requireNoErr(t, admin.AddClientPermission(t.Context(), dbid, priority, 1, teamspeak.ClientPermissionOptions{}))
	time.Sleep(500 * time.Millisecond)
	if got := relayCount(t, s, l, false); got != 0 {
		t.Errorf("as priority speaker %d voice packets were relayed, want 0: it grants no talk power", got)
	}
	requireNoErr(t, admin.DeleteClientPermission(t.Context(), dbid, priority))

	talker, notTalker := true, false
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.EditClient(ctx, s.c.ClientID(), teamspeak.ClientEditOptions{IsTalker: &notTalker})
	})
	requireNoErr(t, admin.EditClient(t.Context(), s.c.ClientID(), teamspeak.ClientEditOptions{IsTalker: &talker}))
	time.Sleep(500 * time.Millisecond)
	if got := relayHeard(t, s, l, false); got == 0 {
		t.Errorf("as talker no voice was relayed, want some")
	}
	requireNoErr(t, admin.EditClient(t.Context(), s.c.ClientID(), teamspeak.ClientEditOptions{IsTalker: &notTalker}))
}

func TestIntegration_VoiceRelay_SubscriptionShowsClientsNotVoice(t *testing.T) {
	admin := requireAdmin(t)
	s, l := relayPair(t, "relay-sub")
	cid := relayChannel(t, admin, nil)
	relayMove(t, s, cid)

	requireNoErr(t, l.c.SubscribeChannel(t.Context(), cid))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = l.c.UnsubscribeChannel(ctx, cid)
	})
	deadline := time.Now().Add(liveEventWait)
	for time.Now().Before(deadline) {
		if _, ok := l.c.View().Client(s.c.ClientID()); ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, ok := l.c.View().Client(s.c.ClientID()); !ok {
		t.Fatalf("after subscribing to channel %d the listener's view does not contain the speaker", cid)
	}
	if got := relayCount(t, s, l, false); got != 0 {
		t.Errorf("%d voice packets reached a subscriber in another channel, want 0", got)
	}
}

func TestIntegration_VoiceRelay_JoiningSubscribesAndLeavingKeepsIt(t *testing.T) {
	admin := requireAdmin(t)
	_, l := relayPair(t, "relay-join")
	b := x5Connect(t, "relay-join-b")
	origin := l.c.ChannelID()
	cid := relayChannel(t, admin, nil)
	relayMove(t, b, cid)
	time.Sleep(500 * time.Millisecond)

	if _, ok := l.c.View().Client(b.c.ClientID()); ok {
		t.Fatalf("the listener, not in channel %d and not subscribed, has the client in it in its view", cid)
	}

	subscribed := listen(t, l.c.OnChannelSubscribed)
	updated := listen(t, l.c.OnClientUpdated)
	relayMove(t, l, cid)
	select {
	case e := <-subscribed:
		t.Errorf("moving into channel %d was announced as a subscription to channel %d", cid, e.ChannelID)
	case <-time.After(500 * time.Millisecond):
	}
	if _, ok := l.c.View().Client(b.c.ClientID()); !ok {
		t.Fatalf("after moving into channel %d the view does not contain the client in it", cid)
	}

	requireNoErr(t, l.c.MoveClient(t.Context(), l.c.ClientID(), origin, teamspeak.ClientMoveOptions{}))
	time.Sleep(500 * time.Millisecond)
	if _, ok := l.c.View().Client(b.c.ClientID()); !ok {
		t.Fatalf("after moving back to channel %d the view lost the client in channel %d", origin, cid)
	}

	for _, away := range []bool{true, false} {
		requireNoErr(t, b.c.UpdateClient(t.Context(), teamspeak.ClientUpdateOptions{IsAway: &away}))
		await(t, updated, fmt.Sprintf("ClientUpdatedEvent with IsAway=%t for the client in channel %d", away, cid),
			func(e client.ClientUpdatedEvent) bool {
				return e.ClientID == b.c.ClientID() && e.Changes.IsAway != nil && *e.Changes.IsAway == away
			})
	}
}

func TestIntegration_VoiceRelay_UnsubscribingTheCurrentChannelDoesNothing(t *testing.T) {
	s, l := relayPair(t, "relay-unsub")
	unsubscribed := listen(t, l.c.OnChannelUnsubscribed)

	requireNoErr(t, l.c.UnsubscribeChannel(t.Context(), l.c.ChannelID()))
	select {
	case e := <-unsubscribed:
		t.Errorf("unsubscribing the current channel announced an unsubscription from channel %d", e.ChannelID)
	case <-time.After(500 * time.Millisecond):
	}
	if _, ok := l.c.View().Client(s.c.ClientID()); !ok {
		t.Errorf("after unsubscribing the current channel the view lost the speaker")
	}
	if got := relayHeard(t, s, l, false); got == 0 {
		t.Errorf("after unsubscribing the current channel no voice was relayed, want some")
	}
}

type framePadConn struct {
	net.PacketConn

	armed  atomic.Bool
	padded atomic.Int64
}

func (c *framePadConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.armed.Load() && len(p) == 500 && p[12]&0x0f == 0 {
		padded := make([]byte, len(p)+1)
		copy(padded, p)
		_, err := c.PacketConn.WriteTo(padded, addr)
		if err != nil {
			return 0, err
		}
		c.padded.Add(1)

		return len(p), nil
	}

	return c.PacketConn.WriteTo(p, addr)
}

func relaySendFrames(t *testing.T, frame []byte, send func([]byte) error) {
	t.Helper()
	next := time.Now()
	for range relayFrames {
		requireNoErr(t, send(frame))
		next = next.Add(x5Interval)
		time.Sleep(time.Until(next))
	}
}

func relayHeardLen(t *testing.T, l *x5Peer, speaker teamspeak.ClientID, whisper bool, wantLen int, send func() error) int {
	t.Helper()
	for attempt := 1; attempt <= 3; attempt++ {
		l.reset()
		requireNoErr(t, send())
		time.Sleep(500 * time.Millisecond)
		got := 0
		for _, p := range vrFrom(l.packets(), speaker, whisper) {
			if p.Len == wantLen {
				got++
			}
		}
		if got > 0 {
			if attempt > 1 {
				t.Logf("relayed len=%d on attempt %d", wantLen, attempt)
			}

			return got
		}
		time.Sleep(500 * time.Millisecond)
	}

	return 0
}

func assertServerDropsPaddedVoice(t *testing.T, s, l *x5Peer, pad *framePadConn, frame484 []byte) {
	t.Helper()
	l.reset()
	pad.armed.Store(true)
	t.Cleanup(func() { pad.armed.Store(false) })
	relaySendFrames(t, frame484, func(b []byte) error {
		return s.c.SendVoice(b, teamspeak.CodecOpusVoice, client.VoiceOptions{})
	})
	pad.armed.Store(false)
	time.Sleep(500 * time.Millisecond)
	if got := pad.padded.Load(); got != relayFrames {
		t.Errorf("padded %d voice datagrams, want %d", got, relayFrames)
	}
	if got := len(vrFrom(l.packets(), s.c.ClientID(), false)); got != 0 {
		t.Errorf("485-byte wire voice frame relayed %d packets, want 0", got)
	}
}

func TestIntegration_VoiceRelay_FrameSize(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	requireNoErr(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	pad := &framePadConn{PacketConn: pc}

	s := x5ConnectWith(t, "relay-frame-s", false, client.WithPacketConn(pad))
	l := x5Connect(t, "relay-frame-l")
	relayWaitKnown(t, s, l)

	frame484 := make([]byte, client.MaxVoiceFrameSize)
	send484 := func() error {
		relaySendFrames(t, frame484, func(b []byte) error {
			return s.c.SendVoice(b, teamspeak.CodecOpusVoice, client.VoiceOptions{})
		})

		return s.c.SendVoice(nil, teamspeak.CodecOpusVoice, client.VoiceOptions{})
	}
	if got := relayHeardLen(t, l, s.c.ClientID(), false, client.MaxVoiceFrameSize, send484); got == 0 {
		t.Errorf("484-byte voice frame was not relayed, want some")
	}

	err = s.c.SendVoice(make([]byte, client.MaxVoiceFrameSize+1), teamspeak.CodecOpusVoice, client.VoiceOptions{})
	if !errors.Is(err, client.ErrVoiceFrameTooLarge) {
		t.Errorf("485-byte SendVoice err = %v, want ErrVoiceFrameTooLarge", err)
	}

	// Pad 500-byte voice datagrams to 501 bytes on the wire (485-byte frame): the server drops them without an error.
	assertServerDropsPaddedVoice(t, s, l, pad, frame484)

	frame600 := make([]byte, 600)
	if got := relayHeardLen(t, l, s.c.ClientID(), true, 600, func() error {
		relaySendFrames(t, frame600, func(b []byte) error {
			return s.c.SendWhisper(b, client.WhisperTargets{Clients: []teamspeak.ClientID{l.c.ClientID()}}, teamspeak.CodecOpusVoice)
		})

		return nil
	}); got == 0 {
		t.Errorf("600-byte direct whisper was not relayed, want some")
	}

	if got := relayHeardLen(t, l, s.c.ClientID(), true, 600, func() error {
		relaySendFrames(t, frame600, func(b []byte) error {
			return s.c.SendGroupWhisper(b, client.WhisperToAllClients(client.GroupWhisperAllChannels), teamspeak.CodecOpusVoice)
		})

		return nil
	}); got == 0 {
		t.Errorf("600-byte group whisper was not relayed, want some")
	}
}
