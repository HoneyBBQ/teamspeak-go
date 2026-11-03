//go:build integration && integration_voice

// The X5 measurements: what TeamSpeak 3 and 6 do to voice packets, as seen
// through the voice receiver. Scaffolding, not library code: it favours
// readable measurement over the style limits.

//nolint:funlen,govet,lll,prealloc,thelper,unparam
package client_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// Each test is one case of the plan (T1 to T10, numbered in the names); they
// run only with X5=1. The cases that keep the receiver's contract, and run
// every time, are in voice_receiver_integration_test.go. These assert what
// must hold for the measurement to mean anything and log what they measure.

const x5Interval = 20 * time.Millisecond

func x5Voice(p *x5Peer) func(int, []byte) error {
	return func(_ int, d []byte) error { return p.c.SendVoice(d, teamspeak.CodecOpusVoice, client.VoiceOptions{}) }
}

func (p *x5Peer) sendVoice(codec teamspeak.Codec) func(int, []byte) error {
	return func(_ int, d []byte) error { return p.c.SendVoice(d, codec, client.VoiceOptions{}) }
}

func (p *x5Peer) sendWhisper(targets client.WhisperTargets) func(int, []byte) error {
	return func(_ int, d []byte) error { return p.c.SendWhisper(d, targets, teamspeak.CodecOpusVoice) }
}

// x5Room makes a temporary channel with the given codec_is_unencrypted flag and
// moves the peers into it.
func x5Room(t *testing.T, admin *serverquery.Client, unencrypted bool, peers ...*x5Peer) teamspeak.ChannelID {
	t.Helper()
	cid, err := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{
		Name:          fmt.Sprintf("x5-room-%d", time.Now().UnixNano()%1e9),
		IsUnencrypted: &unencrypted,
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		for _, p := range peers {
			_ = p.c.MoveClient(ctx, p.c.ClientID(), 1, teamspeak.ClientMoveOptions{})
		}
		_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
	})
	for _, p := range peers {
		requireNoErr(t, p.c.MoveClient(t.Context(), p.c.ClientID(), cid, teamspeak.ClientMoveOptions{}))
	}
	info, err := admin.GetChannelInfo(t.Context(), cid)
	requireNoErr(t, err)
	t.Logf("channel %d reads back codec_is_unencrypted=%v", cid, info.IsUnencrypted != nil && *info.IsUnencrypted)
	time.Sleep(700 * time.Millisecond)

	return cid
}

// x5ServerMode sets virtualserver_codec_encryption_mode, restored afterwards.
func x5ServerMode(t *testing.T, admin *serverquery.Client, mode string) {
	t.Helper()
	info, err := admin.GetServerInfo(t.Context())
	requireNoErr(t, err)
	old := info["virtualserver_codec_encryption_mode"]
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.EditServer(ctx, teamspeak.Properties{"virtualserver_codec_encryption_mode": old})
	})
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{"virtualserver_codec_encryption_mode": mode}))
	after, err := admin.GetServerInfo(t.Context())
	requireNoErr(t, err)
	t.Logf("server mode was %q, set to %q, reads back %q", old, mode, after["virtualserver_codec_encryption_mode"])
	if after["virtualserver_codec_encryption_mode"] != mode {
		t.Fatalf("the server did not take the mode")
	}
}

// x5CrossCheck compares what the receiver gave with what the tap saw come off
// the wire: the same number of packets, and as many of them whispers.
func x5CrossCheck(t *testing.T, l *x5Log, p *x5Peer) {
	t.Helper()
	var kept, whispers int
	for _, r := range p.tap.records() {
		if r.Drop {
			continue
		}
		kept++
		if r.Type == 1 {
			whispers++
		}
	}
	pkts := p.packets()
	var got int
	for _, v := range pkts {
		if v.Whisper {
			got++
		}
	}
	l.Printf("cross-check: tap saw %d datagrams (%d whispers), receiver %d packets (%d whispers)", kept, whispers, len(pkts), got)
	if kept != len(pkts) || whispers != got {
		t.Errorf("receiver and tap disagree: %d/%d datagrams, %d/%d whispers", len(pkts), kept, got, whispers)
	}
}

func x5Tapflags(l *x5Log, label string, p *x5Peer) {
	flags := map[string]int{}
	for _, r := range p.tap.records() {
		flags[fmt.Sprintf("type=%d flags=0x%02x", r.Type, r.Flags)]++
	}
	l.Printf("%s tap datagrams by (type, header flags): %v", label, flags)
}

// x5EncryptionCase is one server configuration of T2 and T3.
type x5EncryptionCase struct {
	name        string
	mode        string
	unencrypted bool
}

var x5EncryptionCases = []x5EncryptionCase{
	{"mode0_channel_unencrypted", "0", true},
	{"mode0_channel_encrypted", "0", false},
	{"mode1_forced_off", "1", false},
	{"mode2_forced_on", "2", true},
}

func x5EncryptionMatrix(t *testing.T, sendEncrypted bool) {
	admin := requireAdmin(t)
	l := newX5Log(t)
	for _, tc := range x5EncryptionCases {
		t.Run(tc.name, func(t *testing.T) {
			x5ServerMode(t, admin, tc.mode)
			// Connected after the mode is set: the server's welcome tells
			// them the mode.
			a, b := x5Connect(t, "x5enc-a"), x5Connect(t, "x5enc-b")
			x5Room(t, admin, tc.unencrypted, a, b)
			b.reset()
			x5Send(t, 40, 0, x5Interval, x5Voice(a))
			x5Settle()
			plain := b.packets()
			l.Printf("[%s] A sends UNENCRYPTED (the SDK's path): B received %d/40; %s", tc.name, len(plain), x5Summary(plain))
			x5Tapflags(l, "["+tc.name+"] B", b)
			x5CrossCheck(t, l, b)
			for _, p := range plain {
				if p.Frame < 0 || p.Frame >= 40 {
					t.Errorf("payload corrupted: %s", p)
				}
			}
			if !sendEncrypted {
				return
			}
			b.reset()
			x5Send(t, 40, 1000, x5Interval, func(_ int, d []byte) error {
				return a.c.SendVoiceEncryptedForTest(d, teamspeak.CodecOpusVoice)
			})
			x5Settle()
			enc := b.packets()
			l.Printf("[%s] A sends ENCRYPTED: B received %d/40; %s", tc.name, len(enc), x5Summary(enc))
			x5Tapflags(l, "["+tc.name+"] B", b)
			for _, p := range enc {
				if p.Frame < 1000 || p.Frame >= 1040 {
					t.Errorf("payload corrupted: %s", p)
				}
			}
		})
	}
}

// T2: do S2C voice packets arrive encrypted, and does the SDK deliver the same
// payload either way?
func TestIntegration_X5_T2_S2CEncryption(t *testing.T) { x5EncryptionMatrix(t, false) }

// T3: does a forced-encryption server drop unencrypted C2S voice, and what
// happens to voice the sender encrypts?
func TestIntegration_X5_T3_ForcedEncryptionDropsPlainVoice(t *testing.T) { x5EncryptionMatrix(t, true) }

// T2 also: switching the mode while the clients are connected.
func TestIntegration_X5_T2_LiveModeSwitch(t *testing.T) {
	admin := requireAdmin(t)
	l := newX5Log(t)
	a, b := x5Connect(t, "x5sw-a"), x5Connect(t, "x5sw-b")
	x5Room(t, admin, true, a, b)
	for _, mode := range []string{"0", "2", "1", "0"} {
		x5ServerMode(t, admin, mode)
		time.Sleep(time.Second)
		b.reset()
		x5Send(t, 25, 0, x5Interval, x5Voice(a))
		x5Settle()
		l.Printf("live switch to mode %s, channel unencrypted: plain from A: B received %d/25; %s", mode, len(b.packets()), x5Summary(b.packets()))
		x5Tapflags(l, "B", b)
		b.reset()
		x5Send(t, 25, 1000, x5Interval, func(_ int, d []byte) error {
			return a.c.SendVoiceEncryptedForTest(d, teamspeak.CodecOpusVoice)
		})
		x5Settle()
		l.Printf("live switch to mode %s: encrypted from A: B received %d/25; %s", mode, len(b.packets()), x5Summary(b.packets()))
	}
}

func TestIntegration_X5_T5_WhisperPacketForms(t *testing.T) {
	admin := requireAdmin(t)
	l := newX5Log(t)
	a, b, c := x5Connect(t, "x5t5-a"), x5Connect(t, "x5t5-b"), x5Connect(t, "x5t5-c")

	sgid := guestCopy(t, admin, "x5-sg")
	dbB := dbIDOf(t, a.c, b.c)
	requireNoErr(t, admin.AddClientToServerGroup(t.Context(), sgid, dbB))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.RemoveClientFromServerGroup(ctx, sgid, dbB)
	})
	cgid := channelGroupCopy(t, admin, "x5-cg")
	requireNoErr(t, admin.SetClientChannelGroup(t.Context(), cgid, b.c.ChannelID(), dbB))
	time.Sleep(600 * time.Millisecond)

	cases := []struct {
		name string
		send func(int, []byte) error
	}{
		{"direct/clients=[B]", a.sendWhisper(client.WhisperTargets{Clients: []teamspeak.ClientID{b.c.ClientID()}})},
		{"direct/channels=[B's channel]", a.sendWhisper(client.WhisperTargets{Channels: []teamspeak.ChannelID{b.c.ChannelID()}})},
		{"group/server-group", func(_ int, d []byte) error {
			return a.c.SendGroupWhisper(d, client.WhisperToServerGroup(client.GroupWhisperAllChannels, sgid), teamspeak.CodecOpusVoice)
		}},
		{"group/channel-group", func(_ int, d []byte) error {
			return a.c.SendGroupWhisper(d, client.WhisperToChannelGroup(client.GroupWhisperAllChannels, cgid), teamspeak.CodecOpusVoice)
		}},
		{"group/all-clients/current-channel", func(_ int, d []byte) error {
			return a.c.SendGroupWhisper(d, client.WhisperToAllClients(client.GroupWhisperCurrentChannel), teamspeak.CodecOpusVoice)
		}},
		{"group/channel-commanders/current-channel", func(_ int, d []byte) error {
			return a.c.SendGroupWhisper(d, client.WhisperToChannelCommanders(client.GroupWhisperCurrentChannel), teamspeak.CodecOpusVoice)
		}},
	}
	for _, tc := range cases {
		b.reset()
		c.reset()
		x5Send(t, 10, 0, x5Interval, tc.send)
		x5Settle()
		for name, p := range map[string]*x5Peer{"B(target)": b, "C(bystander)": c} {
			pkts := p.packets()
			l.Printf("[%s] %s heard %d/10; %s", tc.name, name, len(pkts), x5Summary(pkts))
			x5Tapflags(l, "["+tc.name+"] "+name, p)
			for _, r := range p.tap.records() {
				l.raw("[%s] %s tap type=%d flags=0x%02x id=%d datagram=%d", tc.name, name, r.Type, r.Flags, r.ID, r.Len)
			}
			for _, v := range pkts {
				if !v.Whisper {
					t.Errorf("[%s] %s: a whisper arrived as Voice: %s", tc.name, name, v)
				}
				if v.Len != 5 {
					t.Errorf("[%s] %s: frame length %d, want 5 (layout differs from Voice)", tc.name, name, v.Len)
				}
			}
		}
		if len(b.packets()) == 0 && tc.name != "group/channel-commanders/current-channel" {
			t.Errorf("[%s] the target heard nothing", tc.name)
		}
	}
}

// T7 in full: more than 65536 frames, so that the server's own counter for the
// listener wraps too. Opt in with X5_WRAP_FULL=1: it takes about 100 seconds.
func TestIntegration_X5_T7_WraparoundFull(t *testing.T) {
	if os.Getenv("X5_WRAP_FULL") == "" {
		t.Skip("set X5_WRAP_FULL=1 to send 65700 frames")
	}
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t7f-a"), x5Connect(t, "x5t7f-b")
	const n = 65536 + 200
	for i := range n {
		if os.Getenv("X5_WRAP_ENCRYPTED") != "" {
			requireNoErr(t, a.c.SendVoiceEncryptedForTest(x5Frame(i), teamspeak.CodecOpusVoice))
		} else {
			requireNoErr(t, a.c.SendVoice(x5Frame(i), teamspeak.CodecOpusVoice, client.VoiceOptions{}))
		}
		time.Sleep(1100 * time.Microsecond)
	}
	x5Settle()
	pkts := b.packets()
	l.Printf("sent %d frames at ~1 kHz; B received %d (%d lost)", n, len(pkts), n-len(pkts))
	seqGaps, wraps := 0, 0
	for i := 1; i < len(pkts); i++ {
		if (int(pkts[i].Seq)-int(pkts[i-1].Seq))&0xffff != 1 {
			seqGaps++
			if seqGaps <= 20 {
				l.raw("seq gap before packet %d: %d -> %d (frames %d -> %d)", i, pkts[i-1].Seq, pkts[i].Seq, pkts[i-1].Frame, pkts[i].Frame)
			}
		}
		if pkts[i].Seq < pkts[i-1].Seq && pkts[i-1].Seq > 65000 {
			wraps++
		}
	}
	l.Printf("Seq discontinuities %d, Seq wraps %d; %s", seqGaps, wraps, x5Summary(pkts))
	if len(pkts) < n*9/10 {
		t.Errorf("B received only %d of %d frames", len(pkts), n)
	}
	x5CrossCheck(t, l, b)
}

// T10: arrival timestamps.
func TestIntegration_X5_T10_Timestamps(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t10-a"), x5Connect(t, "x5t10-b")
	x5Send(t, 5, 900, x5Interval, x5Voice(a))
	x5Settle()
	b.reset()
	sent := x5Send(t, 300, 0, x5Interval, x5Voice(a))
	x5Settle()
	pkts := b.packets()
	if len(pkts) < 290 {
		t.Fatalf("B heard %d of 300", len(pkts))
	}
	for i := 1; i < len(pkts); i++ {
		if pkts[i].At.Before(pkts[i-1].At) {
			t.Fatalf("ReceivedAt went backwards at packet %d", i)
		}
	}
	recs := b.tap.records()
	var readPath, dispatch, oneWay, gaps []time.Duration
	for i, p := range pkts {
		if i < len(recs) {
			readPath = append(readPath, p.At.Sub(recs[i].At))
		}
		dispatch = append(dispatch, p.Dispatch.Sub(p.At))
		if p.Frame >= 0 && p.Frame < len(sent) {
			oneWay = append(oneWay, p.At.Sub(sent[p.Frame]))
		}
		if i > 0 {
			gaps = append(gaps, p.At.Sub(pkts[i-1].At))
		}
	}
	l.Printf("ReceivedAt minus the tap's own timestamp of the same datagram (adapter + channel hop): %s", x5Durations(readPath))
	l.Printf("read return minus ReceivedAt (time in the receiver's buffer): %s", x5Durations(dispatch))
	l.Printf("ReceivedAt minus the sender's send time (same host, loopback; one-way delay): %s", x5Durations(oneWay))
	l.Printf("inter-arrival gaps (sender pace 20ms): %s", x5Durations(gaps))
	x5CrossCheck(t, l, b)
	l.Printf("receiver packets %d", len(pkts))
}
