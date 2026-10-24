//go:build integration

// The X5 experiment's scaffolding, not library code: it favours readable
// measurement over the style limits.

//nolint:funlen,govet,intrange,lll,prealloc,thelper,unparam
package client_test

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// Experiment X5: what TeamSpeak 3 and 6 do to voice packets, as seen through
// the experimental voice receiver. Each test is one case of the plan (T1 to
// T10); the numbers are in the test names. The tests assert what must hold for
// the measurement to mean anything and log what they measure.

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

// x5CrossCheck compares what the receiver reported with what the tap saw
// come off the wire: the same count, in the same order, the same ids, and the
// same encryption flag.
func x5CrossCheck(t *testing.T, l *x5Log, p *x5Peer) {
	t.Helper()
	recs := p.tap.records()
	var kept []x5TapRec
	for _, r := range recs {
		if !r.Drop {
			kept = append(kept, r)
		}
	}
	pkts := p.packets()
	if len(kept) != len(pkts) {
		l.Printf("cross-check: tap saw %d datagrams, receiver %d packets (dropped by the client: %d)", len(kept), len(pkts), len(kept)-len(pkts))
	}
	mismatch := 0
	for i := 0; i < min(len(kept), len(pkts)); i++ {
		if kept[i].ID != pkts[i].PacketID || (kept[i].Flags&0x80 == 0) != pkts[i].Encrypted || (kept[i].Type == 1) != pkts[i].Whisper {
			mismatch++
		}
	}
	l.Printf("cross-check: %d of %d compared packets disagree between tap and receiver", mismatch, min(len(kept), len(pkts)))
	if mismatch != 0 {
		t.Errorf("receiver and tap disagree on %d packets", mismatch)
	}
}

func x5Tapflags(l *x5Log, label string, p *x5Peer) {
	flags := map[string]int{}
	for _, r := range p.tap.records() {
		flags[fmt.Sprintf("type=%d flags=0x%02x", r.Type, r.Flags)]++
	}
	l.Printf("%s tap datagrams by (type, header flags): %v", label, flags)
}

// T1: is the voice packet id the sender's, per speaker, and the same for every
// listener?
func TestIntegration_X5_T1_VoicePacketIDPerSpeaker(t *testing.T) {
	l := newX5Log(t)
	a, b, c := x5Connect(t, "x5t1-a"), x5Connect(t, "x5t1-b"), x5Connect(t, "x5t1-c")

	// Seven frames first, so that the sender's own counter is 7 when the
	// numbered frames start: an id that is the sender's carries that offset.
	x5Send(t, 7, 60000, x5Interval, x5Voice(a))
	x5Settle()
	b.reset()
	c.reset()
	const n = 200
	x5Send(t, n, 0, x5Interval, x5Voice(a))
	x5Settle()

	for name, p := range map[string]*x5Peer{"B": b, "C": c} {
		pkts := p.packets()
		if len(pkts) == 0 {
			t.Fatalf("%s heard nothing", name)
		}
		l.Printf("%s (A sent 7 warm-up frames, then %d): %s", name, n, x5Summary(pkts))
		x5Dump(l, name, pkts)
		x5CrossCheck(t, l, p)
		if p.eventCount() == 0 {
			t.Errorf("OnVoiceData delivered nothing to %s", name)
		}
	}
	// The same frame at B and at C: same Seq? same PacketID?
	byFrame := func(p *x5Peer) map[int]x5Pkt {
		m := map[int]x5Pkt{}
		for _, v := range p.packets() {
			m[v.Frame] = v
		}

		return m
	}
	bm, cm := byFrame(b), byFrame(c)
	sameSeq, samePID, both := 0, 0, 0
	for f, bp := range bm {
		if cp, ok := cm[f]; ok {
			both++
			if cp.Seq == bp.Seq {
				sameSeq++
			}
			if cp.PacketID == bp.PacketID {
				samePID++
			}
		}
	}
	l.Printf("frames heard by both B and C: %d; same Seq: %d; same PacketID: %d", both, sameSeq, samePID)
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

// T4: Voice, then Whisper, then Voice again: what the ids do at the switches.
func TestIntegration_X5_T4_VoiceWhisperSwitch(t *testing.T) {
	l := newX5Log(t)
	a, b, c := x5Connect(t, "x5t4-a"), x5Connect(t, "x5t4-b"), x5Connect(t, "x5t4-c")
	targets := client.WhisperTargets{Clients: []teamspeak.ClientID{b.c.ClientID()}}
	x5Send(t, 20, 0, x5Interval, x5Voice(a))
	x5Send(t, 20, 20, x5Interval, a.sendWhisper(targets))
	x5Send(t, 20, 40, x5Interval, x5Voice(a))
	x5Settle()
	for name, p := range map[string]*x5Peer{"B (whisper target)": b, "C (bystander)": c} {
		pkts := p.packets()
		l.Printf("%s: %d packets", name, len(pkts))
		for k, s := range x5Streams(pkts) {
			l.Printf("  stream %s: %s", k, x5Summary(s))
		}
		x5Dump(l, name, pkts)
		x5CrossCheck(t, l, p)
	}
	whisperAtB := 0
	for _, p := range b.packets() {
		if p.Whisper {
			whisperAtB++
			if p.Frame < 20 || p.Frame >= 40 {
				t.Errorf("a whisper packet carries frame %d", p.Frame)
			}
		}
	}
	if whisperAtB == 0 {
		t.Error("B heard no whisper")
	}
	for _, p := range c.packets() {
		if p.Whisper {
			t.Errorf("the bystander heard a whisper: %s", p)
		}
	}
}

// T5: the packet type and header flags of whispers of each form.
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

// T6: end of speech.
func TestIntegration_X5_T6_EndOfSpeech(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t6-a"), x5Connect(t, "x5t6-b")
	send := func(d []byte) { requireNoErr(t, a.c.SendVoice(d, teamspeak.CodecOpusVoice, client.VoiceOptions{})) }
	x5Send(t, 10, 0, x5Interval, x5Voice(a))
	send(nil)
	time.Sleep(time.Second)
	x5Send(t, 5, 100, x5Interval, x5Voice(a))
	send([]byte{0x00}) // one byte: what does the server make of it?
	time.Sleep(200 * time.Millisecond)
	send(nil)
	time.Sleep(200 * time.Millisecond)
	send(nil) // a second empty frame in a row
	x5Settle()
	pkts := b.packets()
	ends := 0
	for _, p := range pkts {
		if p.Len <= 1 {
			ends++
		}
	}
	l.Printf("B heard %d packets, %d with len(Data)<=1: %s", len(pkts), ends, x5Summary(pkts))
	x5Dump(l, "B", pkts)
	if ends == 0 {
		t.Error("no end-of-speech packet arrived")
	}
	for i, p := range pkts {
		if p.Len <= 1 && i > 0 {
			l.Printf("end packet #%d: seq=%d is previous+%d", i, p.Seq, (int(p.Seq)-int(pkts[i-1].Seq))&0xffff)
		}
	}
}

// T7: the 16-bit wrap, reached by seeding the sender's counter. The servers
// drop a sender's voice whose id is far ahead of the one they expect (a seed
// straight to 65490 delivered nothing until the id wrapped to 0), so the
// counter is walked up in steps, and each step records whether the server
// still forwards.
func TestIntegration_X5_T7_Wraparound(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t7-a"), x5Connect(t, "x5t7-b")
	frame := 0
	probe := func(seed uint16, n int) int {
		a.c.SeedVoiceCounterForTest(false, seed, 0)
		b.reset()
		x5Send(t, n, frame, x5Interval, x5Voice(a))
		frame += n
		time.Sleep(400 * time.Millisecond)

		return len(b.packets())
	}
	// Walk up: from the first accepted packet the server expects ids after it.
	got := probe(0, 3)
	l.Printf("seed 0, 3 frames: B heard %d", got)
	for _, seed := range []uint16{100, 1000, 5000, 10000, 20000, 30000, 40000, 50000, 60000, 65000} {
		got = probe(seed, 3)
		l.Printf("seed %d (jump from the previous probe), 3 frames: B heard %d", seed, got)
	}
	a.c.SeedVoiceCounterForTest(false, 65520, 0)
	b.reset()
	x5Send(t, 100, 1000, x5Interval, x5Voice(a))
	x5Settle()
	pkts := b.packets()
	l.Printf("seed 65520 then 100 frames across the wrap; B: %s", x5Summary(pkts))
	x5Dump(l, "B", pkts)
	if len(pkts) < 90 {
		t.Errorf("B heard only %d of 100 frames across the wrap", len(pkts))
	}
	x5CrossCheck(t, l, b)
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
	// Gaps in Seq and PacketID, and what happens at each wrap.
	seqGaps, pidGaps, genChanges, wraps := 0, 0, 0, 0
	for i := 1; i < len(pkts); i++ {
		if (int(pkts[i].Seq)-int(pkts[i-1].Seq))&0xffff != 1 {
			seqGaps++
			if seqGaps <= 20 {
				l.raw("seq gap before packet %d: %d -> %d (frames %d -> %d)", i, pkts[i-1].Seq, pkts[i].Seq, pkts[i-1].Frame, pkts[i].Frame)
			}
		}
		if (int(pkts[i].PacketID)-int(pkts[i-1].PacketID))&0xffff != 1 {
			pidGaps++
		}
		if pkts[i].Gen != pkts[i-1].Gen {
			genChanges++
			l.Printf("generation %d -> %d at packet %d (pid %d -> %d, seq %d -> %d)", pkts[i-1].Gen, pkts[i].Gen, i,
				pkts[i-1].PacketID, pkts[i].PacketID, pkts[i-1].Seq, pkts[i].Seq)
		}
		if pkts[i].PacketID < pkts[i-1].PacketID && pkts[i-1].PacketID > 60000 {
			wraps++
		}
	}
	l.Printf("Seq discontinuities %d, PacketID discontinuities %d, PacketID wraps %d, generation changes %d; %s",
		seqGaps, pidGaps, wraps, genChanges, x5Summary(pkts))
	if len(pkts) < n*9/10 {
		t.Errorf("B received only %d of %d frames", len(pkts), n)
	}
	x5CrossCheck(t, l, b)
}

// T8: codec switches inside one speech.
func TestIntegration_X5_T8_CodecSwitch(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t8-a"), x5Connect(t, "x5t8-b")
	segments := []teamspeak.Codec{
		teamspeak.CodecOpusVoice, teamspeak.CodecOpusMusic, teamspeak.CodecOpusVoice,
		teamspeak.CodecSpeexNarrowband, teamspeak.CodecCELTMono, teamspeak.CodecOpusVoice,
	}
	for i, codec := range segments {
		x5Send(t, 10, i*10, x5Interval, a.sendVoice(codec))
	}
	x5Settle()
	pkts := b.packets()
	l.Printf("B heard %d/60: %s", len(pkts), x5Summary(pkts))
	x5Dump(l, "B", pkts)
	got := map[int]teamspeak.Codec{}
	for _, p := range pkts {
		got[p.Frame] = p.Codec
	}
	for i, codec := range segments {
		for f := i * 10; f < i*10+10; f++ {
			if c, ok := got[f]; ok && c != codec {
				t.Errorf("frame %d sent as codec %d arrived as %d", f, codec, c)
			}
		}
	}
	if len(pkts) < 20 {
		t.Errorf("B heard only %d frames", len(pkts))
	}
}

// T9: Seq makes loss and reordering visible; the receiver neither hides nor
// repairs either.
func TestIntegration_X5_T9_LossAndReorder(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t9-a"), x5Connect(t, "x5t9-b")
	x5Send(t, 5, 900, x5Interval, x5Voice(a))
	x5Settle()
	b.reset()
	b.tap.mu.Lock()
	b.tap.dropOrd = map[int]bool{10: true, 11: true, 30: true, 50: true, 51: true, 52: true}
	b.tap.swapOrd, b.tap.swapOn = 70, true
	b.tap.mu.Unlock()
	x5Send(t, 100, 0, x5Interval, x5Voice(a))
	x5Settle()
	pkts := b.packets()
	l.Printf("tap dropped ordinals 10,11,30,50,51,52 and held back 70 until 71 had been delivered; B: %s", x5Summary(pkts))
	x5Dump(l, "B", pkts)
	frames := map[int]bool{}
	for _, p := range pkts {
		frames[p.Frame] = true
	}
	var missing []int
	for f := range 100 {
		if !frames[f] {
			missing = append(missing, f)
		}
	}
	l.Printf("frames missing at B: %v", missing)
	if !slices.Equal(missing, []int{10, 11, 30, 50, 51, 52}) {
		t.Errorf("missing frames %v, want exactly the dropped ones", missing)
	}
	// The same holes as the Seq of the survivors shows, with no knowledge of
	// the frame numbers.
	holes := 0
	for i := 1; i < len(pkts); i++ {
		step := (int(pkts[i].Seq) - int(pkts[i-1].Seq)) & 0xffff
		if step > 1 && step < 0x8000 {
			holes += step - 1
		}
	}
	l.Printf("holes counted from Seq steps alone (forward steps only): %d", holes)
	idx := slices.IndexFunc(pkts, func(p x5Pkt) bool { return p.Frame == 71 })
	if idx < 0 || idx+1 >= len(pkts) || pkts[idx+1].Frame != 70 {
		t.Errorf("frame 71 should be delivered right before frame 70 (held back)")
	} else {
		l.Printf("reordering seen: seq %d delivered before seq %d", pkts[idx].Seq, pkts[idx+1].Seq)
	}
}

// T10: arrival timestamps, and what a synchronous receiver does to the rest.
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
	l.Printf("receiver call minus ReceivedAt (queue wait in the process loop): %s", x5Durations(dispatch))
	l.Printf("ReceivedAt minus the sender's send time (same host, loopback; one-way delay): %s", x5Durations(oneWay))
	l.Printf("inter-arrival gaps (sender pace 20ms): %s", x5Durations(gaps))
	x5CrossCheck(t, l, b)
	if b.eventCount() == 0 {
		t.Error("OnVoiceData stopped working with a receiver set")
	}
	l.Printf("receiver packets %d, OnVoiceData events %d", len(pkts), b.eventCount())

	// A receiver that takes 30 ms per packet while packets arrive every 20 ms:
	// the synchronous call is on the receive path, so everything behind it waits.
	b.reset()
	b.mu.Lock()
	b.onPacket = func(x5Pkt) { time.Sleep(30 * time.Millisecond) }
	b.mu.Unlock()
	x5Send(t, 100, 0, x5Interval, x5Voice(a))
	started := time.Now()
	_, err := b.c.GetServerInfo(t.Context())
	l.Printf("while the slow receiver (30 ms/packet) is behind: a command round trip took %s (err=%v)", time.Since(started), err)
	time.Sleep(3500 * time.Millisecond) // 100 packets x 30 ms
	b.mu.Lock()
	b.onPacket = nil
	b.mu.Unlock()
	slow := b.packets()
	var lag []time.Duration
	for _, p := range slow {
		lag = append(lag, p.Dispatch.Sub(p.At))
	}
	l.Printf("slow receiver: %d packets, receiver call minus ReceivedAt: %s", len(slow), x5Durations(lag))
	for i := 1; i < len(slow); i++ {
		if slow[i].At.Before(slow[i-1].At) {
			t.Fatalf("ReceivedAt went backwards under a slow receiver")
		}
	}
}

// T10b: a slow OnVoiceData handler costs events, never the receiver's packets.
func TestIntegration_X5_T10_SlowEventHandlerDoesNotDelayReceiver(t *testing.T) {
	l := newX5Log(t)
	a, b := x5Connect(t, "x5t10b-a"), x5Connect(t, "x5t10b-b")
	slowDone := make(chan struct{})
	b.c.OnVoiceData(func(client.VoiceDataEvent) {
		select {
		case <-slowDone:
		case <-time.After(100 * time.Millisecond):
		}
	})
	b.reset()
	x5Send(t, 400, 0, x5Interval, x5Voice(a))
	time.Sleep(300 * time.Millisecond)
	events := b.eventCount()
	pkts := b.packets()
	close(slowDone)
	var lag []time.Duration
	for _, p := range pkts {
		lag = append(lag, p.Dispatch.Sub(p.At))
	}
	l.Printf("400 frames, OnVoiceData handler 100 ms each: receiver got %d, counting handler saw %d; receiver call minus ReceivedAt: %s",
		len(pkts), events, x5Durations(lag))
	if len(pkts) < 390 {
		t.Errorf("the receiver got %d of 400", len(pkts))
	}
}

// T1b: two speakers at once. If the outer id were the sender's it would
// interleave two sequences at the listener; if it were the server's own it
// would count the listener's packets whoever sent them.
func TestIntegration_X5_T1b_TwoSpeakers(t *testing.T) {
	l := newX5Log(t)
	a, d, b := x5Connect(t, "x5t1b-a"), x5Connect(t, "x5t1b-d"), x5Connect(t, "x5t1b-b")
	// Different warm-ups, so the two senders' counters differ.
	x5Send(t, 3, 60000, x5Interval, x5Voice(a))
	x5Send(t, 11, 60000, x5Interval, x5Voice(d))
	x5Settle()
	b.reset()
	done := make(chan struct{})
	go func() {
		defer close(done)
		x5Send(t, 150, 0, x5Interval, x5Voice(d))
	}()
	x5Send(t, 150, 0, x5Interval, x5Voice(a))
	<-done
	x5Settle()
	pkts := b.packets()
	for k, s := range x5Streams(pkts) {
		l.Printf("stream %s: %s", k, x5Summary(s))
	}
	l.Printf("all packets in arrival order: %s", x5Summary(pkts))
	x5Dump(l, "B", pkts)
	x5CrossCheck(t, l, b)
	if len(pkts) < 280 {
		t.Errorf("B heard %d of 300", len(pkts))
	}
}
