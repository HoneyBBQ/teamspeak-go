//go:build integration && integration_voice

// Scaffolding of live measurements: it favours readable output over the style
// limits.

//nolint:cyclop,errcheck,funlen,gocognit,gocyclo,lll,maintidx,unparam
package client_test

import (
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

// The live contract of the voice receiver, on TeamSpeak 3 and 6: what the
// receiver says about each packet has to be what the servers do. Every case
// is short enough for the suite's package timeout, so they run every time; the
// long measurements behind them are the X5 tests. The cases share four
// clients (a speaks, b, c and d listen) and run in order: the ones that end
// connections come last.

const vrSettle = 600 * time.Millisecond

// vrOffsets is the set of Seq-minus-frame values of pkts: one value means the
// Seq went up in step with the frames sent, whatever it started at.
func vrOffsets(pkts []x5Pkt) []int {
	var out []int
	for _, p := range pkts {
		if p.Frame < 0 {
			continue
		}
		off := (int(p.Seq) - p.Frame) & 0xffff
		if !slices.Contains(out, off) {
			out = append(out, off)
		}
	}

	return out
}

func vrFrom(pkts []x5Pkt, speaker teamspeak.ClientID, whisper bool) []x5Pkt {
	var out []x5Pkt
	for _, p := range pkts {
		if p.Speaker == speaker && p.Whisper == whisper {
			out = append(out, p)
		}
	}

	return out
}

// vrWait waits until p has n packets, or the time is out, and a moment more.
func vrMedian(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)

	return s[len(s)/2]
}

func vrWait(p *x5Peer, n int, d time.Duration) {
	for deadline := time.Now().Add(d); len(p.packets()) < n && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
}

func vrAwaitReconnect(t *testing.T, p *x5Peer, before uint64) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if p.c.Status() == client.StatusConnected && p.c.Session() > before && p.c.ChannelID() != 0 {
			time.Sleep(500 * time.Millisecond)

			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("did not reconnect within the deadline (status=%v session=%d)", p.c.Status(), p.c.Session())
}

// vrCommands times commands of p, one every 300 ms (the client's own flood
// throttle lets four through a second), while speaker, if there is
// one, sends 100 frames; it returns when the frames are sent and heard.
func vrCommands(t *testing.T, p, speaker *x5Peer) []time.Duration {
	t.Helper()
	p.reset()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if speaker == nil {
			time.Sleep(time.Second)

			return
		}
		x5Send(t, 100, 0, x5Interval, x5Voice(speaker))
	}()
	var all []time.Duration
	for running := true; running; {
		select {
		case <-done:
			running = false
		case <-time.After(300 * time.Millisecond):
		}
		start := time.Now()
		_, err := p.c.GetServerInfo(t.Context())
		requireNoErr(t, err)
		all = append(all, time.Since(start))
	}
	if speaker != nil {
		vrWait(p, 100, 2*time.Second)
	}

	return all
}

func TestIntegration_VoiceReceiver(t *testing.T) {
	l := newVoiceLog(t)
	reconnect := client.WithReconnect(client.ReconnectOptions{
		Backoff: client.BackoffPolicy{InitialDelay: 500 * time.Millisecond, MaxDelay: 4 * time.Second, Factor: 2},
	})
	a, b, c, d := x5Connect(t, "vr-a"), x5Connect(t, "vr-b"), x5Connect(t, "vr-c"), x5Connect(t, "vr-d")

	t.Run("SeqIsTheSendersAndTheSameForEveryListener", func(t *testing.T) {
		// Seven frames first: a Seq that is the sender's carries that offset.
		x5Send(t, 7, 60000, x5Interval, x5Voice(a))
		time.Sleep(vrSettle)
		b.reset()
		c.reset()
		sent := x5Send(t, 50, 0, x5Interval, x5Voice(a))
		vrWait(b, 50, 2*time.Second)
		vrWait(c, 50, 2*time.Second)

		byFrame := map[string]map[int]x5Pkt{"b": {}, "c": {}}
		for name, p := range map[string]*x5Peer{"b": b, "c": c} {
			pkts := p.packets()
			l.Printf("%s: %s", name, x5Summary(pkts))
			if len(pkts) < 48 {
				t.Fatalf("%s heard %d of 50", name, len(pkts))
			}
			if offs := vrOffsets(pkts); len(offs) != 1 {
				t.Errorf("%s: Seq minus frame takes %v, want one value: Seq is the sender's, in step with what it sent", name, offs)
			}
			var prev time.Time
			for _, v := range pkts {
				byFrame[name][v.Frame] = v
				if v.Session != p.c.Session() || v.Speaker != a.c.ClientID() || v.Whisper || v.Codec != teamspeak.CodecOpusVoice {
					t.Errorf("%s: %s, want session %d from %d", name, v, p.c.Session(), a.c.ClientID())
				}
				if v.At.IsZero() || v.At.Before(prev) || v.At.Before(sent[v.Frame]) || v.At.After(v.Dispatch) {
					t.Errorf("%s: ReceivedAt %v is not between the send %v and the read %v, or goes back from %v", name, v.At, sent[v.Frame], v.Dispatch, prev)
				}
				prev = v.At
			}
		}
		same := 0
		for f, bp := range byFrame["b"] {
			if cp, ok := byFrame["c"][f]; ok {
				if cp.Seq != bp.Seq {
					t.Errorf("frame %d has Seq %d at b and %d at c", f, bp.Seq, cp.Seq)
				}
				same++
			}
		}
		if same < 45 {
			t.Errorf("only %d frames reached both listeners", same)
		}
	})

	t.Run("TwoSpeakersKeepTheirOwnSeq", func(t *testing.T) {
		// Different warm-ups, so the two senders' counters differ. A Seq that
		// were the server's outer id would interleave them instead.
		x5Send(t, 3, 60000, x5Interval, x5Voice(a))
		x5Send(t, 11, 60000, x5Interval, x5Voice(d))
		time.Sleep(vrSettle)
		b.reset()
		done := make(chan struct{})
		go func() {
			defer close(done)
			x5Send(t, 60, 0, x5Interval, x5Voice(d))
		}()
		x5Send(t, 60, 0, x5Interval, x5Voice(a))
		<-done
		vrWait(b, 120, 2*time.Second)

		pkts := b.packets()
		offsets := map[teamspeak.ClientID][]int{}
		for _, id := range []teamspeak.ClientID{a.c.ClientID(), d.c.ClientID()} {
			s := vrFrom(pkts, id, false)
			offsets[id] = vrOffsets(s)
			l.Printf("speaker %d: %s", id, x5Summary(s))
			if len(s) < 55 || len(offsets[id]) != 1 {
				t.Errorf("speaker %d: %d packets, Seq minus frame takes %v", id, len(s), offsets[id])
			}
		}
		if slices.Equal(offsets[a.c.ClientID()], offsets[d.c.ClientID()]) {
			t.Errorf("the two speakers' Seq are in step with each other: %v", offsets)
		}
	})

	t.Run("VoiceAndWhisperAreTwoSequences", func(t *testing.T) {
		targets := client.WhisperTargets{Clients: []teamspeak.ClientID{b.c.ClientID()}}
		b.reset()
		c.reset()
		x5Send(t, 10, 0, x5Interval, x5Voice(a))
		x5Send(t, 10, 10, x5Interval, a.sendWhisper(targets))
		x5Send(t, 10, 20, x5Interval, x5Voice(a))
		vrWait(b, 30, 2*time.Second)

		pkts := b.packets()
		voice, whisper := vrFrom(pkts, a.c.ClientID(), false), vrFrom(pkts, a.c.ClientID(), true)
		l.Printf("voice: %s", x5Summary(voice))
		l.Printf("whisper: %s", x5Summary(whisper))
		if len(voice) < 18 || len(whisper) < 9 {
			t.Fatalf("heard %d voice and %d whisper packets", len(voice), len(whisper))
		}
		for _, w := range whisper {
			if w.Frame < 10 || w.Frame >= 20 {
				t.Errorf("a whisper packet carries frame %d", w.Frame)
			}
		}
		wo := vrOffsets(whisper)
		if len(wo) != 1 {
			t.Errorf("whisper: Seq minus frame takes %v, want one value", wo)
		}
		// The whisper did not advance the voice counter: voice goes on where it
		// stopped, though twenty frames of the test's numbering lie between.
		for i := 1; i < len(voice); i++ {
			if step := (int(voice[i].Seq) - int(voice[i-1].Seq)) & 0xffff; step != 1 && voice[i].Frame-voice[i-1].Frame == 1 {
				t.Errorf("voice Seq %d after %d", voice[i].Seq, voice[i-1].Seq)
			}
		}
		if vo := vrOffsets(voice); len(vo) == 2 && (vo[0]-vo[1])&0xffff != 10 && (vo[1]-vo[0])&0xffff != 10 {
			t.Errorf("voice Seq minus frame takes %v, want two values ten apart: the ten whispered frames did not count", vo)
		}
		for _, p := range c.packets() {
			if p.Whisper {
				t.Errorf("the bystander heard a whisper: %s", p)
			}
		}
	})

	t.Run("EndOfSpeechAndOneByteFramesAreDeliveredInOrder", func(t *testing.T) {
		send := func(data []byte) {
			requireNoErr(t, a.c.SendVoice(data, teamspeak.CodecOpusVoice, client.VoiceOptions{}))
		}
		b.reset()
		x5Send(t, 10, 100, x5Interval, x5Voice(a))
		send(nil)
		time.Sleep(200 * time.Millisecond)
		x5Send(t, 5, 110, x5Interval, x5Voice(a))
		send([]byte{0x00})
		time.Sleep(100 * time.Millisecond)
		send(nil)
		time.Sleep(100 * time.Millisecond)
		send(nil)
		vrWait(b, 19, 2*time.Second)

		pkts := b.packets()
		var shorts []int
		for i, p := range pkts {
			if p.Len <= 1 {
				shorts = append(shorts, p.Len)
			}
			if i > 0 && (int(p.Seq)-int(pkts[i-1].Seq))&0xffff != 1 {
				t.Errorf("packet %d: Seq %d after %d: the end frames take a number like any frame", i, p.Seq, pkts[i-1].Seq)
			}
		}
		l.Printf("%s", x5Summary(pkts))
		if !slices.Equal(shorts, []int{0, 1, 0, 0}) {
			t.Errorf("lengths of the end frames: %v, want [0 1 0 0]", shorts)
		}
	})

	t.Run("CodecChangesPerFrame", func(t *testing.T) {
		segments := []teamspeak.Codec{teamspeak.CodecOpusVoice, teamspeak.CodecOpusMusic, teamspeak.CodecSpeexNarrowband, teamspeak.CodecCELTMono, teamspeak.CodecOpusVoice}
		b.reset()
		for i, codec := range segments {
			x5Send(t, 5, i*5, x5Interval, a.sendVoice(codec))
		}
		vrWait(b, 25, 2*time.Second)

		pkts := b.packets()
		if len(pkts) < 22 {
			t.Fatalf("heard %d of 25", len(pkts))
		}
		for _, p := range pkts {
			if want := segments[p.Frame/5]; p.Codec != want {
				t.Errorf("frame %d sent as codec %d arrived as %d", p.Frame, want, p.Codec)
			}
		}
		if offs := vrOffsets(pkts); len(offs) != 1 {
			t.Errorf("Seq minus frame takes %v: a codec change does not restart the numbering", offs)
		}
	})

	t.Run("PlainAndEncryptedAreDeliveredAlike", func(t *testing.T) {
		b.reset()
		x5Send(t, 20, 0, x5Interval, x5Voice(a))
		x5Send(t, 20, 1000, x5Interval, func(_ int, data []byte) error {
			return a.c.SendVoiceEncryptedForTest(data, teamspeak.CodecOpusVoice)
		})
		vrWait(b, 40, 2*time.Second)

		var plain, enc int
		for _, p := range b.packets() {
			switch {
			case p.Frame >= 0 && p.Frame < 20:
				plain++
			case p.Frame >= 1000 && p.Frame < 1020:
				enc++
			default:
				t.Errorf("the payload came out as another frame: %s", p)
			}
		}
		l.Printf("plain %d/20, encrypted %d/20", plain, enc)
		if plain < 18 || enc < 18 {
			t.Errorf("heard %d plain and %d encrypted frames", plain, enc)
		}
	})

	t.Run("LostAndReorderedPacketsShowInSeq", func(t *testing.T) {
		b.reset()
		b.tap.mu.Lock()
		b.tap.dropOrd = map[int]bool{10: true, 11: true, 30: true}
		b.tap.swapOrd, b.tap.swapOn = 40, true
		b.tap.mu.Unlock()
		defer func() {
			b.tap.mu.Lock()
			b.tap.dropOrd, b.tap.swapOn = nil, false
			b.tap.mu.Unlock()
		}()
		x5Send(t, 60, 0, x5Interval, x5Voice(a))
		vrWait(b, 57, 2*time.Second)

		pkts := b.packets()
		have := map[int]bool{}
		for _, p := range pkts {
			have[p.Frame] = true
		}
		var missing []int
		for f := range 60 {
			if !have[f] {
				missing = append(missing, f)
			}
		}
		if !slices.Equal(missing, []int{10, 11, 30}) {
			t.Errorf("missing frames %v, want exactly the dropped 10, 11, 30: the receiver neither hides nor invents packets", missing)
		}
		i := slices.IndexFunc(pkts, func(p x5Pkt) bool { return p.Frame == 41 })
		if i < 0 || i+1 >= len(pkts) || pkts[i+1].Frame != 40 {
			t.Errorf("frame 41 should be delivered right before the held-back frame 40: the receiver does not reorder")
		}
		if offs := vrOffsets(pkts); len(offs) != 1 {
			t.Errorf("Seq minus frame takes %v", offs)
		}
	})

	t.Run("SlowConsumersDoNotHoldUpCommands", func(t *testing.T) {
		// b has a receiver nobody reads while its other receiver is read at
		// once; a speaks, and b times a command now and then.
		idle, err := b.c.NewVoiceReceiver(client.VoiceReceiverOptions{Capacity: 4})
		requireNoErr(t, err)
		defer idle.Close()

		base := vrCommands(t, b, nil)
		l.Printf("no voice: %s", x5Durations(base))
		under := vrCommands(t, b, a)
		got := len(b.packets())
		l.Printf("a receiver nobody reads: commands under voice load %s; the read receiver got %d/100; the idle one dropped %d",
			x5Durations(under), got, idle.Dropped())
		// The median, for a command now and then waits for the resend of a
		// datagram the emulated server lost; a connection held up delays all.
		if med := vrMedian(under); med > 250*time.Millisecond {
			t.Errorf("a command took %s at the median while a receiver was not read: it must not hold up the connection", med)
		}
		if got < 95 {
			t.Errorf("the receiver being read got %d of 100", got)
		}
		if idle.Dropped() < 90 {
			t.Errorf("the idle receiver dropped %d, want about 96", idle.Dropped())
		}
	})

	t.Run("SeqWrapsAtTheSixteenBitEdge", func(t *testing.T) {
		// A server drops a new stream whose first Seq is far ahead of the one it
		// expects (R18 T7), so walk the sender's counter up in steps.
		frame := 0
		for _, seed := range []uint16{0, 5000, 20000, 40000, 60000, 65000} {
			a.c.SeedVoiceCounterForTest(false, seed, 0)
			x5Send(t, 3, frame, x5Interval, x5Voice(a))
			frame += 3
			time.Sleep(300 * time.Millisecond)
		}
		a.c.SeedVoiceCounterForTest(false, 65520, 0)
		b.reset()
		x5Send(t, 30, 1000, x5Interval, x5Voice(a))
		vrWait(b, 30, 2*time.Second)

		pkts := b.packets()
		l.Printf("%s", x5Summary(pkts))
		saw := map[uint16]bool{}
		for _, p := range pkts {
			saw[p.Seq] = true
			if want := uint16(65520 + p.Frame - 1000); p.Seq != want {
				t.Errorf("frame %d has Seq %d, want %d", p.Frame, p.Seq, want)
			}
		}
		if len(pkts) < 27 || !saw[65535] || !saw[0] {
			t.Errorf("heard %d of 30 across the wrap; 65535 seen %v, 0 seen %v", len(pkts), saw[65535], saw[0])
		}
	})

	reconnecting := func(name string) *x5Peer { return x5ConnectWith(t, name, false, reconnect) }

	t.Run("ReceiverSurvivesAListenersReconnectionAndSessionChanges", func(t *testing.T) {
		speaker, listener := reconnecting("vr-rs"), reconnecting("vr-rl")
		x5Send(t, 10, 0, x5Interval, x5Voice(speaker))
		vrWait(listener, 10, 2*time.Second)
		before := listener.packets()
		if len(before) < 9 {
			t.Fatalf("heard %d of 10 before the drop", len(before))
		}
		session, id := listener.c.Session(), listener.c.ClientID()

		requireNoErr(t, paceConnect(t.Context()))
		requireNoErr(t, listener.c.DropConnectionForTest())
		vrAwaitReconnect(t, listener, session)
		x5Send(t, 10, 10, x5Interval, x5Voice(speaker))
		vrWait(listener, len(before)+10, 2*time.Second)

		after := listener.packets()[len(before):]
		l.Printf("listener reconnect: session %d -> %d, own client id %d -> %d, speaker id %d; before: %s; after: %s",
			session, listener.c.Session(), id, listener.c.ClientID(), speaker.c.ClientID(), x5Summary(before), x5Summary(after))
		if len(after) < 9 {
			t.Fatalf("the receiver heard %d of 10 after the reconnection", len(after))
		}
		for _, p := range before {
			if p.Session != session {
				t.Errorf("before the drop: %s, want session %d", p, session)
			}
		}
		for _, p := range after {
			if p.Session != listener.c.Session() || p.Session <= session {
				t.Errorf("after the reconnection: %s, want a session after %d", p, session)
			}
		}
		// The speaker was not reconnected: its numbering goes on.
		if offs := vrOffsets(append(slices.Clone(before), after...)); len(offs) != 1 {
			l.Printf("the speaker's Seq minus frame takes %v across the listener's reconnection", offs)
			t.Errorf("the speaker did not reconnect, yet its Seq minus frame takes %v", offs)
		}
	})

	t.Run("ASpeakerThatConnectsAgainStartsItsSeqOver", func(t *testing.T) {
		// The same client, disconnected and connected again, as a bot does
		// when it restarts a session; it is quicker than waiting for the
		// server to give up the old session of a dropped one.
		speaker, listener := reconnecting("vr-ss"), reconnecting("vr-sl")
		x5Send(t, 7, 60000, x5Interval, x5Voice(speaker))
		x5Send(t, 10, 0, x5Interval, x5Voice(speaker))
		vrWait(listener, 17, 2*time.Second)
		before := listener.packets()
		idBefore := speaker.c.ClientID()

		ctx, cancel := cleanupContext()
		requireNoErr(t, speaker.c.Disconnect(ctx))
		cancel()
		time.Sleep(500 * time.Millisecond)
		requireNoErr(t, connectWithRetries(t.Context(), t, speaker.c))
		for deadline := time.Now().Add(liveEventWait); speaker.c.ChannelID() == 0 && time.Now().Before(deadline); {
			time.Sleep(50 * time.Millisecond)
		}
		idAfter := speaker.c.ClientID()
		x5Send(t, 10, 100, x5Interval, x5Voice(speaker))
		vrWait(listener, len(before)+10, 2*time.Second)

		after := listener.packets()[len(before):]
		firstSeq := -1
		if len(after) > 0 {
			firstSeq = int(after[0].Seq)
		}
		l.Printf("speaker connects again: client id %d -> %d; its Seq before: %s; after: first Seq %d, %s; the listener's session %d throughout",
			idBefore, idAfter, x5Summary(before), firstSeq, x5Summary(after), listener.c.Session())
		if len(after) < 9 {
			t.Fatalf("the listener heard %d of 10 after the speaker connected again", len(after))
		}
		for _, p := range after {
			if p.Speaker != idAfter || p.Session != listener.c.Session() {
				t.Errorf("after: %s, want speaker %d in session %d", p, idAfter, listener.c.Session())
			}
		}
		if afterOff := vrOffsets(after); len(afterOff) != 1 || afterOff[0] != (0-100)&0xffff {
			t.Errorf("Seq minus frame takes %v after the speaker connected again, want [%d]: its numbering starts over at 0", afterOff, (0-100)&0xffff)
		}
	})

	t.Run("AClientIDCanBeAnotherClientAfterwards", func(t *testing.T) {
		var same bool
		var xID, yID teamspeak.ClientID
		var firstY, lastX uint16
		for attempt := 0; attempt < 2 && !same; attempt++ {
			b.reset()
			x := x5ConnectWith(t, "vr-x", false)
			xID = x.c.ClientID()
			x5Send(t, 5, 0, x5Interval, x5Voice(x))
			vrWait(b, 5, 2*time.Second)
			if xs := vrFrom(b.packets(), xID, false); len(xs) > 0 {
				lastX = xs[len(xs)-1].Seq
			}
			ctx, cancel := cleanupContext()
			requireNoErr(t, x.c.Disconnect(ctx))
			cancel()
			time.Sleep(500 * time.Millisecond)

			b.reset()
			y := x5ConnectWith(t, "vr-y", false)
			yID = y.c.ClientID()
			x5Send(t, 5, 100, x5Interval, x5Voice(y))
			vrWait(b, 5, 2*time.Second)
			ys := vrFrom(b.packets(), yID, false)
			if len(ys) < 4 {
				t.Fatalf("b heard %d of 5 frames from y", len(ys))
			}
			firstY = ys[0].Seq
			same = xID == yID
			l.Printf("attempt %d: x had client id %d, y got %d (reused: %v); x's last Seq %d, y's first Seq %d; b's session %d throughout; y's frames: %s",
				attempt+1, xID, yID, same, lastX, firstY, b.c.Session(), x5Summary(ys))
		}
		if !same {
			t.Logf("no client id was reused in two attempts: nothing more to say")

			return
		}
		// What the receiver reports is the id the server gave the speaker of
		// that packet, in this session; a Seq that restarts says whose it is.
		t.Logf("client id %d was reused by another client: its Seq restarted at %d (the earlier client's last was %d)", yID, firstY, lastX)
	})
}
