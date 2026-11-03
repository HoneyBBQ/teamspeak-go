package client

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// serverVoice builds the packet the transport hands the client for a relayed
// voice packet: [seq: u16][speaker: u16][codec: u8][audio...].
func serverVoice(seq, speaker uint16, codec byte, whisper bool, audio []byte) *transport.Packet {
	data := make([]byte, 5+len(audio))
	binary.BigEndian.PutUint16(data[0:2], seq)
	binary.BigEndian.PutUint16(data[2:4], speaker)
	data[4] = codec
	copy(data[5:], audio)
	t := transport.PacketTypeVoice
	if whisper {
		t = transport.PacketTypeVoiceWhisper
	}

	return &transport.Packet{TypeFlagged: byte(t) | byte(transport.PacketFlagUnencrypted), Data: data}
}

func newReceiver(t *testing.T, c *Client, capacity int) *VoiceReceiver {
	t.Helper()
	r, err := c.NewVoiceReceiver(VoiceReceiverOptions{Capacity: capacity})
	if err != nil {
		t.Fatalf("NewVoiceReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return r
}

func setSession(c *Client, n uint64) {
	c.mu.Lock()
	c.session = n
	c.mu.Unlock()
}

func TestVoiceReceiver_FillsInThePacketFacts(t *testing.T) {
	cases := []struct {
		name    string
		seq     uint16
		speaker uint16
		codec   byte
		whisper bool
		audio   []byte
	}{
		{"voice", 513, 42, 4, false, []byte{9, 8, 7}},
		{"whisper", 0, 43, 5, true, []byte{1}},
		{"highest seq", 0xFFFF, 44, 255, false, []byte{1, 2}},
		{"unnamed codec", 1, 45, 99, false, []byte{3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t)
			setSession(c, 3)
			r := newReceiver(t, c, 0)

			at := time.Now()
			p := serverVoice(tc.seq, tc.speaker, tc.codec, tc.whisper, tc.audio)
			p.ReceivedAt = at
			p.ID = 777 // the outer id is not published
			c.handleVoicePacket(p)

			var got VoicePacket
			if !r.TryRead(&got) {
				t.Fatal("no packet")
			}
			if got.Session != 3 || got.ClientID != teamspeak.ClientID(tc.speaker) || got.Whisper != tc.whisper ||
				got.Seq != tc.seq || got.Codec != teamspeak.Codec(tc.codec) || string(got.Data) != string(tc.audio) {
				t.Errorf("got %+v", got)
			}
			if !got.ReceivedAt.Equal(at) {
				t.Errorf("ReceivedAt = %v, want the packet's %v", got.ReceivedAt, at)
			}
		})
	}
}

func TestVoiceReceiver_ReceivedAtKeepsTheMonotonicReading(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	p := serverVoice(1, 42, 4, false, []byte{1})
	p.ReceivedAt = time.Now()
	c.handleVoicePacket(p)
	var got VoicePacket
	if !r.TryRead(&got) {
		t.Fatal("no packet")
	}
	// == on a time.Time compares the monotonic reading too.
	if got.ReceivedAt != p.ReceivedAt {
		t.Error("ReceivedAt lost its monotonic reading: it is not identical to the packet's value")
	}
}

func TestVoiceReceiver_SkipsShortPacketsAndOwnVoice(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)
	c.mu.Lock()
	c.clid = 7
	c.mu.Unlock()

	c.handleVoicePacket(serverVoice(1, 7, 4, false, []byte{1}))
	c.handleVoicePacket(&transport.Packet{Data: []byte{0, 1, 2, 3}})
	var p VoicePacket
	if r.TryRead(&p) {
		t.Fatalf("got %+v, want nothing", p)
	}
}

func TestVoiceReceiver_DeliversEndOfSpeechFramesAsTheyCame(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	c.handleVoicePacket(serverVoice(10, 42, 4, false, []byte{1, 2, 3}))
	c.handleVoicePacket(serverVoice(11, 42, 4, false, nil))
	c.handleVoicePacket(serverVoice(12, 42, 4, false, []byte{0}))
	c.handleVoicePacket(serverVoice(13, 42, 4, false, []byte{1, 2, 3}))

	want := []struct {
		seq uint16
		n   int
	}{{10, 3}, {11, 0}, {12, 1}, {13, 3}}
	var p VoicePacket
	for _, w := range want {
		if !r.TryRead(&p) || p.Seq != w.seq || len(p.Data) != w.n {
			t.Fatalf("got seq %d len %d, want seq %d len %d", p.Seq, len(p.Data), w.seq, w.n)
		}
	}
}

func TestVoiceReceiver_TryReadNeverBlocksAndKeepsOrder(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	var p VoicePacket
	if r.TryRead(&p) {
		t.Fatal("TryRead on an empty receiver returned true")
	}
	for i := uint16(0); i < 5; i++ {
		c.handleVoicePacket(serverVoice(i, 42, 4, false, []byte{byte(i)}))
	}
	for i := uint16(0); i < 5; i++ {
		if !r.TryRead(&p) || p.Seq != i {
			t.Fatalf("read %d: got seq %d", i, p.Seq)
		}
	}
	if r.TryRead(&p) {
		t.Fatal("TryRead after draining returned true")
	}
}

func TestVoiceReceiver_ReadWaitsForAPacket(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	done := make(chan error, 1)
	var p VoicePacket
	go func() { done <- r.Read(t.Context(), &p) }()
	select {
	case err := <-done:
		t.Fatalf("Read returned %v with nothing to read", err)
	case <-time.After(50 * time.Millisecond):
	}
	c.handleVoicePacket(serverVoice(5, 42, 4, false, []byte{1}))
	select {
	case err := <-done:
		if err != nil || p.Seq != 5 {
			t.Fatalf("Read = %v, seq %d", err, p.Seq)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not wake for a packet")
	}
}

func TestVoiceReceiver_CapacityDefaultAndInvalid(t *testing.T) {
	c := newTestClient(t)
	_, err := c.NewVoiceReceiver(VoiceReceiverOptions{Capacity: -1})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Capacity -1: err = %v, want ErrInvalidConfig", err)
	}

	r := newReceiver(t, c, 0)
	for i := 0; i < 1030; i++ {
		c.handleVoicePacket(serverVoice(uint16(i), 42, 4, false, []byte{1}))
	}
	if r.Dropped() != 6 {
		t.Errorf("Dropped = %d, want 6: the default capacity is 1024", r.Dropped())
	}
	var p VoicePacket
	n := 0
	for r.TryRead(&p) {
		if n == 0 && p.Seq != 6 {
			t.Errorf("oldest kept seq = %d, want 6", p.Seq)
		}
		n++
	}
	if n != 1024 {
		t.Errorf("held %d packets, want 1024", n)
	}
}

func TestVoiceReceiver_FullDropsTheOldestAndCountsPerReceiver(t *testing.T) {
	c := newTestClient(t)
	small := newReceiver(t, c, 4)
	big := newReceiver(t, c, 100)
	events := make(chan VoiceDataEvent, 100)
	c.OnVoiceData(func(e VoiceDataEvent) { events <- e })

	for i := uint16(0); i < 10; i++ {
		c.handleVoicePacket(serverVoice(i, 42, 4, false, []byte{byte(i)}))
	}
	if small.Dropped() != 6 || big.Dropped() != 0 {
		t.Errorf("Dropped small=%d big=%d, want 6 and 0", small.Dropped(), big.Dropped())
	}
	var p VoicePacket
	for want := uint16(6); want < 10; want++ {
		if !small.TryRead(&p) || p.Seq != want {
			t.Fatalf("small: got seq %d, want %d", p.Seq, want)
		}
	}
	if small.TryRead(&p) {
		t.Error("small held more than its capacity")
	}
	for want := uint16(0); want < 10; want++ {
		if !big.TryRead(&p) || p.Seq != want {
			t.Fatalf("big: got seq %d, want %d", p.Seq, want)
		}
	}
	for i := 0; i < 10; i++ {
		select {
		case <-events:
		case <-time.After(time.Second):
			t.Fatalf("OnVoiceData got %d of 10 events: a full receiver must not touch events", i)
		}
	}
}

func TestVoiceReceiver_EveryReceiverGetsEveryPacket(t *testing.T) {
	c := newTestClient(t)
	a, b := newReceiver(t, c, 0), newReceiver(t, c, 0)

	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))
	_ = b.Close()
	c.handleVoicePacket(serverVoice(2, 42, 4, false, []byte{2}))

	var p VoicePacket
	if !a.TryRead(&p) || p.Seq != 1 || !a.TryRead(&p) || p.Seq != 2 {
		t.Fatal("a missed a packet")
	}
	if b.TryRead(&p) {
		t.Fatal("a closed receiver still reads")
	}
}

func TestVoiceReceiver_ReadsAreIndependent(t *testing.T) {
	c := newTestClient(t)
	a, b := newReceiver(t, c, 0), newReceiver(t, c, 0)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))

	var p VoicePacket
	if !a.TryRead(&p) {
		t.Fatal("a has no packet")
	}
	if !b.TryRead(&p) || p.Seq != 1 {
		t.Fatal("reading from a took the packet from b")
	}
}

func TestVoiceReceiver_CloseWakesAReadAndLaterReadsFail(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	errs := make(chan error, 3)
	for range 3 {
		go func() {
			var p VoicePacket
			errs <- r.Read(t.Context(), &p)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if err := r.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	for range 3 {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrVoiceReceiverClosed) {
				t.Errorf("woken Read = %v, want ErrVoiceReceiverClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not wake every Read")
		}
	}
	var p VoicePacket
	if err := r.Read(t.Context(), &p); !errors.Is(err, ErrVoiceReceiverClosed) {
		t.Errorf("Read after Close = %v", err)
	}
	if r.TryRead(&p) {
		t.Error("TryRead after Close returned true")
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
	// Packets for a closed receiver are ignored, not a panic.
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))
}

func TestVoiceReceiver_CloseDiscardsWhatItHolds(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))
	_ = r.Close()

	var p VoicePacket
	if err := r.Read(t.Context(), &p); !errors.Is(err, ErrVoiceReceiverClosed) {
		t.Errorf("Read = %v, want ErrVoiceReceiverClosed even with a packet held", err)
	}
}

func TestVoiceReceiver_ContextEndsTheWait(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		var p VoicePacket
		errc <- r.Read(ctx, &p)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read ignored the cancellation")
	}

	dctx, dcancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer dcancel()
	var p VoicePacket
	err := r.Read(dctx, &p)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, dctx.Err()) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestVoiceReceiver_AnEndedContextTakesNoPacket(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var p VoicePacket
	if err := r.Read(ctx, &p); !errors.Is(err, ctx.Err()) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !r.TryRead(&p) || p.Seq != 1 {
		t.Fatal("the packet was taken by a Read whose context had ended")
	}
}

func TestVoiceReceiver_ClosedWinsOverAnEndedContext(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)
	_ = r.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var p VoicePacket
	if err := r.Read(ctx, &p); !errors.Is(err, ErrVoiceReceiverClosed) {
		t.Errorf("err = %v, want ErrVoiceReceiverClosed", err)
	}
}

func TestVoiceReceiver_SurvivesReconnectionAndNamesTheSession(t *testing.T) {
	c := newTestClient(t)
	setSession(c, 1)
	r := newReceiver(t, c, 0)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))

	// A reconnect is a new session; the handshake numbers it.
	setSession(c, 2)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))

	var p VoicePacket
	if !r.TryRead(&p) || p.Session != 1 {
		t.Fatalf("first packet: session %d, want 1", p.Session)
	}
	if !r.TryRead(&p) || p.Session != 2 || p.Session != c.Session() {
		t.Fatalf("second packet: session %d, want 2 = Client.Session()", p.Session)
	}
}

func TestVoiceReceiver_CanBeMadeBeforeConnect(t *testing.T) {
	c := mustNew(t, mustIdentity(t), "TestBot")
	r := newReceiver(t, c, 0)
	setSession(c, 1)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))
	var p VoicePacket
	if !r.TryRead(&p) || p.Session != 1 {
		t.Fatalf("a receiver made before Connect got nothing: %+v", p)
	}
}

func TestVoiceReceiver_DataIsCopiedIntoTheCallersCapacity(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)
	src := serverVoice(1, 42, 4, false, []byte{1, 2, 3})
	c.handleVoicePacket(src)
	// The transport reuses its buffer once handleVoicePacket returns.
	for i := range src.Data {
		src.Data[i] = 0xEE
	}

	p := VoicePacket{Data: make([]byte, 0, 64)}
	backing := &p.Data[:1][0]
	if !r.TryRead(&p) {
		t.Fatal("no packet")
	}
	if string(p.Data) != "\x01\x02\x03" {
		t.Fatalf("Data = % x, want the frame as it arrived", p.Data)
	}
	if &p.Data[0] != backing {
		t.Error("Data was not copied into the capacity the caller gave")
	}

	// A shorter frame after a longer one leaves no tail.
	c.handleVoicePacket(serverVoice(2, 42, 4, false, nil))
	if !r.TryRead(&p) || len(p.Data) != 0 {
		t.Errorf("empty frame: len(Data) = %d", len(p.Data))
	}
	// Too small a Data grows, and still holds the frame.
	c.handleVoicePacket(serverVoice(3, 42, 4, false, []byte{4, 5, 6, 7}))
	var q VoicePacket
	if !r.TryRead(&q) || string(q.Data) != "\x04\x05\x06\x07" {
		t.Errorf("Data into a zero VoicePacket = % x", q.Data)
	}
}

func TestVoiceReceiver_AFrameIsHeldIntact(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 2)
	big := make([]byte, 1500)
	for i := range big {
		big[i] = byte(i)
	}
	c.handleVoicePacket(serverVoice(1, 42, 4, false, big))
	var p VoicePacket
	if !r.TryRead(&p) || len(p.Data) != len(big) || p.Data[1499] != big[1499] {
		t.Fatalf("a %d-byte frame came back as %d bytes", len(big), len(p.Data))
	}
}

func TestVoiceReceiver_DoesNotAllocateInSteadyState(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 8)
	pkt := serverVoice(1, 42, 4, false, make([]byte, 120))
	pkt.ReceivedAt = time.Now()

	var p VoicePacket
	// Warm up: the caller's Data grows once.
	c.handleVoicePacket(pkt)
	if !r.TryRead(&p) {
		t.Fatal("no packet")
	}

	if n := testing.AllocsPerRun(200, func() { c.handleVoicePacket(pkt); _ = r.TryRead(&p) }); n != 0 {
		t.Errorf("receive and TryRead allocate %v times per packet, want 0", n)
	}
	if n := testing.AllocsPerRun(200, func() { c.handleVoicePacket(pkt) }); n != 0 {
		t.Errorf("the receive path allocates %v times per packet, want 0", n)
	}
	// The receiver is full by now: dropping the oldest allocates nothing either.
	ctx := t.Context()
	if n := testing.AllocsPerRun(200, func() { _ = r.Read(ctx, &p) }); n != 0 {
		t.Errorf("Read allocates %v times, want 0", n)
	}
}

func TestVoiceReceiver_ManyReceiversDoNotAllocate(t *testing.T) {
	c := newTestClient(t)
	for range 4 {
		newReceiver(t, c, 8)
	}
	pkt := serverVoice(1, 42, 4, false, make([]byte, 120))
	if n := testing.AllocsPerRun(200, func() { c.handleVoicePacket(pkt) }); n != 0 {
		t.Errorf("the receive path allocates %v times with 4 receivers, want 0", n)
	}
}

// A handler stuck on the event queue, and a receiver nobody reads, hold up
// neither the packet path nor another receiver.
func TestVoiceReceiver_NothingSlowHoldsUpTheConnection(t *testing.T) {
	c := newTestClient(t)
	idle := newReceiver(t, c, 4) // never read
	live := newReceiver(t, c, 1000)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.OnVoiceData(func(VoiceDataEvent) { <-release })

	start := time.Now()
	for i := 0; i < 500; i++ {
		c.handleVoicePacket(serverVoice(uint16(i), 42, 4, false, make([]byte, 100)))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("500 packets took %v to take in", d)
	}
	var p VoicePacket
	for i := 0; i < 500; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := live.Read(ctx, &p)
		cancel()
		if err != nil || int(p.Seq) != i {
			t.Fatalf("live receiver: read %d: seq %d, err %v", i, p.Seq, err)
		}
	}
	if idle.Dropped() != 496 {
		t.Errorf("idle receiver dropped %d, want 496", idle.Dropped())
	}
}

func TestVoiceReceiver_OnVoiceDataIsUnchanged(t *testing.T) {
	run := func(withReceiver bool) []VoiceDataEvent {
		c := newTestClient(t)
		if withReceiver {
			newReceiver(t, c, 2)
		}
		var mu sync.Mutex
		var got []VoiceDataEvent
		c.OnVoiceData(func(e VoiceDataEvent) { mu.Lock(); got = append(got, e); mu.Unlock() })
		for i := uint16(0); i < 5; i++ {
			c.handleVoicePacket(serverVoice(i, 42, 4, false, []byte{byte(i)}))
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(got)
			mu.Unlock()
			if n == 5 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()

		return got
	}
	without, with := run(false), run(true)
	if len(without) != 5 || len(with) != len(without) {
		t.Fatalf("events without a receiver %d, with one %d, want 5 each", len(without), len(with))
	}
	for i := range with {
		if with[i].ClientID != without[i].ClientID || string(with[i].Data) != string(without[i].Data) || with[i].Codec != without[i].Codec {
			t.Errorf("event %d differs: %+v vs %+v", i, with[i], without[i])
		}
	}
}

func TestVoiceReceiver_SkipsTheEventMiddleware(t *testing.T) {
	seen := 0
	var mu sync.Mutex
	counting := func(next func(Event)) func(Event) {
		return func(e Event) {
			if _, ok := e.(VoiceDataEvent); ok {
				mu.Lock()
				seen++
				mu.Unlock()
			}
			// Drop it: the receiver must not care.
		}
	}
	c := newTestClient(t, WithEventMiddleware(counting))
	r := newReceiver(t, c, 0)
	c.handleVoicePacket(serverVoice(1, 42, 4, false, []byte{1}))
	var p VoicePacket
	if !r.TryRead(&p) {
		t.Fatal("a middleware dropping the event kept the packet from the receiver")
	}
}

func TestVoiceReceiver_ConcurrentUseIsSafe(t *testing.T) {
	c := newTestClient(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	rs := make([]*VoiceReceiver, 4)
	for i := range rs {
		rs[i] = newReceiver(t, c, 16)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c.handleVoicePacket(serverVoice(uint16(i), 42, 4, i%3 == 0, make([]byte, 80)))
		}
	}()
	for _, r := range rs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			var p VoicePacket
			for {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				err := r.Read(ctx, &p)
				cancel()
				if err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			var p VoicePacket
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = r.TryRead(&p)
				_ = r.Dropped()
			}
		}()
	}
	extra, _ := c.NewVoiceReceiver(VoiceReceiverOptions{})
	time.Sleep(100 * time.Millisecond)
	_ = extra.Close()
	for _, r := range rs {
		_ = r.Close()
	}
	close(stop)
	wg.Wait()
}

func FuzzVoiceReceiver(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add([]byte{0, 1, 0, 2, 4}, true)
	f.Add(make([]byte, 5000), false)
	f.Fuzz(func(t *testing.T, data []byte, whisper bool) {
		c := newTestClient(t)
		r := newReceiver(t, c, 2)
		typ := transport.PacketTypeVoice
		if whisper {
			typ = transport.PacketTypeVoiceWhisper
		}
		c.handleVoicePacket(&transport.Packet{TypeFlagged: byte(typ), Data: data})
		var p VoicePacket
		if r.TryRead(&p) && len(data) >= 5 && len(p.Data) != len(data)-5 {
			t.Fatalf("len(Data) = %d for a %d-byte payload", len(p.Data), len(data))
		}
	})
}

func BenchmarkVoiceReceiver_Receive(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		b.Run(string(rune('0'+n/10))+string(rune('0'+n%10)), func(b *testing.B) {
			id, err := identity.Parse(testClientIdentity)
			if err != nil {
				b.Fatal(err)
			}
			c, err := New(id, unitTestServerAddr, "bench")
			if err != nil {
				b.Fatal(err)
			}
			for range n {
				r, _ := c.NewVoiceReceiver(VoiceReceiverOptions{Capacity: 64})
				defer r.Close()
			}
			pkt := serverVoice(1, 42, 4, false, make([]byte, 120))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				c.handleVoicePacket(pkt)
			}
		})
	}
}
