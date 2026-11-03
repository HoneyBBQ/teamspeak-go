//go:build integration

// Scaffolding of the live voice-receiver tests (the X5 measurements and the
// receiver's contract tests), not library code: it favours readable
// measurement over the style limits.

//nolint:errcheck,funcorder,funlen,goprintffuncname,gosec,govet,lll,unparam
package client_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// Helpers of the live voice tests. The contract tests of the voice receiver
// run in every integration run. The long X5 measurements of what the servers
// do to voice packets run only with X5=1: they take minutes a server, more
// than the suite's package timeout leaves room for. X5_LOG_DIR, when set, is a
// directory the tests write one log per test and server into.

// x5Frame is the audio of frame n: an Opus silence TOC and the frame number, so
// that a received packet says which one it was whatever happened to its ids.
func x5Frame(n int) []byte { return []byte{0xF8, 0xFF, 0xFE, byte(n >> 8), byte(n)} }

func x5FrameNo(data []byte) int {
	if len(data) < 5 {
		return -1
	}

	return int(data[3])<<8 | int(data[4])
}

// x5Log writes a test's observations to its log file and to the test log.
type x5Log struct {
	t *testing.T
	f *os.File
}

// newX5Log is newVoiceLog for a long measurement, which runs only with X5=1.
func newX5Log(t *testing.T) *x5Log {
	t.Helper()
	if os.Getenv("X5") == "" {
		t.Skip("the X5 voice measurements take minutes a server; set X5=1 to run them")
	}

	return newVoiceLog(t)
}

func newVoiceLog(t *testing.T) *x5Log {
	t.Helper()
	l := &x5Log{t: t}
	dir := os.Getenv("X5_LOG_DIR")
	if dir == "" {
		return l
	}
	family := os.Getenv("TEAMSPEAK_QUERY_FAMILY")
	name := strings.ReplaceAll(t.Name(), "/", "_")
	f, err := os.Create(filepath.Join(dir, family+"-"+name+".log"))
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	l.f = f
	t.Cleanup(func() { _ = f.Close() })
	fmt.Fprintf(f, "# %s server=%s %s\n", t.Name(), family, time.Now().Format(time.RFC3339))

	return l
}

func (l *x5Log) Printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if l.f != nil {
		fmt.Fprintln(l.f, line)
	}
	l.t.Log(line)
}

// raw writes a line to the file only, for bulk per-packet data.
func (l *x5Log) raw(format string, args ...any) {
	if l.f != nil {
		fmt.Fprintf(l.f, format+"\n", args...)
	}
}

// x5Pkt is what the receiver gave of one packet.
type x5Pkt struct {
	At       time.Time // VoicePacket.ReceivedAt
	Dispatch time.Time // when the read returned
	Session  uint64
	Speaker  teamspeak.ClientID
	Seq      uint16
	Frame    int
	Len      int // len(Data)
	Codec    teamspeak.Codec
	Whisper  bool
}

func (p x5Pkt) String() string {
	return fmt.Sprintf("session=%d spk=%d frame=%d seq=%d whisper=%t codec=%d len=%d",
		p.Session, p.Speaker, p.Frame, p.Seq, p.Whisper, p.Codec, p.Len)
}

// x5Peer is a connected client with a receiver that a goroutine reads into a
// list, and a tap on its socket.
type x5Peer struct {
	c    *client.Client
	rx   *client.VoiceReceiver
	tap  *x5Tap
	mu   sync.Mutex
	pkts []x5Pkt
	// events counts OnVoiceData deliveries.
	events int
}

func (p *x5Peer) packets() []x5Pkt {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.pkts)
}

func (p *x5Peer) reset() {
	p.mu.Lock()
	p.pkts = nil
	p.events = 0
	p.mu.Unlock()
	if p.tap != nil {
		p.tap.reset()
	}
}

func (p *x5Peer) eventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.events
}

// x5Connect connects a client over a tapped socket, with a voice receiver
// being read and an OnVoiceData counter installed.
func x5Connect(t *testing.T, nickname string, extra ...client.Option) *x5Peer {
	t.Helper()

	return x5ConnectWith(t, nickname, true, extra...)
}

// x5ConnectWith is x5Connect, with the socket tapped or, for a client that
// must be able to reconnect, the client's own: it does not close a socket it
// was given, so a dropped connection over one cannot be redone.
func x5ConnectWith(t *testing.T, nickname string, tapped bool, extra ...client.Option) *x5Peer {
	t.Helper()
	addr := requireTeamSpeakAddr(t)
	opts := integrationClientOptions(nil)
	var tap *x5Tap
	if tapped {
		var lc net.ListenConfig
		pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		tap = &x5Tap{PacketConn: pc}
		opts = append(opts, client.WithPacketConn(tap))
	}
	id, err := identity.Generate(t.Context(), 8)
	requireNoErr(t, err)
	c := newClient(t, id, addr, nickname, append(opts, extra...)...)
	rx, err := c.NewVoiceReceiver(client.VoiceReceiverOptions{Capacity: 4096})
	requireNoErr(t, err)
	p := &x5Peer{c: c, rx: rx, tap: tap}
	go func() {
		var v client.VoicePacket
		for rx.Read(context.Background(), &v) == nil {
			rec := x5Pkt{
				At: v.ReceivedAt, Dispatch: time.Now(), Session: v.Session, Speaker: v.ClientID, Seq: v.Seq,
				Frame: x5FrameNo(v.Data), Len: len(v.Data), Codec: v.Codec, Whisper: v.Whisper,
			}
			p.mu.Lock()
			p.pkts = append(p.pkts, rec)
			p.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = rx.Close() })
	c.OnVoiceData(func(client.VoiceDataEvent) {
		p.mu.Lock()
		p.events++
		p.mu.Unlock()
	})
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	for deadline := time.Now().Add(liveEventWait); c.ChannelID() == 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}

	return p
}

// x5Tap sees every server datagram a client reads, before the client does, and
// can lose or delay voice packets.
type x5Tap struct {
	net.PacketConn

	mu    sync.Mutex
	recs  []x5TapRec
	voice int // voice-type datagrams seen since the last reset
	// dropOrd are the ordinals, counted from 0 since the last reset, of the
	// voice datagrams that are lost.
	dropOrd map[int]bool
	// swapOrd, when >= 0 and armed, holds that voice datagram back until the
	// next one has been delivered.
	swapOrd int
	swapOn  bool
	held    []byte
	heldTo  net.Addr
	pending []byte
}

// x5TapRec is one voice-type datagram as it came off the wire.
type x5TapRec struct {
	At    time.Time
	Type  byte
	Flags byte
	ID    uint16
	Len   int // datagram length
	Ord   int
	Drop  bool
	// Plain is the payload's first two bytes when the datagram is unencrypted.
	Seq uint16
}

func (t *x5Tap) reset() {
	t.mu.Lock()
	t.recs = nil
	t.voice = 0
	t.mu.Unlock()
}

func (t *x5Tap) records() []x5TapRec {
	t.mu.Lock()
	defer t.mu.Unlock()

	return slices.Clone(t.recs)
}

func (t *x5Tap) ReadFrom(b []byte) (int, net.Addr, error) {
	t.mu.Lock()
	if t.pending != nil {
		n := copy(b, t.pending)
		to := t.heldTo
		t.pending = nil
		t.mu.Unlock()

		return n, to, nil
	}
	t.mu.Unlock()
	for {
		n, from, err := t.PacketConn.ReadFrom(b)
		at := time.Now()
		if err != nil || n < 11 || b[10]&0x0f > 1 {
			return n, from, err
		}
		rec := x5TapRec{At: at, Type: b[10] & 0x0f, Flags: b[10] & 0xf0, ID: uint16(b[8])<<8 | uint16(b[9]), Len: n}
		if rec.Flags&0x80 != 0 && n >= 13 {
			rec.Seq = uint16(b[11])<<8 | uint16(b[12])
		}
		t.mu.Lock()
		rec.Ord = t.voice
		t.voice++
		if t.dropOrd[rec.Ord] {
			rec.Drop = true
			t.recs = append(t.recs, rec)
			t.mu.Unlock()

			continue
		}
		t.recs = append(t.recs, rec)
		if t.swapOn && rec.Ord == t.swapOrd {
			t.held = append([]byte(nil), b[:n]...)
			t.heldTo = from
			t.mu.Unlock()

			continue
		}
		if t.held != nil {
			t.pending = t.held
			t.held = nil
		}
		t.mu.Unlock()

		return n, from, nil
	}
}

// x5Send sends n frames numbered from first, one every interval, and returns
// the instant each was sent.
func x5Send(t *testing.T, n, first int, interval time.Duration, send func(i int, data []byte) error) []time.Time {
	t.Helper()
	sent := make([]time.Time, n)
	next := time.Now()
	for i := range n {
		sent[i] = time.Now()
		requireNoErr(t, send(first+i, x5Frame(first+i)))
		next = next.Add(interval)
		time.Sleep(time.Until(next))
	}

	return sent
}

func x5Settle() { time.Sleep(1200 * time.Millisecond) }

// x5Streams groups packets by speaker and whisper, in arrival order.
func x5Streams(pkts []x5Pkt) map[string][]x5Pkt {
	out := map[string][]x5Pkt{}
	for _, p := range pkts {
		k := fmt.Sprintf("spk=%d whisper=%t", p.Speaker, p.Whisper)
		out[k] = append(out[k], p)
	}

	return out
}

// x5Summary describes how the Seq of one stream relates to the frame numbers
// that were sent and to each other.
func x5Summary(pkts []x5Pkt) string {
	if len(pkts) == 0 {
		return "no packets"
	}
	offsets := map[int]int{}
	seqSteps := map[int]int{}
	end := 0
	for i, p := range pkts {
		if p.Frame >= 0 {
			offsets[(int(p.Seq)-p.Frame)&0xffff]++
		} else {
			end++
		}
		if i > 0 {
			seqSteps[(int(p.Seq)-int(pkts[i-1].Seq))&0xffff]++
		}
	}

	return fmt.Sprintf("n=%d empty=%d | seq-frame offsets %s | seq steps %s", len(pkts), end, x5Hist(offsets), x5Hist(seqSteps))
}

func x5Hist(m map[int]int) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var parts []string
	for i, k := range keys {
		if i == 8 {
			parts = append(parts, fmt.Sprintf("...(+%d more)", len(keys)-8))

			break
		}
		parts = append(parts, fmt.Sprintf("%d x%d", k, m[k]))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

func x5Dump(l *x5Log, label string, pkts []x5Pkt) {
	l.raw("--- %s: %d packets", label, len(pkts))
	var t0 time.Time
	for i, p := range pkts {
		if i == 0 {
			t0 = p.At
		}
		l.raw("%s t=%.3fms", p, float64(p.At.Sub(t0).Microseconds())/1000)
	}
}

func x5Durations(d []time.Duration) string {
	if len(d) == 0 {
		return "n=0"
	}
	s := slices.Clone(d)
	slices.Sort(s)
	q := func(f float64) time.Duration { return s[int(float64(len(s)-1)*f)] }

	return fmt.Sprintf("n=%d min=%s p50=%s p90=%s p99=%s max=%s", len(s), s[0], q(0.5), q(0.9), q(0.99), s[len(s)-1])
}
