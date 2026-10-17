package transport

import (
	"testing"
	"time"
)

func TestClassOf(t *testing.T) {
	for typ, want := range map[PacketType]TrafficClass{
		PacketTypeVoice: TrafficSpeech, PacketTypeVoiceWhisper: TrafficSpeech,
		PacketTypePing: TrafficKeepalive, PacketTypePong: TrafficKeepalive,
		PacketTypeCommand: TrafficControl, PacketTypeCommandLow: TrafficControl,
		PacketTypeAck: TrafficControl, PacketTypeAckLow: TrafficControl, PacketTypeInit1: TrafficControl,
	} {
		if got := ClassOf(typ); got != want {
			t.Errorf("ClassOf(%d) = %d, want %d", typ, got, want)
		}
	}
}

func TestTrafficMeter_CountsAndWindows(t *testing.T) {
	var m trafficMeter
	start := time.Unix(1000, 0)
	m.recordSent(PacketTypeVoice, 100, start)
	m.recordSent(PacketTypeVoice, 50, start.Add(200*time.Millisecond))
	m.recordReceived(PacketTypePong, 30, start)

	// Within the second the figures are totals only: the second is unfinished.
	s := m.snapshot(start.Add(500 * time.Millisecond))
	if f := s.Sent[TrafficSpeech]; f.Packets != 2 || f.Bytes != 150 || f.BytesLastSecond != 0 {
		t.Errorf("same second = %+v", f)
	}
	// One second on, the finished second is "the last second".
	s = m.snapshot(start.Add(1500 * time.Millisecond))
	if f := s.Sent[TrafficSpeech]; f.BytesLastSecond != 150 || f.BytesPerSecondLastMinute != 2 {
		t.Errorf("next second = %+v", f)
	}
	if f := s.Received[TrafficKeepalive]; f.Packets != 1 || f.Bytes != 30 || f.BytesLastSecond != 30 {
		t.Errorf("received keepalive = %+v", f)
	}
	if f := s.Sent[TrafficControl]; f != (TrafficFigures{}) {
		t.Errorf("control = %+v, want zero", f)
	}
	// Past the window the bytes leave the rates, not the totals.
	s = m.snapshot(start.Add(2 * time.Minute))
	if f := s.Sent[TrafficSpeech]; f.Bytes != 150 || f.BytesLastSecond != 0 || f.BytesPerSecondLastMinute != 0 {
		t.Errorf("after the window = %+v", f)
	}
}

func TestRoundTrip_MeanAndDeviationOverTheLastTen(t *testing.T) {
	var r roundTrip
	if _, ok := r.get(); ok {
		t.Error("an estimate before the first sample")
	}
	r.add(10 * time.Millisecond)
	r.add(30 * time.Millisecond)
	got, ok := r.get()
	if !ok || got.Mean != 20*time.Millisecond || got.Deviation != 10*time.Millisecond {
		t.Errorf("estimate = %+v, %v", got, ok)
	}
	for range 10 {
		r.add(50 * time.Millisecond)
	}
	got, _ = r.get()
	if got.Mean != 50*time.Millisecond || got.Deviation != 0 {
		t.Errorf("after ten more = %+v, want 50ms, 0", got)
	}
}

func TestHandler_PongCompletesTheRoundTrip(t *testing.T) {
	h := NewPacketHandler(nil, nil)
	h.stats.pingSent(7, time.Unix(10, 0))
	h.stats.pongReceived(8, time.Unix(11, 0)) // not a ping we sent
	if _, ok := h.RoundTrip(); ok {
		t.Error("a pong for an unknown ping counted")
	}
	h.stats.pongReceived(7, time.Unix(10, 0).Add(40*time.Millisecond))
	got, ok := h.RoundTrip()
	if !ok || got.Mean != 40*time.Millisecond {
		t.Errorf("estimate = %+v, %v", got, ok)
	}
}

// A datagram is counted whole, header included, on every send.
func TestHandler_CountsWholeDatagramsSent(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn) // Init1, already counted as control

	before := h.Traffic().Sent
	err := h.SendGroupWhisperPacket([]byte{1, 2, 3}, 3, 0, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	pkt := readPacket(t, serverConn)
	after := h.Traffic().Sent
	if got := after[TrafficSpeech].Packets - before[TrafficSpeech].Packets; got != 1 {
		t.Errorf("speech packets grew by %d, want 1", got)
	}
	if got := after[TrafficSpeech].Bytes - before[TrafficSpeech].Bytes; got != uint64(len(pkt)) {
		t.Errorf("speech bytes grew by %d, want %d", got, len(pkt))
	}
	if after[TrafficControl].Packets != 1 {
		t.Errorf("control packets = %d, want the Init1", after[TrafficControl].Packets)
	}
}
