package client

import (
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func TestVoiceReceiver_GetsThePacketFacts(t *testing.T) {
	c := newTestClient(t)
	var got []VoicePacket
	c.SetVoiceReceiver(func(p VoicePacket) { got = append(got, p) })

	at := time.Now()
	p := voicePacket(42, 4, []byte{9, 8, 7})
	p.ID = 513
	p.GenerationID = 2
	p.ReceivedAt = at
	p.TypeFlagged = byte(transport.PacketTypeVoiceWhisper)
	c.handleVoicePacket(p)

	if len(got) != 1 {
		t.Fatalf("receiver called %d times", len(got))
	}
	v := got[0]
	if v.Speaker != 42 || v.Codec != 4 || v.Seq != 1 || v.PacketID != 513 || v.Generation != 2 ||
		!v.Whisper || !v.Encrypted || !v.ReceivedAt.Equal(at) || len(v.Data) != 3 {
		t.Errorf("got %+v", v)
	}

	p.TypeFlagged = byte(transport.PacketTypeVoice) | byte(transport.PacketFlagUnencrypted)
	c.handleVoicePacket(p)
	if v := got[1]; v.Whisper || v.Encrypted {
		t.Errorf("flags of a plain Voice packet: %+v", v)
	}
}

func TestVoiceReceiver_RunsAlongsideOnVoiceDataAndSurvivesAPanic(t *testing.T) {
	c := newTestClient(t)
	events := make(chan VoiceDataEvent, 1)
	c.OnVoiceData(func(e VoiceDataEvent) { events <- e })
	c.SetVoiceReceiver(func(VoicePacket) { panic("boom") })

	c.handleVoicePacket(voicePacket(42, 4, []byte{1}))

	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("OnVoiceData was not called after the receiver panicked")
	}
}

func TestVoiceReceiver_ClearedAndSkipsOwnAudio(t *testing.T) {
	c := newTestClient(t)
	calls := 0
	c.SetVoiceReceiver(func(VoicePacket) { calls++ })
	c.mu.Lock()
	c.clid = 7
	c.mu.Unlock()

	c.handleVoicePacket(voicePacket(7, 4, []byte{1}))
	c.handleVoicePacket(&transport.Packet{Data: []byte{0, 1, 2}})
	c.SetVoiceReceiver(nil)
	c.handleVoicePacket(voicePacket(42, 4, []byte{1}))
	if calls != 0 {
		t.Errorf("receiver called %d times, want 0", calls)
	}
}
