package client

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func voicePacket(speakerID uint16, codec byte, audio []byte) *transport.Packet {
	data := make([]byte, 5+len(audio))
	binary.BigEndian.PutUint16(data[0:2], 1) // voice packet ID
	binary.BigEndian.PutUint16(data[2:4], speakerID)
	data[4] = codec
	copy(data[5:], audio)

	return &transport.Packet{Data: data}
}

func TestHandleVoicePacket_DispatchesSpeakerAndAudio(t *testing.T) {
	c := newTestClient(t)
	got := make(chan VoiceDataEvent, 1)
	c.OnVoiceData(func(vd VoiceDataEvent) { got <- vd })

	audio := []byte{0xaa, 0xbb, 0xcc}
	c.handleVoicePacket(voicePacket(42, 5, audio))

	select {
	case vd := <-got:
		if vd.ClientID != 42 || vd.Codec != 5 || len(vd.Data) != len(audio) {
			t.Errorf("got clid=%d codec=%d data=% x", vd.ClientID, vd.Codec, vd.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("OnVoiceData was not called")
	}
}

func TestHandleVoicePacket_IgnoresOwnAudio(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 7
	c.mu.Unlock()

	got := make(chan VoiceDataEvent, 1)
	c.OnVoiceData(func(vd VoiceDataEvent) { got <- vd })

	c.handleVoicePacket(voicePacket(7, 5, []byte{1, 2}))

	select {
	case vd := <-got:
		t.Errorf("own audio should be ignored, got %+v", vd)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandleVoicePacket_IgnoresTruncatedPackets(t *testing.T) {
	c := newTestClient(t)
	c.OnVoiceData(func(VoiceDataEvent) { t.Error("handler called for a truncated packet") })

	c.handleVoicePacket(&transport.Packet{Data: []byte{0, 1, 2}})
	time.Sleep(100 * time.Millisecond)
}
