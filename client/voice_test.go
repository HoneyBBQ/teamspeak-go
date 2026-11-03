package client

import (
	"encoding/binary"
	"testing"

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
	r := newReceiver(t, c, 0)

	audio := []byte{0xaa, 0xbb, 0xcc}
	c.handleVoicePacket(voicePacket(42, 5, audio))

	var vp VoicePacket
	if !r.TryRead(&vp) {
		t.Fatal("the receiver got no packet")
	}
	if vp.ClientID != 42 || vp.Codec != 5 || len(vp.Data) != len(audio) {
		t.Errorf("got clid=%d codec=%d data=% x", vp.ClientID, vp.Codec, vp.Data)
	}
}

// The server relays a client's empty frame, its end of speech, as a packet with
// the header alone; it reaches receivers with empty Data.
func TestHandleVoicePacket_DeliversEndOfSpeechAsEmptyData(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	c.handleVoicePacket(voicePacket(42, 4, nil))

	var vp VoicePacket
	if !r.TryRead(&vp) {
		t.Fatal("the receiver got no packet for an empty frame")
	}
	if vp.ClientID != 42 || vp.Codec != 4 || len(vp.Data) != 0 {
		t.Errorf("got clid=%d codec=%d data=% x", vp.ClientID, vp.Codec, vp.Data)
	}
}

func TestHandleVoicePacket_IgnoresOwnAudio(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 7
	c.mu.Unlock()
	r := newReceiver(t, c, 0)

	c.handleVoicePacket(voicePacket(7, 5, []byte{1, 2}))

	var vp VoicePacket
	if r.TryRead(&vp) {
		t.Errorf("own audio should be ignored, got %+v", vp)
	}
}

func TestHandleVoicePacket_IgnoresTruncatedPackets(t *testing.T) {
	c := newTestClient(t)
	r := newReceiver(t, c, 0)

	c.handleVoicePacket(&transport.Packet{Data: []byte{0, 1, 2}})

	var vp VoicePacket
	if r.TryRead(&vp) {
		t.Errorf("a truncated packet reached the receiver: %+v", vp)
	}
}
