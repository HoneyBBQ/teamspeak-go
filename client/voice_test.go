package client

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
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

func newVoiceTestClientWithPipe(t *testing.T) (*Client, *pipePair) {
	t.Helper()
	c, server := newTestClientWithPipe(t)
	completeCryptoInit(t, c.handler)
	c.mu.Lock()
	c.status = StatusConnected
	c.mu.Unlock()
	_ = readFromPipe(t, server) // Init1 from Start

	return c, server
}

func TestSendVoice_MaxFrameSizeAndEmptyFrame(t *testing.T) {
	if MaxVoiceFrameSize != 484 {
		t.Fatalf("MaxVoiceFrameSize = %d, want 484", MaxVoiceFrameSize)
	}
	c, server := newVoiceTestClientWithPipe(t)

	err := c.SendVoice(make([]byte, MaxVoiceFrameSize), teamspeak.CodecOpusVoice, VoiceOptions{})
	if err != nil {
		t.Fatalf("SendVoice(484): %v", err)
	}
	if pkt := readFromPipe(t, server); len(pkt) != transport.MaxOutPacketSize {
		t.Errorf("484-byte frame datagram len = %d, want %d", len(pkt), transport.MaxOutPacketSize)
	}

	for _, empty := range [][]byte{nil, {}} {
		err = c.SendVoice(empty, teamspeak.CodecOpusVoice, VoiceOptions{})
		if err != nil {
			t.Fatalf("SendVoice(empty): %v", err)
		}
		if pkt := readFromPipe(t, server); len(pkt) != 16 {
			t.Errorf("empty frame datagram len = %d, want 16", len(pkt))
		}
	}
}

func TestSendVoice_RejectsOversizedFrameWithoutSendingOrAdvancingID(t *testing.T) {
	c, server := newVoiceTestClientWithPipe(t)

	err := c.SendVoice(make([]byte, 10), teamspeak.CodecOpusVoice, VoiceOptions{})
	if err != nil {
		t.Fatalf("first SendVoice: %v", err)
	}
	first := readFromPipe(t, server)
	firstID := binary.BigEndian.Uint16(first[13:15])

	for _, size := range []int{MaxVoiceFrameSize + 1, 633} {
		err = c.SendVoice(make([]byte, size), teamspeak.CodecOpusVoice, VoiceOptions{})
		if !errors.Is(err, ErrVoiceFrameTooLarge) {
			t.Errorf("SendVoice(%d) err = %v, want ErrVoiceFrameTooLarge", size, err)
		}
		if err == nil || !strings.Contains(err.Error(), "at most 484") {
			t.Errorf("SendVoice(%d) err = %v, want message mentioning 'at most 484'", size, err)
		}
	}

	select {
	case unexpected := <-server.recv:
		t.Fatalf("oversized SendVoice sent a %d-byte datagram", len(unexpected))
	case <-time.After(50 * time.Millisecond):
	}

	err = c.SendVoice(make([]byte, 10), teamspeak.CodecOpusVoice, VoiceOptions{})
	if err != nil {
		t.Fatalf("second SendVoice: %v", err)
	}
	second := readFromPipe(t, server)
	if secondID := binary.BigEndian.Uint16(second[13:15]); secondID != firstID+1 {
		t.Errorf("voice ID after refused frames = %d, want %d", secondID, firstID+1)
	}
}
