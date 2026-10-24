package client

import (
	"encoding/binary"
	"log/slog"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// VoicePacket is one incoming Voice or VoiceWhisper packet as the server sent
// it, with nothing interpreted: the facts a receiver needs to order, pace and
// classify audio itself.
//
// Experimental: this may change or go away in a minor release.
type VoicePacket struct {
	// ReceivedAt is when the datagram was read from the socket, taken before
	// the packet was decrypted or queued for processing. It carries Go's
	// monotonic reading, so differences between two values are reliable.
	ReceivedAt time.Time
	// Data is the codec frame: the payload after its five-byte header. It is
	// empty (or one byte) when the speaker stopped talking.
	//
	// Data is borrowed from the receive buffer and is valid only until the
	// receiver returns. Copy it to keep it.
	Data []byte
	// Generation is how often PacketID has wrapped past 65535, as the receive
	// window tracks it; it keys the decryption.
	Generation uint32
	// Speaker is the client speaking.
	Speaker teamspeak.ClientID
	// Seq is the voice packet id the payload starts with (payload bytes 0-1).
	Seq uint16
	// PacketID is the id in the packet's outer header. Voice and VoiceWhisper
	// each have their own sequence of it.
	PacketID uint16
	// Codec is the codec Data is encoded in.
	Codec teamspeak.Codec
	// Whisper is whether the packet type is VoiceWhisper rather than Voice.
	Whisper bool
	// Encrypted is whether the packet arrived encrypted, that is without the
	// Unencrypted flag in its header.
	Encrypted bool
}

// SetVoiceReceiver sets the function called for every voice or whisper packet
// another client sends, or clears it when fn is nil. It replaces any earlier
// receiver, and survives reconnection.
//
// Unlike OnVoiceData, fn is not delivered through the event queue: it is called
// synchronously on the goroutine that processes incoming packets, once per
// packet, in arrival order, with no copy of the audio. It must therefore
// return quickly and must not block, wait for a command's answer, or call
// anything that does; while it runs, no later packet of the connection,
// commands and acknowledgements included, is handled. fn may call SendVoice.
// A panic in fn is recovered and logged at Error. OnVoiceData keeps working
// as before, whether or not a receiver is set.
//
// A packet shorter than its five-byte payload header, and the client's own
// voice, are not delivered.
//
// Experimental: this is a prototype, and may change or go away in a minor
// release.
func (c *Client) SetVoiceReceiver(fn func(VoicePacket)) {
	if fn == nil {
		c.voiceReceiver.Store(nil)

		return
	}
	c.voiceReceiver.Store(&fn)
}

// receiveVoice builds the VoicePacket for p and calls the receiver.
func (c *Client) receiveVoice(fn func(VoicePacket), p *transport.Packet, speaker teamspeak.ClientID) {
	defer func() {
		r := recover()
		if r != nil {
			c.logger.Error("voice receiver panicked", slog.Any("panic", r))
		}
	}()

	fn(VoicePacket{
		ReceivedAt: p.ReceivedAt,
		Data:       p.Data[5:],
		Generation: p.GenerationID,
		Speaker:    speaker,
		Seq:        binary.BigEndian.Uint16(p.Data[0:2]),
		PacketID:   p.ID,
		Codec:      teamspeak.Codec(p.Data[4]),
		Whisper:    p.Type() == transport.PacketTypeVoiceWhisper,
		Encrypted:  !p.IsUnencrypted(),
	})
}
