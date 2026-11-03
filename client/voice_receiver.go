package client

import (
	"context"
	"errors"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// VoicePacket is one voice or whisper packet another client sent, as the
// server relayed it. A VoiceReceiver fills it in.
//
// Experimental: VoicePacket may still change in a minor release.
type VoicePacket struct {
	// ReceivedAt is when the datagram was read from the socket, before it was
	// decrypted or queued for processing. It carries a monotonic clock
	// reading, so the difference between two is the time between their
	// arrivals, whatever the wall clock does meanwhile. The packet itself
	// carries no time.
	ReceivedAt time.Time
	// Data is the encoded audio: one frame in Codec. Read and TryRead copy it
	// into the capacity of Data: it is the caller's, and the next read into
	// the same VoicePacket overwrites it, so copy a frame to keep it.
	//
	// By convention, an empty Data is the speaker's end of speech: the server
	// relays the empty frame a client sends when it stops talking, with its
	// Seq like any frame. It can be lost like any packet, so do not rely on
	// it alone to notice that someone stopped. Other implementations treat a
	// frame of one byte as the end of speech too; whether the official client
	// does is not known, and a one-byte Opus packet is a valid one.
	Data []byte
	// Session is the Client.Session the packet arrived in. A client id names a
	// client only within one session: when Session changes, start every
	// per-speaker state over.
	Session uint64
	// ClientID is the client speaking.
	ClientID teamspeak.ClientID
	// Seq is the speaker's own number for the packet. The server relays it
	// unchanged, so every listener sees the same Seq for the same packet. It
	// goes up by one with every packet the speaker sends, end of speech
	// included, counting a speaker's whispers apart from the rest, and wraps
	// from 65535 to 0: compare two with int16(a-b), not with a < b. A gap is a
	// packet that was lost or is still to come; the network and the server can
	// both reorder packets, and the client delivers them as they arrived.
	//
	// The speaker's client chooses Seq, so it is no fact to trust: bound any
	// wait or buffer it drives.
	Seq uint16
	// Codec is the codec Data is encoded in. It can change from one packet to
	// the next, and the servers relay codecs this module does not name.
	Codec teamspeak.Codec
	// Whisper reports a packet the speaker whispered rather than spoke in the
	// channel. It is all a listener learns of a whisper; who else it was
	// addressed to is not sent. Whispers have a Seq of their own, so keep a
	// speaker's packets apart by ClientID and Whisper together.
	Whisper bool
}

// VoiceReceiverOptions are NewVoiceReceiver's optional parameters.
//
// Experimental: VoiceReceiverOptions may still change in a minor release.
type VoiceReceiverOptions struct {
	// Capacity is how many packets the receiver holds until Read takes them;
	// 0 means 1024, about two seconds of ten people talking at once. When it
	// is full, a packet arriving drops the oldest one held, and Dropped counts
	// it. A negative Capacity is ErrInvalidConfig.
	Capacity int
}

// VoiceReceiver holds the voice and whisper packets the client receives, in
// the order they arrived, until Read or TryRead takes them. Every receiver
// gets every packet, from when it was made until it is closed, across
// disconnects and reconnections.
//
// The client never waits for a receiver. A receiver that is not read fast
// enough drops its own oldest packets and counts them in Dropped; the
// connection, the events and the other receivers carry on as before. Its
// packets do not go through the event queue nor WithEventMiddleware, and a
// handler blocking on the event queue does not delay them. Packets are not
// ordered with events.
//
// Its methods are safe to call from any goroutine, including event handlers.
// When several goroutines Read one receiver, each packet goes to one of them;
// for a second consumer that sees every packet, make a second receiver.
//
// Experimental: VoiceReceiver may still change in a minor release.
type VoiceReceiver struct{}

// ErrVoiceReceiverClosed is what Read returns once Close was called.
//
// Experimental: ErrVoiceReceiverClosed may still change in a minor release.
var ErrVoiceReceiverClosed = errors.New("voice receiver closed")

// NewVoiceReceiver returns a receiver for the voice and whisper packets this
// client receives from now on. It may be made before Connect. Close it when
// done: until then it keeps up to Capacity packets.
//
// It returns ErrInvalidConfig for options it cannot use.
//
// Experimental: NewVoiceReceiver may still change in a minor release.
func (c *Client) NewVoiceReceiver(opts VoiceReceiverOptions) (*VoiceReceiver, error) {
	return &VoiceReceiver{}, nil
}

// Read waits for the next packet and stores it in p, reusing p.Data's
// capacity. It returns nil with p filled in, ErrVoiceReceiverClosed once the
// receiver is closed, or an error for which errors.Is(err, ctx.Err()) holds
// when ctx ends first. A context that has already ended takes no packet.
//
// A disconnect is not an error: Read goes on waiting for the next session's
// packets. To stop at a disconnect, cancel ctx or Close from OnDisconnected.
//
// Experimental: Read may still change in a minor release.
func (r *VoiceReceiver) Read(ctx context.Context, p *VoicePacket) error {
	return ErrVoiceReceiverClosed
}

// TryRead stores the next packet in p, as Read does, if one is waiting, and
// reports whether it did. It never waits: it is for a loop driven by a clock
// of its own, such as an audio device's, that takes what has arrived on each
// tick. After Close it returns false.
//
// Experimental: TryRead may still change in a minor release.
func (r *VoiceReceiver) TryRead(p *VoicePacket) bool {
	return false
}

// Dropped reports how many packets the receiver has dropped, since it was
// made, for being full. Packets the network or the server lost are not in it;
// Seq shows those.
//
// Experimental: Dropped may still change in a minor release.
func (r *VoiceReceiver) Dropped() uint64 {
	return 0
}

// Close stops the receiver and discards what it holds. A Read waiting
// returns ErrVoiceReceiverClosed, as does every later one. Closing again does
// nothing. It always returns nil; it returns an error so that a receiver is an
// io.Closer.
//
// Experimental: Close may still change in a minor release.
func (r *VoiceReceiver) Close() error {
	return nil
}
