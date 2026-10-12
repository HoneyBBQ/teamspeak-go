package transport

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/crypto"
)

// After crypto init the dummy key is public knowledge, so a command sealed
// with it must not be taken for one from the server.
func TestHandlerDropsDummyKeyCommandsAfterCryptoInit(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)

	h.handleRawPacket(sealDummy(t, 0, byte(PacketTypeCommand), []byte("initserver aclid=1")))
	h.handleRawPacket(sealDummy(t, 0, byte(PacketTypeCommandLow), []byte("notifyclientpoke msg=x")))

	if *delivered != 0 {
		t.Fatalf("delivered %d dummy-key commands after crypto init, want 0", *delivered)
	}
}

// The servers acknowledge clientek, the last command sent before the shared
// secret exists, with the dummy key; that one Ack is accepted, once.
func TestHandlerAcceptsOnlyTheClientEkAckUnderTheDummyKey(t *testing.T) {
	h, _ := newFuzzHandler(t, false)
	err := h.SendPacket(byte(PacketTypeCommand), []byte("clientek ek=x proof=y"), 0)
	if err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	clientEk := uint16(h.clientEkID.Load())
	err = h.TsCrypt.SetSharedSecret(make([]byte, 10), make([]byte, 54), make([]byte, 64))
	if err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}

	ackOf := func(id uint16) []byte {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, id)

		return data
	}
	var acked []uint16
	h.OnPacket = func(p *Packet) {
		if p.Type() == PacketTypeAck {
			acked = append(acked, binary.BigEndian.Uint16(p.Data))
		}
	}

	h.handleRawPacket(sealDummy(t, 0, byte(PacketTypeAck), ackOf(clientEk+1)))
	h.handleRawPacket(sealDummy(t, 1, byte(PacketTypeAck), ackOf(clientEk)))
	h.handleRawPacket(sealDummy(t, 2, byte(PacketTypeAck), ackOf(clientEk)))

	if len(acked) != 1 || acked[0] != clientEk {
		t.Fatalf("accepted dummy-key acks %v, want exactly one for clientek (%d)", acked, clientEk)
	}
}

func TestHandlerRefusesSendsWhenNotOpen(t *testing.T) {
	h := NewPacketHandler(newFuzzCrypt(t), nil)

	err := h.SendPacket(byte(PacketTypeCommand), []byte("x"), 0)
	if !errors.Is(err, ErrNotOpen) {
		t.Errorf("SendPacket before Start = %v, want ErrNotOpen", err)
	}
	err = h.SendVoicePacket([]byte{1}, 4)
	if !errors.Is(err, ErrNotOpen) {
		t.Errorf("SendVoicePacket before Start = %v, want ErrNotOpen", err)
	}
	err = h.SendWhisperPacket([]byte{1}, []uint16{1}, 4)
	if !errors.Is(err, ErrNotOpen) {
		t.Errorf("SendWhisperPacket before Start = %v, want ErrNotOpen", err)
	}
}

func TestHandlerDropsCommandsThatDoNotDecompress(t *testing.T) {
	h, delivered := newFuzzHandler(t, false)

	// Compressed, but a stored block declaring more bytes than it holds.
	flags := byte(PacketTypeCommand) | byte(PacketFlagCompressed)
	h.handleRawPacket(sealDummy(t, 0, flags, []byte{0x04, 0x00, 200}))
	h.handleRawPacket(sealDummy(t, 1, byte(PacketTypeCommand), []byte("after")))

	if *delivered != 1 {
		t.Fatalf("delivered %d commands, want only the one after the bad block", *delivered)
	}
}

// A panic while handling a packet closes the connection with a cause instead
// of taking the process down.
func TestHandlerClosesWithACauseWhenHandlingPanics(t *testing.T) {
	h, serverConn := newTestHandler(t)
	_ = readPacket(t, serverConn)

	closed := make(chan error, 1)
	h.OnClosed = func(err error) { closed <- err }
	h.OnPacket = func(*Packet) { panic("boom") }

	_, err := serverConn.Write(buildDummyEncryptedS2CCommand(t, 0, byte(PacketTypeCommand), []byte("x")))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case err := <-closed:
		if !errors.Is(err, ErrPacketHandling) {
			t.Fatalf("closed with %v, want ErrPacketHandling", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not close after a panic")
	}
	if h.IsOpen() {
		t.Error("handler still open after a panic")
	}
}

// Init1 is the handshake's; once a shared secret exists it is not delivered.
func TestHandlerIgnoresInit1AfterCryptoInit(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)

	h.handleRawPacket(buildS2CPacket([]byte("TS3INIT1"), 101, byte(PacketTypeInit1), []byte{0x7F}))

	if *delivered != 0 {
		t.Fatalf("delivered %d Init1 packets after crypto init, want 0", *delivered)
	}
}

// The fake signature that authenticates unencrypted packets is on every
// plaintext ping and voice packet, so anyone on the path can attach it. A
// command claiming to be unencrypted must not be delivered, or such a peer
// could forge text messages, kicks and command answers.
func TestHandlerDropsUnencryptedCommandsAfterCryptoInit(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)
	sig := h.TsCrypt.FakeSignature()
	unenc := byte(PacketFlagUnencrypted)

	h.handleRawPacket(buildS2CPacket(sig[:], 0, byte(PacketTypeCommand)|unenc,
		[]byte("notifytextmessage targetmode=1 msg=forged invokerid=2")))
	h.handleRawPacket(buildS2CPacket(sig[:], 0, byte(PacketTypeCommandLow)|unenc,
		[]byte("notifyclientpoke msg=forged")))
	if *delivered != 0 {
		t.Fatalf("delivered %d unencrypted command packets after crypto init, want 0", *delivered)
	}

	// Voice is sent unencrypted by the servers and must still arrive.
	h.handleRawPacket(buildS2CPacket(sig[:], 0, byte(PacketTypeVoice)|unenc, []byte{0, 0, 0, 0, 0, 4, 1}))
	if *delivered != 1 {
		t.Fatalf("delivered %d unencrypted voice packets, want 1", *delivered)
	}
}

// sealReal seals a server packet with the session key of tc for generation
// gen, as the server would.
func sealReal(t *testing.T, tc *crypto.Crypt, id uint16, gen uint32, typeFlagged byte, payload []byte) []byte {
	t.Helper()
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header, id)
	header[2] = typeFlagged
	key, nonce := tc.GetKeyNonce(true, id, gen, typeFlagged&0x0f, false)
	eax, err := crypto.NewEAX(append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("NewEAX: %v", err)
	}
	ciphertext, mac, err := eax.Encrypt(nonce, header, payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return append(append(append([]byte{}, mac...), header...), ciphertext...)
}

// A packet recorded in one generation and replayed once the 16-bit id has
// wrapped back to it must not decrypt: only the window's own generation is
// tried, never the previous one nor the next.
func TestHandlerRefusesAPacketOfAnotherGeneration(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)
	h.nextCommandID = 200
	h.recvWindowCommand.Advance(1<<16 + 200)
	cmd := byte(PacketTypeCommand) | byte(PacketFlagNewProtocol)
	payload := []byte("notifytextmessage targetmode=1 msg=replayed invokerid=5")

	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 0, cmd, payload))
	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 2, cmd, payload))
	if *delivered != 0 {
		t.Fatalf("delivered %d packets of another generation, want 0", *delivered)
	}

	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 1, cmd, payload))
	if *delivered != 1 {
		t.Fatalf("delivered %d packets of the current generation, want 1", *delivered)
	}
}
