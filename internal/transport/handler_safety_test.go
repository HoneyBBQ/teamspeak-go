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
	err = h.SendWhisperPacket([]byte{1}, []uint16{1}, nil, 4)
	if !errors.Is(err, ErrNotOpen) {
		t.Errorf("SendWhisperPacket before Start = %v, want ErrNotOpen", err)
	}
	err = h.SendGroupWhisperPacket([]byte{1}, 3, 0, 0, 4)
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

// sealRealPacket seals a server packet with the session key of tc for
// generation gen, as the server would.
func sealRealPacket(
	t *testing.T,
	tc *crypto.Crypt,
	id uint16,
	gen uint32,
	typeFlagged byte,
	payload []byte,
) []byte {
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

// sealReal seals a server command with the session key of tc for generation
// gen, as the server would.
func sealReal(t *testing.T, tc *crypto.Crypt, id uint16, gen uint32, payload []byte) []byte {
	t.Helper()

	return sealRealPacket(
		t,
		tc,
		id,
		gen,
		byte(PacketTypeCommand)|byte(PacketFlagNewProtocol),
		payload,
	)
}

// A packet recorded in one generation and replayed once the 16-bit id has
// wrapped back to it must not decrypt: only the window's own generation is
// tried, never the previous one nor the next.
func TestHandlerRefusesAPacketOfAnotherGeneration(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)
	h.nextCommandID = 200
	h.recvWindowCommand.Advance(1<<16 + 200)
	payload := []byte("notifytextmessage targetmode=1 msg=replayed invokerid=5")

	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 0, payload))
	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 2, payload))
	if *delivered != 0 {
		t.Fatalf("delivered %d packets of another generation, want 0", *delivered)
	}

	h.handleRawPacket(sealReal(t, h.TsCrypt, 200, 1, payload))
	if *delivered != 1 {
		t.Fatalf("delivered %d packets of the current generation, want 1", *delivered)
	}
}

// Voice, whisper, ping and pong have separate 16-bit packet id streams. Their
// ids can wrap without the command stream wrapping, but the packet key still
// moves to the next generation, so each stream has to follow its own wrap.
func TestHandlerDecryptsNonCommandPacketsAcrossTheGenerationWrap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pType PacketType
	}{
		{"voice", PacketTypeVoice},
		{"whisper", PacketTypeVoiceWhisper},
		{"pong", PacketTypePong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, delivered := newFuzzHandler(t, true)
			payload := []byte{0, 1, 0, 2, 0, 4, 1}

			h.handleRawPacket(sealRealPacket(
				t, h.TsCrypt, 65535, 0, byte(tc.pType), payload,
			))
			if *delivered != 1 {
				t.Fatalf("delivered the last packet of generation 0: got %d, want 1", *delivered)
			}

			h.handleRawPacket(sealRealPacket(
				t, h.TsCrypt, 0, 1, byte(tc.pType), payload,
			))
			if *delivered != 2 {
				t.Fatalf("delivered first packet of generation 1: got %d, want 2", *delivered)
			}
		})
	}

	t.Run("ping", func(t *testing.T) {
		h, _ := newFuzzHandler(t, true)
		conn := &countingConn{}
		h.conn = conn

		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 65535, 0, byte(PacketTypePing), nil,
		))
		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 0, 1, byte(PacketTypePing), nil,
		))
		if conn.writes != 2 {
			t.Fatalf("answered %d wrapped pings, want 2", conn.writes)
		}
	})

	t.Run("wrong generation does not advance", func(t *testing.T) {
		h, delivered := newFuzzHandler(t, true)
		payload := []byte{0, 1, 0, 2, 0, 4, 1}

		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 65535, 0, byte(PacketTypeVoice), payload,
		))
		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 0, 0, byte(PacketTypeVoice), payload,
		))
		if *delivered != 1 {
			t.Fatalf("accepted a voice packet under the old generation: got %d delivered, want 1", *delivered)
		}

		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 0, 1, byte(PacketTypeVoice), payload,
		))
		if *delivered != 2 {
			t.Fatalf("the failed old-generation packet prevented the next generation: got %d delivered, want 2", *delivered)
		}
	})

	t.Run("streams advance independently", func(t *testing.T) {
		h, delivered := newFuzzHandler(t, true)
		h.recvWindowVoice.Advance(1 << 16)
		payload := []byte{0, 1, 0, 2, 0, 4, 1}

		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 7, 0, byte(PacketTypeVoiceWhisper), payload,
		))
		h.handleRawPacket(sealRealPacket(
			t, h.TsCrypt, 7, 1, byte(PacketTypeVoice), payload,
		))
		if *delivered != 2 {
			t.Fatalf("delivered %d independently wrapped streams, want 2", *delivered)
		}
	})
}

// countingConn counts the datagrams written to it.
type countingConn struct {
	discardConn

	writes int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.writes++

	return len(b), nil
}

// A command whose acknowledgement was lost is sent again after the window has
// moved past it. Across the 16-bit wrap it is sent under the generation before
// the window's: it must decrypt there, be acknowledged, and not be delivered a
// second time. Under any other generation, or before the first wrap, it is not
// taken at all.
func TestHandlerAcknowledgesAnOldPacketAcrossTheWrap(t *testing.T) {
	payload := []byte("notifytextmessage targetmode=1 msg=again invokerid=5")
	newWrapped := func() (*PacketHandler, *countingConn, *int) {
		h, delivered := newFuzzHandler(t, true)
		conn := &countingConn{}
		h.conn = conn
		h.nextCommandID = 1
		h.recvWindowCommand.Advance(1<<16 + 1) // base 1 of generation 1

		return h, conn, delivered
	}

	h, conn, delivered := newWrapped()
	h.handleRawPacket(sealReal(t, h.TsCrypt, 65535, 0, payload))
	if conn.writes != 1 || *delivered != 0 {
		t.Errorf("the generation before: %d acknowledgements, %d delivered, want 1 and 0", conn.writes, *delivered)
	}

	h, conn, delivered = newWrapped()
	h.handleRawPacket(sealReal(t, h.TsCrypt, 65535, 1, payload))
	if conn.writes != 0 || *delivered != 0 {
		t.Errorf("the window's generation: %d acknowledgements, %d delivered, want 0 and 0", conn.writes, *delivered)
	}

	h, delivered = newFuzzHandler(t, true)
	conn = &countingConn{}
	h.conn = conn
	h.handleRawPacket(sealReal(t, h.TsCrypt, 65535, 0, payload))
	if conn.writes != 0 || *delivered != 0 {
		t.Errorf("before the first wrap: %d acknowledgements, %d delivered, want 0 and 0", conn.writes, *delivered)
	}
}

// A datagram larger than 4096 bytes is dropped whole, and the connection
// goes on; one of exactly 4096 is taken.
func TestHandlerDropsDatagramsLargerThan4096(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)
	got := make(chan int, 4)
	h.OnPacket = func(p *Packet) {
		*delivered++
		got <- len(p.Data)
	}
	clientConn, serverConn := newTestPair()
	h.conn = clientConn
	go h.receiveLoop()
	go h.processLoop()
	t.Cleanup(func() { _ = h.Close(); _ = clientConn.Close() })

	_, _ = serverConn.Write(sealReal(t, h.TsCrypt, 0, 0, make([]byte, maxDatagramSize-10)))
	_, _ = serverConn.Write(sealReal(t, h.TsCrypt, 0, 0, make([]byte, maxDatagramSize-11)))

	select {
	case n := <-got:
		if n != maxDatagramSize-11 {
			t.Fatalf("delivered a %d-byte payload, want the 4096-byte datagram's", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the 4096-byte datagram was not delivered")
	}
}

// Out-of-order command packets are held only up to maxQueuedCommandBytes;
// past it they are dropped unacknowledged, and the packet the queue waits for
// is still taken, so it drains and the dropped ones are accepted when resent.
func TestHandlerCapsTheReceiveQueueBytes(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)
	const size, count = 4000, 300
	for id := uint16(1); id <= count; id++ {
		h.handleRawPacket(sealReal(t, h.TsCrypt, id, 0, make([]byte, size)))
	}
	h.mu.Lock()
	held, queued := h.queuedBytes, len(h.commandQueue)
	h.mu.Unlock()
	if held > maxQueuedCommandBytes || queued >= count {
		t.Fatalf("holding %d bytes in %d packets, want at most %d bytes", held, queued, maxQueuedCommandBytes)
	}

	h.handleRawPacket(sealReal(t, h.TsCrypt, 0, 0, make([]byte, size)))
	if *delivered != queued+1 {
		t.Fatalf("delivered %d after the missing packet arrived, want %d", *delivered, queued+1)
	}
	for id := uint16(queued + 1); id <= count; id++ {
		h.handleRawPacket(sealReal(t, h.TsCrypt, id, 0, make([]byte, size)))
	}
	if *delivered != count+1 {
		t.Fatalf("delivered %d once the dropped packets were resent, want %d", *delivered, count+1)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.queuedBytes != 0 {
		t.Errorf("%d bytes still counted as queued", h.queuedBytes)
	}
}

// A block declaring more output than its input could expand to is refused
// before the output is allocated.
func TestQlzDecompressRefusesASizeTheInputCannotReach(t *testing.T) {
	data := make([]byte, 13)
	data[0] = 0x47 // level 1, 9-byte header, compressed
	binary.LittleEndian.PutUint32(data[1:5], 13)
	binary.LittleEndian.PutUint32(data[5:9], MaxDecompressedSize)
	_, err := NewQlz().Decompress(data)
	if !errors.Is(err, errQlzTooLarge) {
		t.Fatalf("Decompress = %v, want errQlzTooLarge", err)
	}
	allocs := testing.AllocsPerRun(10, func() { _, _ = NewQlz().Decompress(data) })
	if allocs > 2 {
		t.Errorf("%v allocations for a refused block", allocs)
	}
}
