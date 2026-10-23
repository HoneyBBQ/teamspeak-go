package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
)

// packetPipe is one leg of an in-memory datagram pair: one Write is one Read message.
type packetPipe struct {
	recv   <-chan []byte
	send   chan<- []byte
	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
}

func (p *packetPipe) Read(b []byte) (int, error) {
	select {
	case data, ok := <-p.recv:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)

		return n, nil
	case <-p.done:
		return 0, io.EOF
	}
}

func (p *packetPipe) Write(b []byte) (int, error) {
	if p.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case p.send <- cp:
		return len(b), nil
	case <-p.done:
		return 0, io.ErrClosedPipe
	}
}

func (p *packetPipe) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.done)
	})

	return nil
}

// newTestPair creates a pair of connected packetPipe endpoints.
// clientConn is given to PacketHandler.Start(); serverConn is used by the test
// to read what the handler sends and inject packets the handler receives.
func newTestPair() (*packetPipe, *packetPipe) {
	toClient := make(chan []byte, 256)
	fromClient := make(chan []byte, 256)
	done := make(chan struct{})

	clientConn := &packetPipe{recv: toClient, send: fromClient, done: done}
	serverConn := &packetPipe{recv: fromClient, send: toClient, done: done}

	return clientConn, serverConn
}

const testIdentityForHandler = "W2OSGpWxkzBPJjt8iyJFsMnqnwHCnxOlmE9gWFOFnKs=:0"

// These match the unexported dummy key/nonce in crypto/crypt_ops.go,
// used for EAX encrypt/decrypt before CryptoInit completes.
var (
	handlerTestDummyKey   = []byte(`c:\windows\syste`)
	handlerTestDummyNonce = []byte(`m\firewall32.cpl`)
)

func newTestHandler(t *testing.T) (*PacketHandler, *packetPipe) {
	t.Helper()
	id, err := identity.Parse(testIdentityForHandler)
	if err != nil {
		t.Fatalf("IdentityFromString: %v", err)
	}
	tc := crypto.NewCrypt(id)
	h := NewPacketHandler(tc, slog.Default())
	clientConn, serverConn := newTestPair()
	startErr := h.Start(clientConn)
	if startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}

	return h, serverConn
}

// readPacket reads the next packet from serverConn with a 2-second timeout.
func readPacket(t *testing.T, serverConn *packetPipe) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	done := make(chan []byte, 1)

	go func() {
		n, err := serverConn.Read(buf)
		if err != nil {
			done <- nil

			return
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		done <- cp
	}()

	select {
	case data := <-done:
		return data
	case <-time.After(2 * time.Second):
		t.Fatalf("readPacket: timed out after 2s")

		return nil
	}
}

// buildS2CPacket constructs a raw S2C (server-to-client) packet for injection.
// Format: [8 tag][2 ID][1 TypeFlagged][payload].
func buildS2CPacket(tag []byte, id uint16, typeFlagged byte, payload []byte) []byte {
	raw := make([]byte, 8+3+len(payload))
	copy(raw[0:8], tag)
	binary.BigEndian.PutUint16(raw[8:10], id)
	raw[10] = typeFlagged
	copy(raw[11:], payload)

	return raw
}

// buildDummyEncryptedS2CCommand encrypts a command payload with the dummy EAX key
// and returns the full raw S2C packet bytes.
func buildDummyEncryptedS2CCommand(t *testing.T, pktID uint16, typeFlagged byte, payload []byte) []byte {
	t.Helper()
	s2cHeader := make([]byte, 3)
	binary.BigEndian.PutUint16(s2cHeader[0:2], pktID)
	s2cHeader[2] = typeFlagged

	key := make([]byte, 16)
	copy(key, handlerTestDummyKey)
	eax, err := crypto.NewEAX(key)
	if err != nil {
		t.Fatalf("NewEAX: %v", err)
	}
	ciphertext, mac, err := eax.Encrypt(handlerTestDummyNonce, s2cHeader, payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	raw := make([]byte, 8+3+len(ciphertext))
	copy(raw[0:8], mac)
	copy(raw[8:11], s2cHeader)
	copy(raw[11:], ciphertext)

	return raw
}

func TestHandlerStart_SendsInit1Packet(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()

	pkt := readPacket(t, serverConn)
	if len(pkt) < 13+21 {
		t.Fatalf("expected at least %d bytes, got %d", 13+21, len(pkt))
	}

	// Verify MAC is "TS3INIT1"
	if string(pkt[0:8]) != "TS3INIT1" {
		t.Errorf("expected 'TS3INIT1' MAC, got %q", pkt[0:8])
	}
	// C2S header[4] lower nibble is the packet type.
	typeByte := pkt[12] & 0x0F
	if typeByte != byte(PacketTypeInit1) {
		t.Errorf("expected PacketTypeInit1 (%d), got %d", PacketTypeInit1, typeByte)
	}
	// Payload: [4 version][1 type=0x00][...] = 21 bytes
	if len(pkt[13:]) != 21 {
		t.Errorf("expected 21-byte Init1 payload, got %d", len(pkt[13:]))
	}
}

// TestHandlerReceive_Init1Packet_CallsOnPacket verifies that a server-sent Init1
// packet is delivered to OnPacket. Responding with subsequent Init1 steps is the
// Client's responsibility, not the PacketHandler's.
func TestHandlerReceive_Init1Packet_CallsOnPacket(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()

	_ = readPacket(t, serverConn)

	received := make(chan *Packet, 1)
	h.OnPacket = func(p *Packet) {
		received <- p
	}

	step0Data := make([]byte, 21)
	step0Data[0] = 0x00
	binary.LittleEndian.PutUint32(step0Data[9:13], 0xCAFEBABE)

	raw := buildS2CPacket(make([]byte, 8), 0, byte(PacketTypeInit1), step0Data)
	_, writeErr := serverConn.Write(raw)
	if writeErr != nil {
		t.Fatalf("Write: %v", writeErr)
	}

	select {
	case p := <-received:
		if p.Type() != PacketTypeInit1 {
			t.Errorf("expected PacketTypeInit1, got %v", p.Type())
		}
		if len(p.Data) != 21 {
			t.Errorf("expected 21-byte payload, got %d", len(p.Data))
		}
	case <-time.After(2 * time.Second):
		t.Error("OnPacket not called for Init1 packet")
	}
}

func TestHandlerReceive_PingFromServer_SendsPong(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()

	_ = readPacket(t, serverConn)

	const pingID = uint16(42)
	pingPayload := make([]byte, 2)
	binary.BigEndian.PutUint16(pingPayload, pingID)

	// TypeFlagged = PacketTypePing(4) | PacketFlagUnencrypted(0x80)
	// FakeSignature before CryptoInit = all zeros.
	typeFlagged := byte(PacketTypePing) | byte(PacketFlagUnencrypted)
	raw := buildS2CPacket(make([]byte, 8), pingID, typeFlagged, pingPayload)
	_, writeErr2 := serverConn.Write(raw)
	if writeErr2 != nil {
		t.Fatalf("Write ping: %v", writeErr2)
	}

	resp := readPacket(t, serverConn)
	if len(resp) < 13+2 {
		t.Fatalf("expected pong, got %d bytes", len(resp))
	}
	if resp[12]&0x0F != byte(PacketTypePong) {
		t.Errorf("expected PacketTypePong (%d), got %d", PacketTypePong, resp[12]&0x0F)
	}
}

func TestHandlerClose_CallsOnClosed(t *testing.T) {
	h, serverConn := newTestHandler(t)

	closed := make(chan error, 1)
	h.OnClosed = func(err error) {
		closed <- err
	}

	_ = readPacket(t, serverConn)
	_ = h.Close()

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("OnClosed not called within timeout")
	}
}

func TestHandlerReceive_CommandPacket_CallsOnPacket(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()

	_ = readPacket(t, serverConn)

	typeFlagged := byte(PacketTypeCommand) | byte(PacketFlagNewProtocol)
	raw := buildDummyEncryptedS2CCommand(t, 0, typeFlagged, []byte("hello"))

	received := make(chan *Packet, 1)
	h.OnPacket = func(p *Packet) {
		received <- p
	}

	_, writeErr3 := serverConn.Write(raw)
	if writeErr3 != nil {
		t.Fatalf("Write command: %v", writeErr3)
	}

	select {
	case p := <-received:
		if string(p.Data) != "hello" {
			t.Errorf("expected 'hello', got %q", p.Data)
		}
	case <-time.After(2 * time.Second):
		t.Error("OnPacket not called within timeout")
	}
}

// TestHandlerReceive_FragmentedCommandPacket_Reassembles verifies that two
// fragmented command packets are correctly reassembled before OnPacket is called.
//
// TeamSpeak fragmentation:
//   - First fragment:  PacketFlagFragmented SET
//   - Middle fragments: PacketFlagFragmented NOT set
//   - Last fragment:  PacketFlagFragmented SET  ← both start and end have the flag
func TestHandlerReceive_FragmentedCommandPacket_Reassembles(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()

	_ = readPacket(t, serverConn)

	// Fragment 1 (start): ID=0, Command | NewProtocol | Fragmented
	f1Type := byte(PacketTypeCommand) | byte(PacketFlagNewProtocol) | byte(PacketFlagFragmented)
	// Fragment 2 (end):   ID=1, Command | NewProtocol | Fragmented
	// Both first and last fragments have Fragmented set per TeamSpeak fragmentation rules.
	f2Type := byte(PacketTypeCommand) | byte(PacketFlagNewProtocol) | byte(PacketFlagFragmented)

	received := make(chan *Packet, 1)
	h.OnPacket = func(p *Packet) {
		received <- p
	}

	_, err1 := serverConn.Write(buildDummyEncryptedS2CCommand(t, 0, f1Type, []byte("hello")))
	if err1 != nil {
		t.Fatalf("Write fragment 1: %v", err1)
	}
	_, err2 := serverConn.Write(buildDummyEncryptedS2CCommand(t, 1, f2Type, []byte(" world")))
	if err2 != nil {
		t.Fatalf("Write fragment 2: %v", err2)
	}

	select {
	case p := <-received:
		if string(p.Data) != "hello world" {
			t.Errorf("expected 'hello world', got %q", p.Data)
		}
	case <-time.After(2 * time.Second):
		t.Error("OnPacket not called for reassembled packet")
	}
}

// TestHandlerSendPacket_LargeCommand_SplitsIntoFragments verifies that a
// Command payload >487 bytes is fragmented.
//
//	first != last → set PacketFlagFragmented (only on first and last, not middle).
func TestHandlerSendPacket_LargeCommand_SplitsIntoFragments(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	// 975 bytes → 3 fragments: 487 + 487 + 1
	largeData := make([]byte, 975)
	sendErr := h.SendPacket(byte(PacketTypeCommand), largeData, 0)
	if sendErr != nil {
		t.Fatalf("SendPacket error: %v", sendErr)
	}

	// Collect 3 fragments.
	pkts := make([][]byte, 0, 3)
	for range 3 {
		pkts = append(pkts, readPacket(t, serverConn))
	}

	// C2S raw layout: [8 tag][2 pktID][2 clientID][1 TypeFlagged][ciphertext]
	// TypeFlagged byte is at index 12.
	fragFlag := byte(PacketFlagFragmented)
	// Fragment 0 (first=true, last=false): Fragmented set
	if pkts[0][12]&fragFlag == 0 {
		t.Errorf("fragment 0 should have Fragmented flag, TypeFlagged=0x%02x", pkts[0][12])
	}
	// Fragment 1 (first=false, last=false): Fragmented NOT set
	if pkts[1][12]&fragFlag != 0 {
		t.Errorf("fragment 1 (middle) should NOT have Fragmented flag, TypeFlagged=0x%02x", pkts[1][12])
	}
	// Fragment 2 (first=false, last=true): Fragmented set
	if pkts[2][12]&fragFlag == 0 {
		t.Errorf("fragment 2 (last) should have Fragmented flag, TypeFlagged=0x%02x", pkts[2][12])
	}
}

// TestHandlerSendPacket_ExactBoundary_NoSplit verifies that a 487-byte payload
// (exactly the max) is sent as a single packet.
func TestHandlerSendPacket_ExactBoundary_NoSplit(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	sendErr := h.SendPacket(byte(PacketTypeCommand), make([]byte, 487), 0)
	if sendErr != nil {
		t.Fatalf("SendPacket: %v", sendErr)
	}

	pkt := readPacket(t, serverConn)
	if pkt[12]&byte(PacketFlagFragmented) != 0 {
		t.Error("exact-boundary packet should not have Fragmented flag")
	}

	// Ensure no second fragment arrives.
	select {
	case extra := <-func() chan []byte {
		ch := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 4096)
			n, readErr := serverConn.Read(buf)
			if readErr == nil {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				ch <- cp
			}
		}()

		return ch
	}():
		t.Errorf("unexpected second packet: %d bytes", len(extra))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandlerSendVoicePacket_Format(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	voiceData := []byte{0x01, 0x02, 0x03, 0x04}
	const codec = byte(4) // Opus Voice
	sendErr := h.SendVoicePacket(voiceData, codec)
	if sendErr != nil {
		t.Fatalf("SendVoicePacket: %v", sendErr)
	}

	pkt := readPacket(t, serverConn)
	if len(pkt) < 13+3+len(voiceData) {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}

	// Tag bytes 0-7 should be FakeSignature (all zeros for unused crypto state).
	fakeSig := h.TsCrypt.FakeSignature()
	for i, b := range fakeSig {
		if pkt[i] != b {
			t.Errorf("tag[%d]: expected 0x%02x (FakeSignature), got 0x%02x", i, b, pkt[i])
		}
	}

	// TypeFlagged byte 12: type = PacketTypeVoice (0), flags = Unencrypted (0x80)
	if pkt[12]&0x0F != byte(PacketTypeVoice) {
		t.Errorf("expected PacketTypeVoice (0), got %d", pkt[12]&0x0F)
	}
	if pkt[12]&byte(PacketFlagUnencrypted) == 0 {
		t.Error("voice packet should have Unencrypted flag")
	}

	// Payload: [2 seqID][1 codec][data]
	if pkt[13+2] != codec {
		t.Errorf("expected codec=0x%02x, got 0x%02x", codec, pkt[13+2])
	}
}

func TestHandlerSendVoicePacket_SequenceIncreases(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	for i := range 3 {
		voiceSendErr := h.SendVoicePacket([]byte{byte(i)}, 4)
		if voiceSendErr != nil {
			t.Fatalf("SendVoicePacket[%d]: %v", i, voiceSendErr)
		}
	}

	pkt0 := readPacket(t, serverConn)
	pkt1 := readPacket(t, serverConn)

	seq0 := binary.BigEndian.Uint16(pkt0[13:15])
	seq1 := binary.BigEndian.Uint16(pkt1[13:15])
	if seq1 != seq0+1 {
		t.Errorf("expected seq1 = seq0+1 = %d, got %d", seq0+1, seq1)
	}
}

func TestHandlerSendWhisperPacket_Format(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	audio := []byte{0xaa, 0xbb, 0xcc}
	err := h.SendWhisperPacket(audio, []uint16{0x0102, 0x0304}, nil, 5)
	if err != nil {
		t.Fatalf("SendWhisperPacket: %v", err)
	}

	pkt := readPacket(t, serverConn)
	if pkt[12]&0x0F != byte(PacketTypeVoiceWhisper) {
		t.Errorf("expected PacketTypeVoiceWhisper (1), got %d", pkt[12]&0x0F)
	}
	if pkt[12]&byte(PacketFlagUnencrypted) == 0 {
		t.Error("whisper packet should have Unencrypted flag")
	}

	// Payload: [2 voiceID][1 codec][1 channel count][1 client count][2*N client IDs][data]
	payload := pkt[13:]
	if payload[2] != 5 || payload[3] != 0 || payload[4] != 2 {
		t.Errorf("header codec/channels/clients = %d/%d/%d, want 5/0/2", payload[2], payload[3], payload[4])
	}
	if got := binary.BigEndian.Uint16(payload[5:7]); got != 0x0102 {
		t.Errorf("target[0] = %#04x, want 0x0102", got)
	}
	if got := binary.BigEndian.Uint16(payload[7:9]); got != 0x0304 {
		t.Errorf("target[1] = %#04x, want 0x0304", got)
	}
	if !bytes.Equal(payload[9:], audio) {
		t.Errorf("audio = %x, want %x", payload[9:], audio)
	}
}

func TestHandlerSendWhisperPacket_RejectsUnencodableTargets(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	err := h.SendWhisperPacket([]byte{1}, nil, nil, 5)
	if !errors.Is(err, ErrNoWhisperTargets) {
		t.Errorf("no targets: got %v, want ErrNoWhisperTargets", err)
	}
	err = h.SendWhisperPacket([]byte{1}, make([]uint16, 33), nil, 5)
	if !errors.Is(err, ErrTooManyWhisperTargets) {
		t.Errorf("33 targets: got %v, want ErrTooManyWhisperTargets", err)
	}
}

func TestHandlerSendWhisperPacket_RejectsTooManyChannels(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	err := h.SendWhisperPacket([]byte{1}, nil, make([]uint64, 256), 5)
	if !errors.Is(err, ErrTooManyWhisperChannels) {
		t.Errorf("256 channels: got %v, want ErrTooManyWhisperChannels", err)
	}
	err = h.SendWhisperPacket([]byte{1}, nil, make([]uint64, 255), 5)
	if err != nil {
		t.Errorf("255 channels: %v", err)
	}
}

// The direct form, byte for byte: no new-protocol flag, then VId, C, N, M, the
// u64 channel ids, the u16 client ids and the data.
func TestHandlerSendWhisperPacket_ChannelsAndClientsLayout(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	err := h.SendWhisperPacket([]byte{0xaa, 0xbb}, []uint16{0x0102}, []uint64{0x0102030405060708, 9}, 5)
	if err != nil {
		t.Fatal(err)
	}
	pkt := readPacket(t, serverConn)
	if pkt[12] != byte(PacketTypeVoiceWhisper)|byte(PacketFlagUnencrypted) {
		t.Errorf("type byte = %#02x, want whisper and unencrypted only", pkt[12])
	}
	want := []byte{
		0x00, 0x00, // voice packet id
		5, 2, 1,
		1, 2, 3, 4, 5, 6, 7, 8,
		0, 0, 0, 0, 0, 0, 0, 9,
		0x01, 0x02,
		0xaa, 0xbb,
	}
	if !bytes.Equal(pkt[13:], want) {
		t.Errorf("payload = %x, want %x", pkt[13:], want)
	}
}

// The group form, byte for byte: the new-protocol flag, then VId, C, TY, TA, a
// u64 id and the data.
func TestHandlerSendGroupWhisperPacket_Layout(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	err := h.SendGroupWhisperPacket([]byte{0xaa}, 1, 4, 0x0a0b, 5)
	if err != nil {
		t.Fatal(err)
	}
	pkt := readPacket(t, serverConn)
	if pkt[12] != byte(PacketTypeVoiceWhisper)|byte(PacketFlagUnencrypted)|byte(PacketFlagNewProtocol) {
		t.Errorf("type byte = %#02x, want whisper, unencrypted and new protocol", pkt[12])
	}
	want := []byte{0, 0, 5, 1, 4, 0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0xaa}
	if !bytes.Equal(pkt[13:], want) {
		t.Errorf("payload = %x, want %x", pkt[13:], want)
	}
	err = h.SendGroupWhisperPacket(nil, 3, 0, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	pkt = readPacket(t, serverConn)
	if got := binary.BigEndian.Uint16(pkt[13:15]); got != 1 {
		t.Errorf("second voice packet id = %d, want 1", got)
	}
	if len(pkt[13:]) != 13 {
		t.Errorf("payload length = %d, want 13", len(pkt[13:]))
	}
}

func TestHandlerReceivedFinalInitAck_ClearsInitPacketCheck(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)

	h.mu.Lock()
	hasCheck := h.initPacketCheck != nil
	h.mu.Unlock()

	if !hasCheck {
		t.Error("expected initPacketCheck to be set after Start()")
	}

	h.ReceivedFinalInitAck()

	h.mu.Lock()
	hasCheck = h.initPacketCheck != nil
	h.mu.Unlock()

	if hasCheck {
		t.Error("expected initPacketCheck to be nil after ReceivedFinalInitAck()")
	}
}

func TestHandlerCheckResends_InitPacket_ReSent(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	// Drain the initial Init1 packet.
	_ = readPacket(t, serverConn)

	// Fast-forward initPacketCheck.lastSend so checkResends triggers a resend.
	h.mu.Lock()
	if h.initPacketCheck != nil {
		h.initPacketCheck.lastSend = time.Now().Add(-time.Second)
	}
	h.mu.Unlock()

	h.checkResends()

	// A resent Init1 packet should now appear on serverConn.
	resent := readPacket(t, serverConn)
	if len(resent) < 13 {
		t.Fatalf("expected resent Init1, got %d bytes", len(resent))
	}
	if resent[12]&0x0F != byte(PacketTypeInit1) {
		t.Errorf("expected PacketTypeInit1, got type %d", resent[12]&0x0F)
	}
}

// answerInit1 makes h answer each Init1 packet it receives the way the client
// does: from inside delivery, with whatever step ProcessInit1 gives, or nothing.
func answerInit1(h *PacketHandler) {
	h.OnPacket = func(p *Packet) {
		if p.Type() != PacketTypeInit1 {
			return
		}
		response, err := handshake.ProcessInit1(context.Background(), h.TsCrypt, p.Data)
		if err != nil || response == nil {
			return
		}
		_ = h.SendPacket(byte(PacketTypeInit1), response, 0)
	}
}

// injectInit1 delivers an Init1 packet from the server whose payload starts
// with step, and returns what the handler sent while handling it. The packet
// is followed by a ping: the handler handles packets in order, so its pong
// means the Init1 is entirely handled, state updates after delivery included.
func injectInit1(t *testing.T, serverConn *packetPipe, step byte) [][]byte {
	t.Helper()

	data := make([]byte, 21)
	data[0] = step
	_, err := serverConn.Write(buildS2CPacket(make([]byte, 8), 0, byte(PacketTypeInit1), data))
	if err != nil {
		t.Fatalf("Write Init1: %v", err)
	}
	ping := buildS2CPacket(make([]byte, 8), 1, byte(PacketTypePing)|byte(PacketFlagUnencrypted), []byte{0, 1})
	_, err = serverConn.Write(ping)
	if err != nil {
		t.Fatalf("Write ping: %v", err)
	}

	var sent [][]byte
	for {
		pkt := readPacket(t, serverConn)
		if len(pkt) >= 13 && pkt[12]&0x0F == byte(PacketTypePong) {
			return sent
		}
		sent = append(sent, pkt)
	}
}

// makeInitResendDue moves the pending Init1 packet's last send back, so the
// next checkResends sends it again.
func makeInitResendDue(h *PacketHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.initPacketCheck != nil {
		h.initPacketCheck.lastSend = time.Now().Add(-time.Minute)
	}
}

// expectNoPacket fails if the handler sends anything within d.
func expectNoPacket(t *testing.T, serverConn *packetPipe, d time.Duration) {
	t.Helper()
	select {
	case pkt := <-serverConn.recv:
		t.Errorf("expected nothing to be sent, got a packet of %d bytes (type %d)", len(pkt), pkt[12]&0x0F)
	case <-time.After(d):
	}
}

func TestHandlerCheckResends_StepAnsweredInDelivery_IsTheOneResent(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	step0 := readPacket(t, serverConn)
	answerInit1(h)

	// The server's reply to step 0 is answered from inside delivery, so the
	// client's next step is sent while the received Init1 is still being handled.
	sent := injectInit1(t, serverConn, 0)
	if len(sent) != 1 {
		t.Fatalf("handler sent %d packets in answer to the server's step, want 1", len(sent))
	}
	answer := sent[0]
	if bytes.Equal(answer, step0) {
		t.Fatal("the answer is the same packet as step 0, the test cannot tell them apart")
	}

	makeInitResendDue(h)
	h.checkResends()

	resent := readPacket(t, serverConn)
	if bytes.Equal(resent, step0) {
		t.Error("resent step 0 after the client moved on to its next step")
	}
	if !bytes.Equal(resent, answer) {
		t.Errorf("resent packet is not the client's latest step:\n got %x\nwant %x", resent, answer)
	}
}

func TestHandlerCheckResends_IgnoredInit1_KeepsPendingStepResending(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	step0 := readPacket(t, serverConn)
	answerInit1(h)

	// A step the client does not know gets no answer.
	sent := injectInit1(t, serverConn, 0x55)
	if len(sent) != 0 {
		t.Fatalf("handler answered a step it does not know with %d packets", len(sent))
	}

	makeInitResendDue(h)
	h.checkResends()

	resent := readPacket(t, serverConn)
	if !bytes.Equal(resent, step0) {
		t.Errorf("resent packet is not the pending step:\n got %x\nwant %x", resent, step0)
	}
}

func TestHandlerCheckResends_AfterFinalInitAck_NothingResent(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn)
	answerInit1(h)

	sent := injectInit1(t, serverConn, 0)
	if len(sent) != 1 {
		t.Fatalf("handler sent %d packets in answer to the server's step, want 1", len(sent))
	}

	// Until the final acknowledgement, the step the client sent is still pending.
	makeInitResendDue(h)
	h.checkResends()
	resent := readPacket(t, serverConn)
	if !bytes.Equal(resent, sent[0]) {
		t.Fatalf("pending step was not resent before the final acknowledgement:\n got %x\nwant %x", resent, sent[0])
	}

	h.ReceivedFinalInitAck()
	makeInitResendDue(h)
	h.checkResends()

	// Longer than the resend loop's interval, so its own run is covered too.
	expectNoPacket(t, serverConn, 3*resendLoopInterval)
}

func TestHandlerCheckResends_IdleTimeout_ClosesHandler(t *testing.T) {
	h, serverConn := newTestHandler(t)
	closed := make(chan error, 1)
	h.OnClosed = func(err error) { closed <- err }
	_ = readPacket(t, serverConn)

	// Simulate idle timeout: set lastMessageReceived to a distant past.
	h.mu.Lock()
	h.lastMessageReceived = time.Now().Add(-(PacketTimeout + time.Second))
	h.mu.Unlock()

	h.checkResends()

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("expected handler to close on idle timeout")
	}
}

func TestHandlerClose_IdempotentNoError(t *testing.T) {
	h, serverConn := newTestHandler(t)
	_ = readPacket(t, serverConn)

	err := h.Close()
	if err != nil {
		t.Errorf("first Close() returned error: %v", err)
	}
	err = h.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}
