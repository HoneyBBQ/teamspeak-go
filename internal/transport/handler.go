// Package transport speaks the TeamSpeak voice protocol's packet layer over
// UDP: it encrypts and decrypts packets, numbers them per type with wrapping
// id generations, acknowledges and resends commands, resends the handshake's
// Init1 packets until the server's final reply, splits and reassembles
// fragmented commands, decompresses QuickLZ payloads, and keeps the connection
// alive with pings.
//
// Callers above it see whole, decrypted packets through PacketHandler.OnPacket.
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
)

// Sizes and timings of the packet layer.
const (
	// MaxOutPacketSize is the largest datagram sent, tag and header included;
	// longer command payloads are split into fragments.
	MaxOutPacketSize = 500
	// ReceivePacketWindowSize is how many command ids past the next expected
	// one are accepted and queued.
	ReceivePacketWindowSize = 1024
	// PingInterval is how often a ping is sent once the handshake completes.
	PingInterval = 5 * time.Second
	// PacketTimeout is how long the server may stay silent, or leave a command
	// unacknowledged, before the connection is closed with ErrTimedOut.
	PacketTimeout = 60 * time.Second
	// MaxRetryInterval caps the doubling interval between resends.
	MaxRetryInterval = time.Second

	// maxDatagramSize is the largest datagram accepted. The servers send at
	// most MaxOutPacketSize; a larger one is dropped, not truncated.
	maxDatagramSize = 4096
	// udpReadBufferSize has one byte more, so a larger datagram shows as one
	// rather than being cut to size.
	udpReadBufferSize = maxDatagramSize + 1
	// maxQueuedCommandBytes caps the bytes of command and command-low packets
	// held for reordering and reassembly, together. Past it, a packet is
	// dropped unacknowledged, so the server sends it again; the one packet the
	// queue is waiting for is always taken, so the queue keeps draining.
	maxQueuedCommandBytes  = 1 << 20
	voicePayloadBufferSize = 1027
	smallPacketBufferSize  = 2
	packetProcessQueueSize = 2048
	resendBaseInterval     = 500 * time.Millisecond
	resendLoopInterval     = 100 * time.Millisecond
	headerSize             = 5
	tagSize                = 8
	voiceHeaderSize        = 3
	whisperHeaderSize      = 5
	maxWhisperTargets      = 32
	ackDataSize            = 2
)

var (
	// ErrTimedOut reports a connection the server stopped answering: nothing
	// arrived, or a packet went unacknowledged, for PacketTimeout.
	ErrTimedOut = errors.New("connection timed out: the server stopped answering")
	// ErrNoWhisperTargets is returned when a whisper is sent to no clients.
	ErrNoWhisperTargets = errors.New("whisper requires at least one target client")
	// ErrTooManyWhisperTargets is returned when a whisper names more than 32 clients.
	ErrTooManyWhisperTargets = errors.New("whisper supports at most 32 target clients")
	// ErrNotOpen is returned by a send on a handler that has not started or
	// has closed.
	ErrNotOpen = errors.New("connection is not open")
	// ErrPacketHandling is the cause a handler closes with when handling a
	// received packet panicked: the connection's state can no longer be
	// trusted.
	ErrPacketHandling = errors.New("handling a received packet failed")
)

// MaxReassembledSize caps a command reassembled from fragments; a larger one is
// dropped. It matches MaxDecompressedSize, for the reasons given there.
const MaxReassembledSize = MaxDecompressedSize

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, udpReadBufferSize)

		return &buf
	},
}

// voicePayloadPool holds buffers for the 3-byte voice header plus Opus frame.
var voicePayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, voicePayloadBufferSize)

		return &buf
	},
}

// smallBufPool holds 2-byte buffers for ACK/Pong payloads.
var smallBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, smallPacketBufferSize)

		return &buf
	},
}

type pooledBuffer struct {
	buf []byte
	n   int
}

// PacketHandler runs one voice protocol connection: it sends packets with the
// next id and generation for their type, resends commands until they are
// acknowledged, and delivers received packets in order through OnPacket.
type PacketHandler struct {
	lastMessageReceived time.Time
	conn                io.ReadWriteCloser
	// closeCause is why the handler closed itself, reported to OnClosed; nil
	// for a Close from outside. Guarded by lifecycleMu.
	closeCause           error
	commandQueue         map[uint16]*Packet
	commandLowQueue      map[uint16]*Packet
	stopCh               chan struct{}
	recvWindowCommand    *GenerationWindow
	recvWindowCommandLow *GenerationWindow
	sendWindowCommand    *GenerationWindow
	sendWindowCommandLow *GenerationWindow
	ackManager           map[uint32]*resendPacket
	// initPacketCheck is the last Init1 packet the client sent, resent until
	// the handshake's final acknowledgement. Init1 packets are not acknowledged
	// one by one: each step the client sends replaces it, and only
	// ReceivedFinalInitAck clears it. Receiving an Init1 does not, as the
	// client may have nothing to answer with. Guarded by mu.
	initPacketCheck *resendPacket
	packetProcessCh chan *pooledBuffer
	OnClosed        func(err error)
	// OnOpen, when set before Start, is called once the connection is attached
	// and before the first handshake packet is sent, with the local address of
	// the connection ("" if it has none).
	OnOpen   func(localAddr string)
	logger   *slog.Logger
	OnAck    func(id uint16)
	OnPacket func(p *Packet)
	TsCrypt  *crypto.Crypt
	// readerDone is closed when the receive loop has stopped reading.
	readerDone        chan struct{}
	generationCounter [9]uint32
	mu                sync.Mutex
	// lifecycleMu orders Start and Close: a Close that races a Start either
	// sees the connection and closes it, or makes Start refuse it.
	lifecycleMu sync.Mutex
	closed      atomic.Bool
	started     atomic.Bool
	// resends counts the packets sent again by the resend loop.
	resends atomic.Int64
	// queuedBytes is the payload size of everything in commandQueue and
	// commandLowQueue. Guarded by mu.
	queuedBytes   int
	packetCounter [9]uint16
	// clientID is written once the server assigns it and read on every send.
	clientID atomic.Uint32
	// clientEkID is the id of the last Command sent with the dummy key, or -1.
	// The server acknowledges that packet — clientek, the last one before the
	// shared secret exists — with the dummy key even though the client has
	// already switched to the real one, so its Ack is the one packet the dummy
	// key is accepted for once crypto init is complete.
	clientEkID       atomic.Int32
	nextCommandLowID uint16
	nextCommandID    uint16
}

type resendPacket struct {
	packet       *Packet
	firstSend    time.Time
	lastSend     time.Time
	retryCount   int
	nextInterval time.Duration
}

type decryptPacketResult struct {
	plaintext []byte
	dummyUsed bool
}

// NewPacketHandler returns a handler that encrypts with tsCrypt and logs to
// logger (nil means slog.Default). It sends nothing until Connect or Start.
func NewPacketHandler(tsCrypt *crypto.Crypt, logger *slog.Logger) *PacketHandler {
	if logger == nil {
		logger = slog.Default()
	}

	h := &PacketHandler{
		readerDone:           make(chan struct{}),
		TsCrypt:              tsCrypt,
		logger:               logger,
		ackManager:           make(map[uint32]*resendPacket),
		packetProcessCh:      make(chan *pooledBuffer, packetProcessQueueSize),
		stopCh:               make(chan struct{}),
		recvWindowCommand:    NewGenerationWindow(1<<16, ReceivePacketWindowSize),
		recvWindowCommandLow: NewGenerationWindow(1<<16, ReceivePacketWindowSize),
		sendWindowCommand:    NewGenerationWindow(1<<16, ReceivePacketWindowSize),
		sendWindowCommandLow: NewGenerationWindow(1<<16, ReceivePacketWindowSize),
		commandQueue:         make(map[uint16]*Packet),
		commandLowQueue:      make(map[uint16]*Packet),
		lastMessageReceived:  time.Now(),
	}
	h.clientEkID.Store(-1)

	return h
}

// Resends is how many packets the handler has sent again, handshake packets
// and commands alike, since it was created. A handler serves one connection
// attempt, so it is the attempt's count.
func (h *PacketHandler) Resends() int {
	return int(h.resends.Load())
}

// LocalAddr is the host:port of the connection's local end, or "" when the
// connection does not say. Valid once the handler has started.
func (h *PacketHandler) LocalAddr() string {
	type localAddrer interface{ LocalAddr() net.Addr }
	if l, ok := h.conn.(localAddrer); ok {
		if a := l.LocalAddr(); a != nil {
			return a.String()
		}
	}

	return ""
}

// SetClientID sets the client id the server assigned, which every packet the
// client sends carries in its header.
func (h *PacketHandler) SetClientID(id uint16) {
	h.clientID.Store(uint32(id))
}

// Connect resolves and dials addr over UDP, both bounded by ctx, and calls
// Start. A handler closed while the socket was opening closes the socket
// instead of starting on it.
func (h *PacketHandler) Connect(ctx context.Context, addr string) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}

	return h.Start(conn)
}

// WaitReaderStopped waits, until ctx is done, for a closed handler's receive
// loop to stop reading from its connection. A handler that never started
// returns at once.
//
// A connection that outlives the handler — a caller's PacketConn — must not
// be read by two handlers at once, or the old one takes datagrams meant for
// the new.
func (h *PacketHandler) WaitReaderStopped(ctx context.Context) error {
	if !h.started.Load() {
		return nil
	}
	select {
	case <-h.readerDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Start attaches conn to the handler, launches background goroutines, and sends
// the initial Init1 handshake packet. conn must implement io.ReadWriteCloser
// with datagram-style semantics (each Write produces one discrete message).
func (h *PacketHandler) Start(conn io.ReadWriteCloser) error {
	h.lifecycleMu.Lock()
	if h.closed.Load() {
		h.lifecycleMu.Unlock()
		_ = conn.Close()

		return net.ErrClosed
	}
	h.mu.Lock()
	h.packetCounter[PacketTypeCommand]++
	h.packetCounter[PacketTypeInit1] = 101
	h.mu.Unlock()
	// conn is written once, before started: a sender that sees started set
	// sees conn too.
	h.conn = conn
	h.started.Store(true)
	h.lifecycleMu.Unlock()

	go h.receiveLoop()
	go h.processLoop()
	go h.resendLoop()
	go h.pingLoop()

	if h.OnOpen != nil {
		h.OnOpen(h.LocalAddr())
	}

	init1Data, err := handshake.StartInit1()
	if err != nil {
		return err
	}

	return h.SendPacket(byte(PacketTypeInit1), init1Data, 0)
}

// SendPacket sends data as one packet of type pType, splitting a command
// payload too large for one datagram into fragments. Until the crypto
// handshake completes it encrypts with the protocol's fixed dummy key. On a
// handler that is not open it returns ErrNotOpen.
func (h *PacketHandler) SendPacket(pType byte, data []byte, flags byte) error {
	if !h.IsOpen() {
		return ErrNotOpen
	}
	dummy := !h.TsCrypt.InitComplete()

	// Fragment non-voice command payloads larger than one UDP frame (487 B body).
	if len(data) > 487 && pType != 0 && pType != 1 {
		return h.sendSplitPacket(pType, data, flags, dummy)
	}

	return h.sendPacket(pType, data, flags, dummy)
}

func (h *PacketHandler) sendSplitPacket(pType byte, data []byte, flags byte, dummy bool) error {
	maxSize := 487 // MaxOutPacketSize(500) - Header(5) - Tag(8)
	pos := 0
	first := true

	for pos < len(data) {
		blockSize := min(len(data)-pos, maxSize)

		last := (pos + blockSize) == len(data)

		pFlags := flags
		// TeamSpeak sets Fragmented on the first and last chunk only.
		if first != last {
			pFlags |= byte(PacketFlagFragmented)
		}

		err := h.sendPacket(pType, data[pos:pos+blockSize], pFlags, dummy)
		if err != nil {
			return err
		}

		pos += blockSize
		first = false
	}

	return nil
}

func (h *PacketHandler) sendPacket(pType byte, data []byte, flags byte, dummy bool) error {
	flags = applyProtocolFlags(pType, flags)
	pID, pGen := h.nextPacketIdentity(pType)

	p := &Packet{
		TypeFlagged:  pType | flags,
		ID:           pID,
		GenerationID: pGen,
		Data:         data,
		ClientID:     uint16(h.clientID.Load()), //nolint:gosec // stored from a uint16
	}

	unencrypted := (flags&byte(PacketFlagUnencrypted) != 0)
	header := p.BuildC2SHeader()
	ciphertext, tag, err := h.TsCrypt.Encrypt(pType, p.ID, p.GenerationID, header, p.Data, dummy, unencrypted)
	if err != nil {
		return err
	}
	if dummy && !unencrypted && pType == byte(PacketTypeCommand) {
		h.clientEkID.Store(int32(pID))
	}

	final := getPooledBytes(&bufPool, tagSize+headerSize+len(ciphertext))
	defer putPooledBytes(&bufPool, final)

	copy(final[0:8], tag)
	copy(final[8:13], header)
	copy(final[13:], ciphertext)

	_, err = h.conn.Write(final[:tagSize+headerSize+len(ciphertext)])

	rp := &resendPacket{
		packet:       p,
		firstSend:    time.Now(),
		lastSend:     time.Now(),
		nextInterval: resendBaseInterval,
	}
	h.trackResendPacket(pType, p, rp)

	return err
}

func (h *PacketHandler) sendPong(pID uint16, dummy bool) error {
	pongData := getPooledBytes(&smallBufPool, smallPacketBufferSize)
	binary.BigEndian.PutUint16(pongData, pID)
	err := h.sendPacket(byte(PacketTypePong), pongData, byte(PacketFlagUnencrypted), dummy)
	putPooledBytes(&smallBufPool, pongData)

	return err
}

func (h *PacketHandler) receiveLoop() {
	var finalErr error
	defer func() {
		if h.OnClosed != nil {
			h.OnClosed(finalErr)
		}
	}()

	for {
		buf := getPooledBytes(&bufPool, udpReadBufferSize)
		n, err := h.conn.Read(buf)
		if err == nil && n > maxDatagramSize {
			h.logger.Debug("datagram too large, dropping it", slog.Int("min_length", n))
			putPooledBytes(&bufPool, buf)

			continue
		}
		if err != nil {
			close(h.readerDone)
			putPooledBytes(&bufPool, buf)
			select {
			case <-h.stopCh:
				h.lifecycleMu.Lock()
				finalErr = h.closeCause
				h.lifecycleMu.Unlock()

				return
			default:
				// Debug, not Error: the error goes to OnClosed, which reports it.
				h.logger.Debug("udp read failed", slog.Any("error", err))
				finalErr = err

				return
			}
		}

		select {
		case h.packetProcessCh <- &pooledBuffer{buf: buf, n: n}:
		default:
			h.logger.Warn("packet process channel full, dropping packet")
			putPooledBytes(&bufPool, buf)
		}
	}
}

func (h *PacketHandler) processLoop() {
	for {
		select {
		case <-h.stopCh:
			return
		case pb := <-h.packetProcessCh:
			h.handleRawPacketSafely(pb.buf[:pb.n])
			putPooledBytes(&bufPool, pb.buf)
			if h.closed.Load() {
				return
			}
		}
	}
}

// handleRawPacketSafely handles one datagram, turning a panic anywhere below —
// parsing, decryption, reassembly, decompression or OnPacket — into a closed
// connection whose cause wraps ErrPacketHandling, rather than a crashed
// process.
func (h *PacketHandler) handleRawPacketSafely(raw []byte) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		h.logger.Error("handling a received packet panicked, closing the connection",
			slog.Any("panic", r), slog.Int("length", len(raw)))
		_ = h.closeWith(fmt.Errorf("%w: %v", ErrPacketHandling, r))
	}()

	h.handleRawPacket(raw)
}

func (h *PacketHandler) handleRawPacket(raw []byte) {
	if len(raw) < 11 {
		return
	}

	tag := raw[0:8]
	header := raw[8:11]
	ciphertext := raw[11:]
	p := parseServerPacket(header)
	if p.Type() > PacketTypeInit1 {
		return
	}
	// Init1 belongs to the handshake; once a shared secret exists, a late or
	// replayed one could only restart what has finished.
	if p.Type() == PacketTypeInit1 && h.TsCrypt.InitComplete() {
		return
	}
	p.ReceivedAt = time.Now()

	decrypted, ok := h.decryptPacketData(p, header, ciphertext, tag)
	if !ok {
		return
	}
	// Only a packet that authenticates counts as hearing from the server;
	// noise must not keep a dead connection from timing out.
	h.markMessageReceived()
	p.Data = decrypted.plaintext

	if p.Type() == PacketTypePing {
		_ = h.sendPong(p.ID, decrypted.dummyUsed)

		return
	}

	if !h.handleCommandWindowAndAck(p, decrypted.dummyUsed) {
		return
	}

	h.handlePacketQueue(p)
	h.updatePostReceiveState(p)
}

func (h *PacketHandler) getWinForType(pType PacketType) *GenerationWindow {
	switch pType {
	case PacketTypeCommand:
		return h.recvWindowCommand
	case PacketTypeCommandLow:
		return h.recvWindowCommandLow
	case PacketTypeVoice, PacketTypeVoiceWhisper, PacketTypePing, PacketTypePong,
		PacketTypeAck, PacketTypeAckLow, PacketTypeInit1:
		return nil
	default:
		return nil
	}
}

func (h *PacketHandler) handlePacketQueue(p *Packet) {
	pType := p.Type()
	if pType != PacketTypeCommand && pType != PacketTypeCommandLow {
		if h.OnPacket != nil {
			h.OnPacket(p)
		}

		return
	}

	// Delivered outside the lock, so OnPacket may send.
	for _, ready := range h.takeReadyCommands(p) {
		if h.OnPacket != nil {
			h.OnPacket(ready)
		}
	}
}

// takeReadyCommands queues a received command packet and returns, in order,
// every command that is now complete: reassembled and decompressed.
func (h *PacketHandler) takeReadyCommands(p *Packet) []*Packet {
	h.mu.Lock()
	defer h.mu.Unlock()

	pType := p.Type()
	var queue map[uint16]*Packet
	var nextID *uint16
	var win *GenerationWindow
	if pType == PacketTypeCommand {
		queue = h.commandQueue
		nextID = &h.nextCommandID
		win = h.recvWindowCommand
	} else {
		queue = h.commandLowQueue
		nextID = &h.nextCommandLowID
		win = h.recvWindowCommandLow
	}

	if old, ok := queue[p.ID]; ok {
		h.queuedBytes -= len(old.Data)
	}
	queue[p.ID] = p
	h.queuedBytes += len(p.Data)

	// If the expected ID never arrives, skip it once a newer fragment has stalled long enough.
	h.fastForwardMissingPackets(pType, queue, nextID)

	var ready []*Packet
	for {
		packet, ok := queue[*nextID]
		if !ok {
			h.logQueueBacklog(pType, queue, *nextID)

			break
		}

		reassembled, consumed := h.tryReassemble(packet, queue, nextID, win)
		if !consumed {
			break
		}
		if reassembled == nil || !h.tryDecompressPacket(reassembled) {
			continue
		}
		ready = append(ready, reassembled)
	}

	return ready
}

func parseServerPacket(header []byte) *Packet {
	p := &Packet{}
	p.ParseS2CHeader(header)

	return p
}

func (h *PacketHandler) markMessageReceived() {
	h.mu.Lock()
	h.lastMessageReceived = time.Now()
	h.mu.Unlock()
}

func (h *PacketHandler) resolvePacketGeneration(p *Packet) uint32 {
	var gen uint32
	h.mu.Lock()
	switch p.Type() {
	case PacketTypeCommand:
		gen = h.recvWindowCommand.GetGeneration(int(p.ID))
	case PacketTypeCommandLow:
		gen = h.recvWindowCommandLow.GetGeneration(int(p.ID))
	case PacketTypeAck:
		gen = h.sendWindowCommand.GetGeneration(int(p.ID))
	case PacketTypeAckLow:
		gen = h.sendWindowCommandLow.GetGeneration(int(p.ID))
	case PacketTypeVoice, PacketTypeVoiceWhisper, PacketTypePing, PacketTypePong, PacketTypeInit1:
		// No generation tracking for these packet types.
	default:
		// Unknown packet type, keep generation as zero.
	}
	h.mu.Unlock()

	return gen
}

func (h *PacketHandler) decryptPacketData(
	p *Packet, header, ciphertext, tag []byte,
) (*decryptPacketResult, bool) {
	unencrypted := (p.Flags() & PacketFlagUnencrypted) != 0
	if unencrypted && !mayArriveUnencrypted(p.Type()) {
		h.logger.Debug("unencrypted packet of an encrypted type, dropping it",
			slog.Uint64("type", uint64(p.Type())),
			slog.Uint64("id", uint64(p.ID)))

		return nil, false
	}
	gen := h.resolvePacketGeneration(p)

	if !h.TsCrypt.InitComplete() {
		plaintext, err := h.TsCrypt.Decrypt(byte(p.Type()), p.ID, gen, header, ciphertext, tag, true, unencrypted)
		if err != nil {
			h.logDecryptFailure(p, gen, err)

			return nil, false
		}

		return &decryptPacketResult{plaintext: plaintext, dummyUsed: true}, true
	}

	// Decrypted under the generation the window gives the id and no other:
	// guessing the previous one would accept a packet recorded before the id
	// wrapped and replayed after, and guessing the next one never decrypted a
	// packet on TeamSpeak 3 or 6.
	plaintext, err := h.TsCrypt.Decrypt(byte(p.Type()), p.ID, gen, header, ciphertext, tag, false, unencrypted)
	dummyUsed := false
	if err != nil && !unencrypted && p.Type() == PacketTypeAck {
		plaintext, err = h.decryptClientEkAck(p, gen, header, ciphertext, tag)
		dummyUsed = err == nil
	}
	if err != nil {
		h.logDecryptFailure(p, gen, err)

		return nil, false
	}

	return &decryptPacketResult{plaintext: plaintext, dummyUsed: dummyUsed}, true
}

// mayArriveUnencrypted reports whether a packet of type t is accepted with the
// Unencrypted flag. Such a packet is authenticated only by the fake
// signature, which every plaintext ping and voice packet shows to anyone on
// the path, so the flag is honoured only where TeamSpeak 3 and 6 were
// measured to use it: Init1 before crypto init, and voice, whisper, ping,
// pong and Ack after it. AckLow was not seen but is allowed as Ack is: an Ack
// carries nothing but a packet ID, so a forged one can at most stop one
// resend. Command and CommandLow are never sent unencrypted; one that claims
// to be is dropped, so text messages, kicks and command answers cannot be
// forged.
func mayArriveUnencrypted(t PacketType) bool {
	switch t {
	case PacketTypeVoice, PacketTypeVoiceWhisper, PacketTypePing, PacketTypePong,
		PacketTypeAck, PacketTypeAckLow, PacketTypeInit1:
		return true
	case PacketTypeCommand, PacketTypeCommandLow:
		return false
	default:
		return false
	}
}

func (h *PacketHandler) logDecryptFailure(p *Packet, gen uint32, err error) {
	h.logger.Debug("packet decryption failed, dropping it",
		slog.Uint64("type", uint64(p.Type())),
		slog.Uint64("id", uint64(p.ID)),
		slog.Uint64("gen", uint64(gen)),
		slog.Any("error", err))
}

var errDecryptFailed = errors.New("decrypt failed")

// decryptClientEkAck accepts the one dummy-key packet that arrives after crypto
// init completes: the server's Ack for clientek, measured on TeamSpeak 3 and
// 6. Anything else under the dummy key, including an Ack for another packet,
// is refused; the dummy key is public.
func (h *PacketHandler) decryptClientEkAck(
	p *Packet, gen uint32, header, ciphertext, tag []byte,
) ([]byte, error) {
	pending := h.clientEkID.Load()
	if pending < 0 {
		return nil, errDecryptFailed
	}
	plaintext, err := h.TsCrypt.Decrypt(byte(p.Type()), p.ID, gen, header, ciphertext, tag, true, false)
	if err != nil {
		return nil, err
	}
	if len(plaintext) < ackDataSize || int32(binary.BigEndian.Uint16(plaintext)) != pending {
		return nil, errDecryptFailed
	}
	h.clientEkID.CompareAndSwap(pending, -1)

	return plaintext, nil
}

func (h *PacketHandler) handleCommandWindowAndAck(p *Packet, dummyUsed bool) bool {
	if p.Type() != PacketTypeCommand && p.Type() != PacketTypeCommandLow {
		return true
	}
	h.mu.Lock()
	var win *GenerationWindow
	if p.Type() == PacketTypeCommand {
		win = h.recvWindowCommand
	} else {
		win = h.recvWindowCommandLow
	}
	inWindow := win.IsInWindow(int(p.ID))
	isOld := win.IsOldPacket(int(p.ID))
	fits := h.fitsQueueLocked(p)
	h.mu.Unlock()

	ackType := PacketTypeAck
	if p.Type() == PacketTypeCommandLow {
		ackType = PacketTypeAckLow
	}

	if !inWindow {
		if isOld {
			h.logger.Debug("received old packet, sending ack only",
				slog.Uint64("type", uint64(p.Type())),
				slog.Uint64("id", uint64(p.ID)))
			h.sendAckPacket(p.ID, ackType, dummyUsed)
		} else {
			h.logger.Warn("packet too far ahead, ignoring",
				slog.Uint64("type", uint64(p.Type())),
				slog.Uint64("id", uint64(p.ID)))
		}

		return false
	}
	if !fits {
		// Not acknowledged, so the server sends it again once the queue has
		// drained.
		h.logger.Debug("receive queues full, dropping packet",
			slog.Uint64("type", uint64(p.Type())),
			slog.Uint64("id", uint64(p.ID)))

		return false
	}
	h.logger.Debug("sending ack for command",
		slog.Uint64("type", uint64(ackType)),
		slog.Uint64("id", uint64(p.ID)))
	h.sendAckPacket(p.ID, ackType, dummyUsed)

	return true
}

// fitsQueueLocked reports whether command packet p may join its receive queue
// within maxQueuedCommandBytes. The packet the queue needs next — the first id
// from the next expected one that it does not hold — is always taken, so a
// queue full of later packets still drains. The caller holds h.mu.
func (h *PacketHandler) fitsQueueLocked(p *Packet) bool {
	queue, nextID := h.commandQueue, h.nextCommandID
	if p.Type() == PacketTypeCommandLow {
		queue, nextID = h.commandLowQueue, h.nextCommandLowID
	}
	held := h.queuedBytes
	if old, ok := queue[p.ID]; ok {
		held -= len(old.Data)
	}
	if held+len(p.Data) <= maxQueuedCommandBytes {
		return true
	}
	needed := nextID
	for range len(queue) {
		if _, ok := queue[needed]; !ok {
			break
		}
		needed++
	}

	return p.ID == needed
}

func (h *PacketHandler) sendAckPacket(packetID uint16, ackType PacketType, dummyUsed bool) {
	ackData := getPooledBytes(&smallBufPool, ackDataSize)
	binary.BigEndian.PutUint16(ackData, packetID)
	_ = h.sendPacket(byte(ackType), ackData, 0, dummyUsed)
	putPooledBytes(&smallBufPool, ackData)
}

func (h *PacketHandler) updatePostReceiveState(p *Packet) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if (p.Type() == PacketTypeAck || p.Type() == PacketTypeAckLow) && len(p.Data) >= 2 {
		ackID := binary.BigEndian.Uint16(p.Data[0:2])
		targetType := uint32(PacketTypeCommand)
		if p.Type() == PacketTypeAckLow {
			targetType = uint32(PacketTypeCommandLow)
		}
		h.logger.Debug("received ack from server",
			slog.Uint64("target_type", uint64(targetType)),
			slog.Uint64("id", uint64(ackID)))
		delete(h.ackManager, (targetType<<16)|uint32(ackID))
		if targetType == uint32(PacketTypeCommand) {
			// Acknowledged under the real key: the dummy-key Ack is no
			// longer due.
			h.clientEkID.CompareAndSwap(int32(ackID), -1)
		}
	}
}

func (h *PacketHandler) fastForwardMissingPackets(
	pType PacketType, queue map[uint16]*Packet, nextID *uint16,
) {
	for {
		if _, ok := queue[*nextID]; ok {
			return
		}
		if !hasOldNewerPacket(queue, *nextID) {
			return
		}
		h.logger.Warn("skipping missing packet to unblock queue",
			slog.Uint64("type", uint64(pType)),
			slog.Uint64("missing_id", uint64(*nextID)))
		*nextID++
		if win := h.getWinForType(pType); win != nil {
			win.Advance(1)
		}
	}
}

func hasOldNewerPacket(queue map[uint16]*Packet, nextID uint16) bool {
	for id, pkg := range queue {
		if (id-nextID) < 32768 && time.Since(pkg.ReceivedAt) > 5*time.Second {
			return true
		}
	}

	return false
}

func (h *PacketHandler) logQueueBacklog(pType PacketType, queue map[uint16]*Packet, nextID uint16) {
	if len(queue) <= 10 {
		return
	}
	h.logger.Debug("packet queue backlog",
		slog.Uint64("type", uint64(pType)),
		slog.Uint64("next_id", uint64(nextID)),
		slog.Int("backlog_size", len(queue)))
}

// tryDecompressPacket decompresses a packet that is flagged compressed,
// reporting false for one that does not decompress, which is dropped.
func (h *PacketHandler) tryDecompressPacket(packet *Packet) bool {
	if (packet.Flags() & PacketFlagCompressed) == 0 {
		return true
	}
	qlz := NewQlz()
	decompressed, err := qlz.Decompress(packet.Data)
	if err != nil {
		h.logger.Debug("decompression failed, dropping the packet",
			slog.Uint64("id", uint64(packet.ID)),
			slog.Any("error", err))

		return false
	}
	packet.Data = decompressed
	packet.TypeFlagged &= ^byte(PacketFlagCompressed)

	return true
}

// tryReassemble takes the command starting at nextID off the queue: the packet
// itself, or the fragments it starts joined into one. It reports false when
// the fragments are not all there yet. A reassembled command larger than
// MaxReassembledSize is taken off the queue and dropped: it is returned as nil.
func (h *PacketHandler) tryReassemble(
	startPacket *Packet, queue map[uint16]*Packet, nextID *uint16, win *GenerationWindow,
) (*Packet, bool) {
	if (startPacket.Flags() & PacketFlagFragmented) == 0 {
		h.advanceQueueWindow(queue, nextID, win)

		return startPacket, true
	}

	fragments, totalSize, ok := collectFragments(queue, *nextID)
	if !ok {
		return nil, false
	}

	if totalSize > MaxReassembledSize {
		h.logger.Debug("reassembled packet too large, dropping it",
			slog.Uint64("start_id", uint64(*nextID)),
			slog.Int("fragments", len(fragments)),
			slog.Int("total_size", totalSize))
		for range fragments {
			h.advanceQueueWindow(queue, nextID, win)
		}

		return nil, true
	}

	combined := make([]byte, totalSize)
	pos := 0
	for i := range fragments {
		copy(combined[pos:], fragments[i].Data)
		pos += len(fragments[i].Data)
		h.advanceQueueWindow(queue, nextID, win)
	}

	startPacket.Data = combined
	startPacket.TypeFlagged &= ^byte(PacketFlagFragmented)

	return startPacket, true
}

func applyProtocolFlags(pType byte, flags byte) byte {
	if pType == byte(PacketTypeCommand) || pType == byte(PacketTypeCommandLow) {
		return flags | byte(PacketFlagNewProtocol)
	}

	return flags
}

func (h *PacketHandler) nextPacketIdentity(pType byte) (uint16, uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	pID := h.packetCounter[pType]
	pGen := h.generationCounter[pType]
	if pType == byte(PacketTypeInit1) {
		return pID, pGen
	}

	h.packetCounter[pType]++
	if h.packetCounter[pType] == 0 {
		h.generationCounter[pType]++
	}
	if pType == byte(PacketTypeCommand) {
		h.sendWindowCommand.AdvanceToExcluded(int(pID))
	} else if pType == byte(PacketTypeCommandLow) {
		h.sendWindowCommandLow.AdvanceToExcluded(int(pID))
	}

	return pID, pGen
}

func (h *PacketHandler) trackResendPacket(pType byte, p *Packet, rp *resendPacket) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if pType == byte(PacketTypeInit1) {
		h.initPacketCheck = rp

		return
	}
	if pType == byte(PacketTypeCommand) || pType == byte(PacketTypeCommandLow) {
		key := (uint32(pType) << 16) | uint32(p.ID)
		h.ackManager[key] = rp
	}
}

func collectFragments(queue map[uint16]*Packet, startID uint16) ([]*Packet, int, bool) {
	var fragments []*Packet
	currID := startID
	totalSize := 0
	startSeen := false
	for {
		p, ok := queue[currID]
		if !ok {
			return nil, 0, false
		}
		fragments = append(fragments, p)
		totalSize += len(p.Data)
		var complete bool
		startSeen, complete = updateFragmentState(startSeen, p.Flags())
		if complete {
			return fragments, totalSize, true
		}
		currID++
	}
}

func updateFragmentState(startSeen bool, flags PacketFlags) (bool, bool) {
	if (flags & PacketFlagFragmented) != 0 {
		if !startSeen {
			return true, false
		}

		return true, true
	}
	if !startSeen {
		return true, true
	}

	return startSeen, false
}

func (h *PacketHandler) advanceQueueWindow(queue map[uint16]*Packet, nextID *uint16, win *GenerationWindow) {
	if p, ok := queue[*nextID]; ok {
		h.queuedBytes -= len(p.Data)
	}
	delete(queue, *nextID)
	*nextID++
	if win != nil {
		win.Advance(1)
	}
}

func (h *PacketHandler) pingLoop() {
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			if h.TsCrypt.InitComplete() {
				_ = h.SendPacket(byte(PacketTypePing), []byte{}, byte(PacketFlagUnencrypted))
			}
		}
	}
}

func (h *PacketHandler) resendLoop() {
	ticker := time.NewTicker(resendLoopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkResends()
		}
	}
}

// ReceivedFinalInitAck stops resending the last Init1 packet the client sent.
// Until it is called, the latest step stays pending whatever the server sends
// in between: a step the client does not answer, an unknown one or a second
// RSA challenge, must not stop the resending of its own. The server's
// initivexpand2 command acknowledges the last step, not an Init1 reply.
func (h *PacketHandler) ReceivedFinalInitAck() {
	h.mu.Lock()
	h.initPacketCheck = nil
	h.mu.Unlock()
}

func (h *PacketHandler) checkResends() {
	h.mu.Lock()
	now := time.Now()
	needClose := false

	if now.Sub(h.lastMessageReceived) > PacketTimeout {
		h.logger.Warn("idle timeout: no packets received", slog.Duration("timeout", PacketTimeout))
		needClose = true
	}

	if h.initPacketCheck != nil {
		h.doResend(h.initPacketCheck, now)
	}
	for key, rp := range h.ackManager {
		if now.Sub(rp.firstSend) > PacketTimeout {
			delete(h.ackManager, key)
			needClose = true

			break
		}
		h.doResend(rp, now)
	}
	h.mu.Unlock()
	if needClose {
		_ = h.closeWith(ErrTimedOut)
	}
}

func (h *PacketHandler) doResend(rp *resendPacket, now time.Time) {
	if now.Sub(rp.lastSend) >= rp.nextInterval {
		rp.lastSend = now
		rp.retryCount++
		h.resends.Add(1)
		rp.nextInterval *= 2
		if rp.nextInterval > MaxRetryInterval {
			rp.nextInterval = MaxRetryInterval
		}

		unencrypted := (rp.packet.Flags()&PacketFlagUnencrypted != 0)
		dummy := !h.TsCrypt.InitComplete()
		header := rp.packet.BuildC2SHeader()
		h.logger.Debug("resending packet",
			slog.Uint64("type", uint64(rp.packet.Type())),
			slog.Uint64("id", uint64(rp.packet.ID)),
			slog.Int("retry_count", rp.retryCount),
			slog.Duration("next_interval", rp.nextInterval))
		ciphertext, tag, _ := h.TsCrypt.Encrypt(
			byte(rp.packet.Type()), rp.packet.ID, rp.packet.GenerationID, header, rp.packet.Data, dummy, unencrypted,
		)
		final := make([]byte, tagSize+headerSize+len(ciphertext))
		copy(final[0:8], tag)
		copy(final[8:13], header)
		copy(final[13:], ciphertext)
		_, err := h.conn.Write(final)
		if err != nil {
			h.logger.Warn("resend write failed", slog.Any("error", err))
		}
	}
}

// SendVoicePacket sends one unencrypted Voice packet carrying an audio frame
// in codec. Voice is never acknowledged or resent. On a handler that is not
// open it returns ErrNotOpen.
//
// Payload layout: u16 voice packet ID, u8 codec, then the frame.
func (h *PacketHandler) SendVoicePacket(data []byte, codec byte) error {
	if !h.IsOpen() {
		return ErrNotOpen
	}
	h.mu.Lock()
	pID := h.packetCounter[PacketTypeVoice]
	pGen := h.generationCounter[PacketTypeVoice]
	h.packetCounter[PacketTypeVoice]++
	if h.packetCounter[PacketTypeVoice] == 0 {
		h.generationCounter[PacketTypeVoice]++
	}
	clid := uint16(h.clientID.Load()) //nolint:gosec // stored from a uint16
	h.mu.Unlock()

	payloadLen := voiceHeaderSize + len(data)

	voicePayload := getPooledBytes(&voicePayloadPool, payloadLen)
	binary.BigEndian.PutUint16(voicePayload[0:2], pID)
	voicePayload[2] = codec
	copy(voicePayload[voiceHeaderSize:], data)

	p := &Packet{
		TypeFlagged:  byte(PacketTypeVoice) | byte(PacketFlagUnencrypted),
		ID:           pID,
		GenerationID: pGen,
		Data:         voicePayload,
		ClientID:     clid,
	}

	header := p.BuildC2SHeader()

	final := getPooledBytes(&bufPool, tagSize+headerSize+payloadLen)

	fakeSig := h.TsCrypt.FakeSignature()
	copy(final[0:8], fakeSig[:])
	copy(final[8:13], header)
	copy(final[13:], voicePayload)

	_, err := h.conn.Write(final[:tagSize+headerSize+payloadLen])

	putPooledBytes(&bufPool, final)
	putPooledBytes(&voicePayloadPool, voicePayload)

	return err
}

// SendWhisperPacket sends an unencrypted VoiceWhisper packet to up to 32 clients,
// regardless of which channel they are in. On a handler that is not open it
// returns ErrNotOpen.
//
// Payload layout: u16 voice packet ID, u8 codec, u8 channel target count (always
// 0 here), u8 client target count, one u16 per client ID, then the Opus frame.
func (h *PacketHandler) SendWhisperPacket(data []byte, targetClientIDs []uint16, codec byte) error {
	err := h.checkWhisper(targetClientIDs)
	if err != nil {
		return err
	}

	h.mu.Lock()
	pID := h.packetCounter[PacketTypeVoiceWhisper]
	pGen := h.generationCounter[PacketTypeVoiceWhisper]
	h.packetCounter[PacketTypeVoiceWhisper]++
	if h.packetCounter[PacketTypeVoiceWhisper] == 0 {
		h.generationCounter[PacketTypeVoiceWhisper]++
	}
	clid := uint16(h.clientID.Load()) //nolint:gosec // stored from a uint16
	h.mu.Unlock()

	targetsLen := len(targetClientIDs) * 2
	payloadLen := whisperHeaderSize + targetsLen + len(data)

	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload[0:2], pID)
	payload[2] = codec
	payload[3] = 0
	payload[4] = byte(len(targetClientIDs)) //nolint:gosec // bounded by maxWhisperTargets above
	for i, id := range targetClientIDs {
		binary.BigEndian.PutUint16(payload[whisperHeaderSize+i*2:], id)
	}
	copy(payload[whisperHeaderSize+targetsLen:], data)

	p := &Packet{
		TypeFlagged:  byte(PacketTypeVoiceWhisper) | byte(PacketFlagUnencrypted),
		ID:           pID,
		GenerationID: pGen,
		Data:         payload,
		ClientID:     clid,
	}

	final := make([]byte, tagSize+headerSize+payloadLen)
	fakeSig := h.TsCrypt.FakeSignature()
	copy(final[0:8], fakeSig[:])
	copy(final[8:13], p.BuildC2SHeader())
	copy(final[13:], payload)

	_, err = h.conn.Write(final)

	return err
}

func (h *PacketHandler) checkWhisper(targetClientIDs []uint16) error {
	switch {
	case len(targetClientIDs) == 0:
		return ErrNoWhisperTargets
	case len(targetClientIDs) > maxWhisperTargets:
		return ErrTooManyWhisperTargets
	case !h.IsOpen():
		return ErrNotOpen
	default:
		return nil
	}
}

// IsOpen reports whether there is a live connection to send on.
func (h *PacketHandler) IsOpen() bool {
	return h.started.Load() && !h.closed.Load()
}

// Done returns a channel closed when the handler is closed.
func (h *PacketHandler) Done() <-chan struct{} { return h.stopCh }

// Close stops the handler and closes its connection.
func (h *PacketHandler) Close() error {
	return h.closeWith(nil)
}

// closeWith closes the handler, recording cause for OnClosed.
func (h *PacketHandler) closeWith(cause error) error {
	h.lifecycleMu.Lock()
	if h.closed.Swap(true) {
		h.lifecycleMu.Unlock()

		return nil
	}
	h.closeCause = cause
	close(h.stopCh)
	conn := h.conn
	h.lifecycleMu.Unlock()

	if conn != nil {
		return conn.Close()
	}

	return nil
}

func getPooledBytes(pool *sync.Pool, size int) []byte {
	bufPtr, ok := pool.Get().(*[]byte)
	if !ok || bufPtr == nil {
		return make([]byte, size)
	}
	buf := *bufPtr
	if cap(buf) < size {
		return make([]byte, size)
	}

	return buf[:size]
}

func putPooledBytes(pool *sync.Pool, buf []byte) {
	pool.Put(&buf)
}
