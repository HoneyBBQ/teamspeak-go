package transport

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// A command sent under the dummy key — clientek — is sent again under the
// dummy key, though crypto init completes right after it: the server can only
// decrypt the resend with the key it was first sent under.
func TestHandlerResendsAPacketUnderTheKeyItFirstWentOutUnder(t *testing.T) {
	h, serverConn := newTestHandler(t)
	defer func() { _ = h.Close() }()
	_ = readPacket(t, serverConn) // Init1

	sendCommand(t, h, []byte("clientek ek=x proof=y"))
	first := readPacket(t, serverConn)

	err := h.TsCrypt.SetSharedSecret(make([]byte, 10), make([]byte, 54), make([]byte, 64))
	if err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}
	h.mu.Lock()
	for _, rp := range h.ackManager {
		rp.lastSend = time.Now().Add(-time.Minute)
	}
	h.mu.Unlock()
	h.checkResends()

	again := readPacket(t, serverConn)
	if !bytes.Equal(first, again) {
		t.Errorf("the resend differs from the first send:\n first %x\n again %x", first, again)
	}
}

// sendCommand sends data as a command, failing the test on an error. It is
// safe to call from any goroutine.
func sendCommand(t *testing.T, h *PacketHandler, data []byte) {
	t.Helper()
	err := h.SendPacket(byte(PacketTypeCommand), data, 0)
	if err != nil {
		t.Errorf("SendPacket: %v", err)
	}
}

// recordingConn keeps each datagram written to it, in order.
type recordingConn struct {
	discardConn

	writes [][]byte
	mu     sync.Mutex
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, bytes.Clone(b))
	c.mu.Unlock()

	return len(b), nil
}

// Concurrent commands must not take the ids between the fragments of a split
// one: the server reassembles consecutive ids, and a small command's packet in
// between would be glued into the large one.
func TestHandlerKeepsTheFragmentsOfACommandTogether(t *testing.T) {
	h, _ := newFuzzHandler(t, true)
	conn := &recordingConn{}
	h.conn = conn

	const small, perSender, senders = 10, 100, 4
	big := make([]byte, 487*4+100)
	var wg sync.WaitGroup
	wg.Add(senders + 1)
	go func() {
		defer wg.Done()
		for range 50 {
			sendCommand(t, h, big)
		}
	}()
	for range senders {
		go func() {
			defer wg.Done()
			for range perSender {
				sendCommand(t, h, make([]byte, small))
			}
		}()
	}
	wg.Wait()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	requireFragmentsTogether(t, conn.writes, small)
}

// requireFragmentsTogether checks the commands written, in order: ids follow
// each other, and between the Fragmented packet that opens a split command and
// the one that closes it there are only its own full-size fragments.
func requireFragmentsTogether(t *testing.T, writes [][]byte, small int) {
	t.Helper()
	const overhead = tagSize + headerSize
	inFragments, nextID := false, -1
	for i, w := range writes {
		if PacketType(w[typeByteOffset]&0x0f) != PacketTypeCommand {
			continue
		}
		id := int(w[8])<<8 | int(w[9])
		if nextID >= 0 && id != nextID {
			t.Fatalf("write %d carries id %d, want %d: ids are not in write order", i, id, nextID)
		}
		nextID = (id + 1) & 0xffff
		fragmented := w[typeByteOffset]&byte(PacketFlagFragmented) != 0
		size := len(w) - overhead
		switch {
		case fragmented:
			inFragments = !inFragments
		case inFragments && size != 487:
			t.Fatalf("write %d: a %d-byte packet sits between the fragments of a command", i, size)
		case !inFragments && size != small:
			t.Fatalf("write %d: a %d-byte packet outside a command", i, size)
		}
	}
	if inFragments {
		t.Error("a split command never ended")
	}
}

// A command packet that stays missing while later ones wait for it ends the
// connection with ErrCommandStalled; it is not skipped.
func TestHandlerClosesWhenACommandStaysMissing(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)

	h.handleRawPacket(sealReal(t, h.TsCrypt, 1, 0, []byte("later")))
	h.checkResends()
	if !h.IsOpen() {
		t.Fatal("closed before the hole was old")
	}

	h.mu.Lock()
	h.commandQueue[1].ReceivedAt = time.Now().Add(-commandHoleTimeout - time.Second)
	h.mu.Unlock()
	h.checkResends()

	if h.IsOpen() {
		t.Fatal("still open with a command missing for longer than the timeout")
	}
	h.lifecycleMu.Lock()
	cause := h.closeCause
	h.lifecycleMu.Unlock()
	if !errors.Is(cause, ErrCommandStalled) {
		t.Errorf("closed with %v, want ErrCommandStalled", cause)
	}
	if *delivered != 0 {
		t.Errorf("delivered %d commands, want none: the later one must not run without the missing one", *delivered)
	}
}

func TestHandlerKeepsOpenWhenTheMissingCommandArrives(t *testing.T) {
	h, delivered := newFuzzHandler(t, true)

	h.handleRawPacket(sealReal(t, h.TsCrypt, 1, 0, []byte("later")))
	h.mu.Lock()
	h.commandQueue[1].ReceivedAt = time.Now().Add(-commandHoleTimeout - time.Second)
	h.mu.Unlock()
	h.handleRawPacket(sealReal(t, h.TsCrypt, 0, 0, []byte("first")))
	h.checkResends()

	if !h.IsOpen() || *delivered != 2 {
		t.Errorf("open = %v, delivered = %d, want open and 2", h.IsOpen(), *delivered)
	}
}

// eventLog records what happened, in order, from any goroutine.
type eventLog struct {
	events []string
	mu     sync.Mutex
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.events...)
}

// writeCommands has the server send count small commands, ids from 0.
func writeCommands(t *testing.T, serverConn *packetPipe, count int) {
	t.Helper()
	typ := byte(PacketTypeCommand) | byte(PacketFlagNewProtocol)
	for id := range count {
		_, err := serverConn.Write(buildDummyEncryptedS2CCommand(t, uint16(id), typ, []byte("x")))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
}

// Nothing is delivered after the close is reported: OnClosed waits for the
// packet being handled, and a packet buffered behind it is not handled.
func TestHandlerDeliversNothingAfterOnClosed(t *testing.T) {
	h, serverConn := newTestHandler(t)
	_ = readPacket(t, serverConn)

	var log eventLog
	record := log.add
	entered := make(chan struct{}, 1)
	gate := make(chan struct{})
	h.OnPacket = func(*Packet) {
		record("packet")
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}
	closed := make(chan struct{})
	h.OnClosed = func(error) {
		record("closed")
		close(closed)
	}

	writeCommands(t, serverConn, 3)
	<-entered
	_ = h.Close()
	select {
	case <-closed:
		t.Fatal("OnClosed ran while a packet was still being delivered")
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("OnClosed did not run")
	}

	if events := log.all(); len(events) == 0 || events[len(events)-1] != "closed" {
		t.Errorf("events = %v, want closed last", events)
	}
}
