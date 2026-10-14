package transport

import (
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
)

// discardConn accepts every write and never delivers a read.
type discardConn struct{}

func (discardConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (discardConn) Close() error                { return nil }

// newFuzzHandler returns a handler that can send but runs none of its loops,
// so each input meets the same state and any panic surfaces in the fuzz
// function itself rather than in a background goroutine.
func newFuzzHandler(tb testing.TB, initComplete bool) (*PacketHandler, *int) {
	tb.Helper()
	tc := newFuzzCrypt(tb)
	if initComplete {
		err := tc.SetSharedSecret(make([]byte, 10), make([]byte, 54), make([]byte, 64))
		if err != nil {
			tb.Fatalf("SetSharedSecret: %v", err)
		}
	}
	h := NewPacketHandler(tc, slog.New(slog.DiscardHandler))
	h.conn = discardConn{}
	h.started.Store(true)
	delivered := new(int)
	h.OnPacket = func(p *Packet) {
		*delivered++
		_ = p.Data
	}

	return h, delivered
}

func newFuzzCrypt(tb testing.TB) *crypto.Crypt {
	tb.Helper()
	id, err := identity.Parse(testIdentityForHandler)
	if err != nil {
		tb.Fatalf("Parse: %v", err)
	}

	return crypto.NewCrypt(id)
}

// sealDummy encrypts payload as the server would before crypto init: with the
// public dummy key, so the fuzzer's bytes get past authentication and reach
// reassembly and decompression.
func sealDummy(tb testing.TB, id uint16, typeFlagged byte, payload []byte) []byte {
	tb.Helper()
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header, id)
	header[2] = typeFlagged
	key := make([]byte, 16)
	copy(key, handlerTestDummyKey)
	eax, err := crypto.NewEAX(key)
	if err != nil {
		tb.Fatalf("NewEAX: %v", err)
	}
	ciphertext, mac, err := eax.Encrypt(handlerTestDummyNonce, header, payload)
	if err != nil {
		tb.Fatalf("Encrypt: %v", err)
	}

	return append(append(append([]byte{}, mac...), header...), ciphertext...)
}

// FuzzHandleRawPacket feeds arbitrary datagrams to the receive path, before
// and after crypto init. Nothing a network peer sends may panic.
func FuzzHandleRawPacket(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add(make([]byte, 11), false)
	f.Add(buildS2CPacket(make([]byte, 8), 1, 0x88, []byte{0x01}), false)
	f.Add(buildS2CPacket(make([]byte, 8), 0, 0x84, nil), true)
	f.Add(buildS2CPacket([]byte("TS3INIT1"), 101, 0x08, make([]byte, 233)), false)
	f.Add(buildS2CPacket(make([]byte, 8), 5, 0x80, []byte{0, 1, 0, 0, 5, 1, 2, 3}), true)

	f.Fuzz(func(t *testing.T, raw []byte, initComplete bool) {
		h, _ := newFuzzHandler(t, initComplete)
		h.handleRawPacket(raw)
	})
}

// FuzzHandleSealedCommands feeds two authenticated command packets with
// arbitrary flags and payloads, so fragment reassembly and QuickLZ see
// whatever the fuzzer invents.
func FuzzHandleSealedCommands(f *testing.F) {
	f.Add(byte(0x02), byte(0x02), uint16(0), []byte("initserver"), []byte(""))
	// Two fragments, the first compressed: a QuickLZ header split across them.
	f.Add(byte(0x52), byte(0x12), uint16(0), []byte{0x05, 0x10, 0x20}, []byte{0, 0, 0, 0, 'a', 'b'})
	f.Add(byte(0x42), byte(0x02), uint16(0), []byte{0x04, 0, 200}, []byte{})
	f.Add(byte(0x46), byte(0x03), uint16(7), []byte{0x00, 0x07}, []byte{0x47})

	f.Fuzz(func(t *testing.T, flags1, flags2 byte, id uint16, payload1, payload2 []byte) {
		h, _ := newFuzzHandler(t, false)
		h.nextCommandID = id
		h.nextCommandLowID = id
		h.handleRawPacket(sealDummy(t, id, flags1, payload1))
		h.handleRawPacket(sealDummy(t, id+1, flags2, payload2))
	})
}

// FuzzQlzDecompress checks that no QuickLZ input panics or allocates past the
// cap, and that output always has the declared size.
func FuzzQlzDecompress(f *testing.F) {
	f.Add([]byte{0x04, 0x05, 0x02, 'h', 'i'})
	f.Add([]byte{0x05, 0x09, 0x02, 0, 0, 0, 0, 'h', 'i'})
	// Stored block declaring 200 bytes it does not have.
	f.Add([]byte{0x04, 0x00, 200})
	// 9-byte header declaring 0x7fffffff bytes.
	f.Add([]byte{0x06, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f})
	// A back-reference before any output.
	f.Add([]byte{0x05, 0, 20, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := NewQlz().Decompress(data)
		if err != nil {
			return
		}
		if len(out) > MaxDecompressedSize {
			t.Fatalf("decompressed %d bytes, over the %d cap", len(out), MaxDecompressedSize)
		}
		if want := getDecompressedSize(data); len(out) != want {
			t.Fatalf("decompressed %d bytes, header declared %d", len(out), want)
		}
	})
}

// FuzzGenerationWindow checks the receive window over the 16-bit id wrap, which
// a server steers by the ids it sends: that the generation counts the wraps,
// that each id in the window sits at its absolute position and so in its
// generation, that "in the window" is "neither old nor ahead", and that an id
// just behind the window is old and in the generation it was sent in, across the
// wrap as well. Each three bytes of steps advance the window by a 17-bit amount.
func FuzzGenerationWindow(f *testing.F) {
	const mod = 1 << 16
	f.Add([]byte{}, uint16(0))
	f.Add([]byte{0, 0xff, 0xff, 0, 0, 1}, uint16(65535))
	f.Add([]byte{1, 0, 0, 0, 0, 5}, uint16(3))
	f.Add([]byte{0, 0xfb, 0xff}, uint16(2))
	f.Add([]byte{1, 0, 1}, uint16(65535))
	f.Add([]byte{1, 0, 0, 0, 4, 0}, uint16(64000))

	f.Fuzz(func(t *testing.T, steps []byte, probe uint16) {
		w := NewGenerationWindow(mod, ReceivePacketWindowSize)
		absolute := 0
		for i := 0; i+2 < len(steps); i += 3 {
			amount := int(steps[i]&1)<<16 | int(steps[i+1])<<8 | int(steps[i+2])
			w.Advance(amount)
			absolute += amount
		}

		if got, want := w.generation, uint32(absolute/mod); got != want {
			t.Fatalf("generation %d after %d ids, want %d", got, absolute, want)
		}
		id := int(probe)
		if w.IsInWindow(id) != (!w.IsOldPacket(id) && !w.IsFuturePacket(id)) {
			t.Fatalf("id %d at %d: in window %v, old %v, ahead %v",
				id, absolute, w.IsInWindow(id), w.IsOldPacket(id), w.IsFuturePacket(id))
		}
		for offset := range ReceivePacketWindowSize {
			at := (absolute + offset) % mod
			if !w.IsInWindow(at) || w.MappedToIndex(at) != offset ||
				w.GetGeneration(at) != uint32((absolute+offset)/mod) {
				t.Fatalf("id %d at %d+%d: in window %v, index %d, generation %d",
					at, absolute, offset, w.IsInWindow(at), w.MappedToIndex(at), w.GetGeneration(at))
			}
		}
		// An id that was ever sent: none lies behind the very first one.
		for behind := 1; behind <= ReceivePacketWindowSize && behind <= absolute; behind++ {
			at := (absolute - behind) % mod
			if w.IsInWindow(at) || !w.IsOldPacket(at) || w.IsFuturePacket(at) ||
				w.GetGeneration(at) != uint32((absolute-behind)/mod) {
				t.Fatalf("id %d, %d behind the window at %d: in window %v, old %v, ahead %v, generation %d",
					at, behind, absolute, w.IsInWindow(at), w.IsOldPacket(at), w.IsFuturePacket(at), w.GetGeneration(at))
			}
		}
	})
}
