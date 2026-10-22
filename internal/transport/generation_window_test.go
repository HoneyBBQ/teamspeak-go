package transport_test

import (
	"testing"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func TestGenerationWindowNew(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	if gw == nil {
		t.Fatal("expected non-nil GenerationWindow")
	}
	if gw.GetGeneration(0) != 0 {
		t.Error("initial generation should be 0")
	}
	if !gw.IsInWindow(0) {
		t.Error("0 should be in window after creation")
	}
}

func TestGenerationWindowReset(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(500)
	gw.Reset()
	if gw.GetGeneration(0) != 0 {
		t.Error("generation should be 0 after Reset")
	}
	// After Reset, base=0 so window is [0..1023]
	if !gw.IsInWindow(0) {
		t.Error("0 should be in window after Reset")
	}
	if !gw.IsInWindow(1023) {
		t.Error("1023 should be in window after Reset")
	}
	if gw.IsInWindow(1024) {
		t.Error("1024 should NOT be in window after Reset")
	}
}

func TestGenerationWindowAdvanceBasic(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(100)
	if !gw.IsInWindow(100) {
		t.Error("100 should be in window after Advance(100)")
	}
	if gw.IsInWindow(99) {
		t.Error("99 should not be in window after Advance(100)")
	}
	if !gw.IsInWindow(1123) {
		t.Error("1123 (100+1023) should be in window")
	}
	if gw.IsInWindow(1124) {
		t.Error("1124 should not be in window")
	}
}

func TestGenerationWindowAdvanceZeroAndNegative(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(0)
	gw.Advance(-1)
	if !gw.IsInWindow(0) {
		t.Error("0 should still be in window after zero/negative advance")
	}
	if gw.GetGeneration(0) != 0 {
		t.Error("generation should remain 0")
	}
}

func TestGenerationWindowFullCycleIncrementsGeneration(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(65536)
	if gw.GetGeneration(0) != 1 {
		t.Errorf("after one full cycle, generation should be 1, got %d", gw.GetGeneration(0))
	}
}

func TestGenerationWindowIsOldPacket(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(100)
	if !gw.IsOldPacket(0) {
		t.Error("0 should be old after Advance(100)")
	}
	if !gw.IsOldPacket(99) {
		t.Error("99 should be old after Advance(100)")
	}
	if gw.IsOldPacket(100) {
		t.Error("100 should not be old (it's the window start)")
	}
	if gw.IsOldPacket(500) {
		t.Error("500 should not be old (it's in window)")
	}
}

func TestGenerationWindowIsFuturePacket(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	if !gw.IsFuturePacket(1024) {
		t.Error("1024 should be a future packet (base=0, window=1024)")
	}
	if gw.IsFuturePacket(1023) {
		t.Error("1023 should not be a future packet (last in window)")
	}
	if gw.IsFuturePacket(500) {
		t.Error("500 should not be a future packet")
	}
}

func TestGenerationWindowAdvanceToExcluded(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	// AdvanceToExcluded(10): moveDist=10, Advance(11), base becomes 11
	gw.AdvanceToExcluded(10)
	if !gw.IsOldPacket(10) {
		t.Error("10 should be old after AdvanceToExcluded(10)")
	}
	if gw.IsOldPacket(11) {
		t.Error("11 should be in window (new base)")
	}
}

func TestGenerationWindowAdvanceAfter(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(1<<16 + 10) // base 10 of generation 1

	gw.AdvanceAfter(65535) // stale packet from generation 0
	if !gw.IsOldPacket(65535) {
		t.Error("65535 should remain old after AdvanceAfter")
	}
	if gw.IsOldPacket(10) || gw.GetGeneration(10) != 1 {
		t.Error("a stale packet moved the window back from generation 1")
	}

	gw.AdvanceAfter(20)
	if !gw.IsOldPacket(20) {
		t.Error("20 should be old after AdvanceAfter(20)")
	}
	if gw.IsOldPacket(21) || gw.GetGeneration(21) != 1 {
		t.Error("21 should be the next packet in generation 1")
	}
}

func TestGenerationWindowSyncTo(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.SyncTo(500)
	if gw.IsOldPacket(500) {
		t.Error("500 should not be old after SyncTo(500)")
	}
	if !gw.IsOldPacket(499) {
		t.Error("499 should be old after SyncTo(500)")
	}
}

func TestGenerationWindowWrapAroundInWindow(t *testing.T) {
	// mod=16, window=4: after Advance(14), window spans 14,15,0,1
	gw := transport.NewGenerationWindow(16, 4)
	gw.Advance(14)
	if !gw.IsInWindow(14) {
		t.Error("14 should be in window")
	}
	if !gw.IsInWindow(15) {
		t.Error("15 should be in window")
	}
	if !gw.IsInWindow(0) {
		t.Error("0 (wrapped) should be in window")
	}
	if !gw.IsInWindow(1) {
		t.Error("1 (wrapped) should be in window")
	}
	if gw.IsInWindow(2) {
		t.Error("2 should NOT be in window")
	}
	if gw.IsInWindow(13) {
		t.Error("13 should NOT be in window")
	}
}

func TestGenerationWindowIsNextGen(t *testing.T) {
	// mod=16, window=4: IsNextGen requires base > 16-4=12
	gw := transport.NewGenerationWindow(16, 4)
	gw.Advance(13) // base=13
	// 0 < (13+4)-16=1 and base=13>12 → IsNextGen(0)=true
	if !gw.IsNextGen(0) {
		t.Error("0 should be next-gen when base=13, mod=16, window=4")
	}
	// 1 is NOT < 1 → IsNextGen(1)=false
	if gw.IsNextGen(1) {
		t.Error("1 should NOT be next-gen when base=13")
	}
}

func TestGenerationWindowNextGenIncreasesGeneration(t *testing.T) {
	gw := transport.NewGenerationWindow(16, 4)
	gw.Advance(13)
	if gw.GetGeneration(13) != 0 {
		t.Errorf("generation of 13 should be 0, got %d", gw.GetGeneration(13))
	}
	if gw.GetGeneration(0) != 1 {
		t.Errorf("generation of 0 (next-gen) should be 1, got %d", gw.GetGeneration(0))
	}
}

func TestGenerationWindowMultipleAdvanceCycles(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(65536)
	gw.Advance(65536)
	gw.Advance(65536)
	if gw.GetGeneration(0) != 3 {
		t.Errorf("after 3 full cycles, generation should be 3, got %d", gw.GetGeneration(0))
	}
}

func TestGenerationWindowMappedToIndex(t *testing.T) {
	gw := transport.NewGenerationWindow(65536, 1024)
	gw.Advance(100) // base=100
	idx := gw.MappedToIndex(150)
	if idx != 50 {
		t.Errorf("MappedToIndex(150)=%d, want 50 (base=100)", idx)
	}
	idx = gw.MappedToIndex(99)
	if idx != -1 {
		t.Errorf("MappedToIndex(99)=%d, want -1 (old packet)", idx)
	}
}

const (
	wrapMod  = 65536
	wrapSize = 1024
)

// wrapProbe is an id, and where the window should place it: its offset from
// the base, its generation, and whether it is "old", "in" the window or "ahead"
// of it.
type wrapProbe struct {
	name  string
	kind  string
	id    int
	index int
	gen   uint32
}

type wrapCase struct {
	name    string
	probes  []wrapProbe
	advance int
}

var wrapCases = []wrapCase{
	{"just past the wrap", []wrapProbe{
		{"base", "in", 1, 0, 1},
		{"zero", "old", 0, -1, 1},
		{"last id of the generation before", "old", 65535, -2, 0},
		{"furthest behind the window holds", "old", 1 + wrapMod - wrapSize, -wrapSize, 0},
		{"one further", "ahead", wrapMod - wrapSize, wrapMod - wrapSize - 1, 1},
		{"far ahead", "ahead", 5000, 4999, 1},
	}, wrapMod + 1},
	{"exactly on the wrap", []wrapProbe{
		{"base", "in", 0, 0, 1},
		{"last id of the generation before", "old", 65535, -1, 0},
		{"furthest behind the window holds", "old", wrapMod - wrapSize, -wrapSize, 0},
		{"one further", "ahead", wrapMod - wrapSize - 1, wrapMod - wrapSize - 1, 1},
	}, wrapMod},
	{"window straddling the next wrap", []wrapProbe{
		{"base", "in", 65530, 0, 1},
		{"one behind", "old", 65529, -1, 1},
		{"first id of the next generation", "in", 0, 6, 2},
		{"last id of the window", "in", 1017, 1023, 2},
	}, wrapMod + 65530},
	{"two wraps on", []wrapProbe{
		{"last id of the generation before", "old", 65535, -11, 1},
		{"behind within the generation", "old", 3, -7, 2},
	}, 2*wrapMod + 10},
	{"before the first wrap", []wrapProbe{
		{"top of the range is not behind", "ahead", 65535, 65534, 0},
		{"zero is behind", "old", 0, -1, 0},
	}, 1},
}

// After the 16-bit id wraps, the ids the window has just left behind are at the
// top of the range. A packet whose acknowledgement was lost is sent again
// after the move, and it must read as old, and belong to the generation before
// the window's, or it is neither acknowledged nor decrypted.
func TestGenerationWindowBehindTheBaseAcrossTheWrap(t *testing.T) {
	for _, tc := range wrapCases {
		t.Run(tc.name, func(t *testing.T) {
			gw := transport.NewGenerationWindow(wrapMod, wrapSize)
			gw.Advance(tc.advance)
			for _, p := range tc.probes {
				if got := gw.MappedToIndex(p.id); got != p.index {
					t.Errorf("%s: id %d: MappedToIndex = %d, want %d", p.name, p.id, got, p.index)
				}
				if got := gw.GetGeneration(p.id); got != p.gen {
					t.Errorf("%s: id %d: GetGeneration = %d, want %d", p.name, p.id, got, p.gen)
				}
				if got := gw.IsOldPacket(p.id); got != (p.kind == "old") {
					t.Errorf("%s: id %d: IsOldPacket = %v", p.name, p.id, got)
				}
				if got := gw.IsInWindow(p.id); got != (p.kind == "in") {
					t.Errorf("%s: id %d: IsInWindow = %v", p.name, p.id, got)
				}
				if got := gw.IsFuturePacket(p.id); got != (p.kind == "ahead") {
					t.Errorf("%s: id %d: IsFuturePacket = %v", p.name, p.id, got)
				}
			}
		})
	}
}

// The same on a small window, where every id can be listed.
func TestGenerationWindowBehindTheBaseAcrossTheWrap_SmallWindow(t *testing.T) {
	gw := transport.NewGenerationWindow(16, 4)
	gw.Advance(17) // base 1 of generation 1: the window is 1..4

	want := map[int]string{
		0: "old", 15: "old", 14: "old", 13: "old", 12: "ahead", 11: "ahead", 6: "ahead", 5: "ahead",
		1: "in", 2: "in", 3: "in", 4: "in",
	}
	for id, kind := range want {
		got := "in"
		switch {
		case gw.IsOldPacket(id):
			got = "old"
		case gw.IsFuturePacket(id):
			got = "ahead"
		}
		if got != kind {
			t.Errorf("id %d is %s, want %s", id, got, kind)
		}
	}
	if gen := gw.GetGeneration(13); gen != 0 {
		t.Errorf("generation of 13 = %d, want 0", gen)
	}
}
