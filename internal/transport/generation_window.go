package transport

import "math"

// GenerationWindow tracks a packet id sequence that wraps at mod (65536 for
// the 16-bit ids on the wire) and counts the wraps as a generation, which the
// packet encryption needs alongside the id. Ids within receiveWindow past the
// base are accepted, so a window near the end of one generation also covers
// the first ids of the next.
type GenerationWindow struct {
	mappedBaseOffset int
	generation       uint32
	mod              int
	receiveWindow    int
}

// NewGenerationWindow returns a window over ids modulo mod that accepts the
// windowSize ids starting at the base, at id 0 of generation 0.
func NewGenerationWindow(mod int, windowSize int) *GenerationWindow {
	return &GenerationWindow{
		mod:           mod,
		receiveWindow: windowSize,
	}
}

// Advance moves the base forward by amount ids, incrementing the generation
// each time it wraps past mod. A non-positive amount does nothing.
func (g *GenerationWindow) Advance(amount int) {
	if amount <= 0 {
		return
	}
	newBaseOffset := g.mappedBaseOffset + amount
	genStep := newBaseOffset / g.mod
	if genStep > 0 {
		if genStep > math.MaxUint32 {
			genStep = math.MaxUint32
		}
		g.generation += uint32(genStep)
	}
	g.mappedBaseOffset = newBaseOffset % g.mod
}

// AdvanceToExcluded moves the base to just past mappedValue, so mappedValue
// itself is no longer in the window; it wraps forward if mappedValue is behind.
func (g *GenerationWindow) AdvanceToExcluded(mappedValue int) {
	moveDist := mappedValue - g.mappedBaseOffset
	if moveDist < 0 {
		moveDist += g.mod
	}
	g.Advance(moveDist + 1)
}

// SyncTo advances the window baseline toward mappedValue (handles wrap and resync).
func (g *GenerationWindow) SyncTo(mappedValue int) {
	moveDist := mappedValue - g.mappedBaseOffset
	if moveDist < 0 {
		moveDist += g.mod
	}
	g.Advance(moveDist)
}

// IsInWindow reports whether mappedValue lies in the receive window,
// including a window that wraps past mod into the next generation.
func (g *GenerationWindow) IsInWindow(mappedValue int) bool {
	maxOffset := g.mappedBaseOffset + g.receiveWindow
	if maxOffset < g.mod {
		return mappedValue >= g.mappedBaseOffset && mappedValue < maxOffset
	}

	return mappedValue >= g.mappedBaseOffset || mappedValue < maxOffset-g.mod
}

// MappedToIndex returns the offset from the window base; negative means stale, >= receiveWindow too far ahead.
// An id up to receiveWindow behind the base across the last wrap, which reads as
// a high number, is stale too.
func (g *GenerationWindow) MappedToIndex(mappedValue int) int {
	if g.IsNextGen(mappedValue) {
		return (mappedValue + g.mod) - g.mappedBaseOffset
	}
	index := mappedValue - g.mappedBaseOffset
	if g.isBehindAcrossWrap(index) {
		return index - g.mod
	}

	return index
}

// IsOldPacket reports whether mappedValue is before the receive window: a packet
// whose acknowledgement was lost is sent again after the window has moved past
// it, also when the move wrapped the 16-bit id.
func (g *GenerationWindow) IsOldPacket(mappedValue int) bool {
	index := g.MappedToIndex(mappedValue)

	return index < 0
}

// IsFuturePacket reports whether mappedValue lies beyond the window.
func (g *GenerationWindow) IsFuturePacket(mappedValue int) bool {
	index := g.MappedToIndex(mappedValue)

	return index >= g.receiveWindow
}

// IsNextGen reports whether mappedValue belongs to the next generation: the
// window wraps past mod and mappedValue is in the wrapped part.
func (g *GenerationWindow) IsNextGen(mappedValue int) bool {
	return g.mappedBaseOffset > (g.mod-g.receiveWindow) &&
		mappedValue < (g.mappedBaseOffset+g.receiveWindow)-g.mod
}

// GetGeneration returns the generation mappedValue belongs to: one past the
// current generation if the id has already wrapped, one before it if the id is
// just behind the base across the last wrap.
func (g *GenerationWindow) GetGeneration(mappedValue int) uint32 {
	if g.IsNextGen(mappedValue) {
		return g.generation + 1
	}
	if g.isBehindAcrossWrap(mappedValue - g.mappedBaseOffset) {
		return g.generation - 1
	}

	return g.generation
}

// Reset returns the window to id 0 of generation 0.
func (g *GenerationWindow) Reset() {
	g.mappedBaseOffset = 0
	g.generation = 0
}

// isBehindAcrossWrap reports whether an id index past the base is really up to
// receiveWindow behind it, in the generation before: the base has wrapped
// since, so the id reads as nearly a whole generation ahead. Before the first
// wrap no id lies behind the base across it.
func (g *GenerationWindow) isBehindAcrossWrap(index int) bool {
	return g.generation > 0 && index >= g.receiveWindow && index >= g.mod-g.receiveWindow
}
