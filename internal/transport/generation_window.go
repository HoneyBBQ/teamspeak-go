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
func (g *GenerationWindow) MappedToIndex(mappedValue int) int {
	if g.IsNextGen(mappedValue) {
		return (mappedValue + g.mod) - g.mappedBaseOffset
	}

	return mappedValue - g.mappedBaseOffset
}

// IsOldPacket reports whether mappedValue is before the receive window.
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

// GetGeneration returns the generation mappedValue belongs to, one past the
// current generation if the id has already wrapped.
func (g *GenerationWindow) GetGeneration(mappedValue int) uint32 {
	if g.IsNextGen(mappedValue) {
		return g.generation + 1
	}

	return g.generation
}

// Reset returns the window to id 0 of generation 0.
func (g *GenerationWindow) Reset() {
	g.mappedBaseOffset = 0
	g.generation = 0
}
