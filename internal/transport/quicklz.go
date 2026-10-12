package transport

import (
	"encoding/binary"
	"errors"
)

var (
	errQlzDataTooShort          = errors.New("data too short")
	errQlzUnsupportedLevel      = errors.New("only QuickLZ level 1 is supported")
	errQlzDataTooShortForHeader = errors.New("data too short for header")
	errQlzTooLarge              = errors.New("declared decompressed size exceeds the limit")
	errQlzTruncated             = errors.New("compressed data ends before the declared size")
	errQlzBadReference          = errors.New("back-reference outside the decompressed data")
)

// TableSize is the QuickLZ level-1 hash table size.
const TableSize = 4096

// MaxDecompressedSize is the largest payload Decompress produces; a block
// declaring more is refused before anything is allocated.
//
// The largest command the servers send is the permission list, about 21 KiB
// decompressed on TeamSpeak 3 and 6. A reassembled command is bounded by the
// receive window to about 500 KiB compressed, so 1 MiB leaves a wide margin
// for real traffic while keeping a forged header from allocating gigabytes.
const MaxDecompressedSize = 1 << 20

// qlzMaxExpansion bounds how many output bytes one input byte of a level 1
// block can produce. The longest back-reference is three bytes copying 255, so
// 85 is the most; control words only lower it. Rounded up generously.
const qlzMaxExpansion = 128

// Qlz decompresses QuickLZ level 1, the compression TeamSpeak uses for
// command payloads. Its hash table is reused between calls, so a Qlz is not
// safe for concurrent use.
type Qlz struct {
	hashtable [TableSize]int
}

type qlzState struct {
	control    uint32
	sourcePos  int
	destPos    int
	nextHashed int
}

// NewQlz returns a QuickLZ level 1 decompressor.
func NewQlz() *Qlz {
	return &Qlz{}
}

// getDecompressedSize reads the declared size from a header whose length
// parseQlzHeader has already checked.
func getDecompressedSize(data []byte) int {
	if (data[0] & 0x02) != 0 {
		return int(binary.LittleEndian.Uint32(data[5:9]))
	}

	return int(data[2])
}

// Decompress returns the data a QuickLZ level 1 block holds, with a 3- or
// 9-byte header; a block stored uncompressed is copied out. Any other level, a
// declared size over MaxDecompressedSize, data that ends early and a
// back-reference outside the output are rejected with an error.
func (q *Qlz) Decompress(data []byte) ([]byte, error) {
	headerLen, decompressedSize, flags, err := parseQlzHeader(data)
	if err != nil {
		return nil, err
	}
	if decompressedSize > MaxDecompressedSize {
		return nil, errQlzTooLarge
	}
	// Nor more than the input can expand to, checked before the output is
	// allocated: a few bytes declaring a megabyte would otherwise cost one.
	if decompressedSize > (len(data)-headerLen)*qlzMaxExpansion+qlzMaxExpansion {
		return nil, errQlzTooLarge
	}

	if (flags & 0x01) == 0 {
		if len(data)-headerLen < decompressedSize {
			return nil, errQlzTruncated
		}
		dest := make([]byte, decompressedSize)
		copy(dest, data[headerLen:headerLen+decompressedSize])

		return dest, nil
	}

	dest := make([]byte, decompressedSize)

	for i := range q.hashtable {
		q.hashtable[i] = 0
	}

	state := qlzState{
		control:   1,
		sourcePos: headerLen,
	}

	for {
		if !q.ensureControl(data, &state) {
			return nil, errQlzTruncated
		}
		if (state.control & 1) != 0 {
			err = q.processReference(data, dest, &state)
			if err != nil {
				return nil, err
			}

			continue
		}
		done, err := q.processLiteral(data, dest, decompressedSize, &state)
		if err != nil {
			return nil, err
		}
		if done {
			return dest, nil
		}
	}
}

func parseQlzHeader(data []byte) (int, int, byte, error) {
	if len(data) < 3 {
		return 0, 0, 0, errQlzDataTooShort
	}
	flags := data[0]
	level := (flags >> 2) & 0x03
	if level != 1 {
		return 0, 0, 0, errQlzUnsupportedLevel
	}
	headerLen := 3
	if (flags & 0x02) != 0 {
		headerLen = 9
	}
	if len(data) < headerLen {
		return 0, 0, 0, errQlzDataTooShortForHeader
	}

	return headerLen, getDecompressedSize(data), flags, nil
}

func (q *Qlz) ensureControl(data []byte, st *qlzState) bool {
	if st.control != 1 {
		return true
	}
	if st.sourcePos+4 > len(data) {
		return false
	}
	st.control = binary.LittleEndian.Uint32(data[st.sourcePos : st.sourcePos+4])
	st.sourcePos += 4

	return true
}

func (q *Qlz) processReference(data, dest []byte, st *qlzState) error {
	st.control >>= 1
	if st.sourcePos+2 > len(data) {
		return errQlzTruncated
	}
	b1 := data[st.sourcePos]
	b2 := data[st.sourcePos+1]
	st.sourcePos += 2

	hash := int(b1>>4) | (int(b2) << 4)
	matchlen := int(b1 & 0x0F)
	if matchlen != 0 {
		matchlen += 2
	} else {
		if st.sourcePos >= len(data) {
			return errQlzTruncated
		}
		matchlen = int(data[st.sourcePos])
		st.sourcePos++
	}

	// A reference copies from output already written, possibly overlapping
	// what it writes, so it must start before the current position and end
	// within the declared size.
	offset := q.hashtable[hash]
	if offset >= st.destPos || st.destPos+matchlen > len(dest) {
		return errQlzBadReference
	}
	for i := range matchlen {
		dest[st.destPos] = dest[offset+i]
		st.destPos++
	}

	end := st.destPos + 1 - matchlen
	q.updateHashtable(dest, &st.nextHashed, end)
	st.nextHashed = st.destPos

	return nil
}

// processLiteral copies one literal, or every remaining one once the output is
// within ten bytes of its end, reporting whether the output is complete.
func (q *Qlz) processLiteral(data, dest []byte, decompressedSize int, st *qlzState) (bool, error) {
	if st.destPos >= max(decompressedSize, 10)-10 {
		for st.destPos < decompressedSize {
			if st.control == 1 {
				st.sourcePos += 4
				if st.sourcePos > len(data) {
					return false, errQlzTruncated
				}
				st.control = binary.LittleEndian.Uint32(data[st.sourcePos-4 : st.sourcePos])
			}
			if st.sourcePos >= len(data) {
				return false, errQlzTruncated
			}
			dest[st.destPos] = data[st.sourcePos]
			st.destPos++
			st.sourcePos++
			st.control >>= 1
		}

		return true, nil
	}
	if st.sourcePos >= len(data) {
		return false, errQlzTruncated
	}
	dest[st.destPos] = data[st.sourcePos]
	st.destPos++
	st.sourcePos++
	st.control >>= 1
	end := max(st.destPos-2, 0)
	q.updateHashtable(dest, &st.nextHashed, end)
	if st.nextHashed < end {
		st.nextHashed = end
	}

	return false, nil
}

func (q *Qlz) updateHashtable(dest []byte, nextHashed *int, end int) {
	for *nextHashed < end {
		if *nextHashed+3 > len(dest) {
			break
		}
		v := uint32(dest[*nextHashed]) | (uint32(dest[*nextHashed+1]) << 8) | (uint32(dest[*nextHashed+2]) << 16)
		hash := ((v >> 12) ^ v) & 0xFFF
		q.hashtable[hash] = *nextHashed
		*nextHashed++
	}
}
