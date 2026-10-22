package teamspeak

import (
	"math"
	"testing"
)

func TestNewTransferRunClampsTotal(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   uint64
		want int64
	}{
		{"zero", 0, 0},
		{"small", 1234, 1234},
		{"max int64", math.MaxInt64, math.MaxInt64},
		{"above max int64", math.MaxInt64 + 1, math.MaxInt64},
		{"max uint64", math.MaxUint64, math.MaxInt64},
	} {
		if got := newTransferRun(FileTransferOptions{}, tc.in).total; got != tc.want {
			t.Errorf("%s: total = %d, want %d", tc.name, got, tc.want)
		}
	}
}
