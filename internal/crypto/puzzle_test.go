package crypto_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/crypto"
)

var errCallerGaveUp = errors.New("caller gave up")

func puzzleData(x, n *big.Int) []byte {
	d := make([]byte, 128)
	x.FillBytes(d[:64])
	n.FillBytes(d[64:])

	return d
}

func TestSolveRsaChallengeMatchesModPow(t *testing.T) {
	n := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 511), big.NewInt(1000003))
	x := big.NewInt(0x123456789abcdef)
	for _, level := range []int{0, 1, 10, 49999, 50000, 50001, 120007} {
		want := new(big.Int).Exp(x, new(big.Int).Lsh(big.NewInt(1), uint(level)), n)
		got, err := crypto.NewCrypt(nil).SolveRsaChallenge(context.Background(), puzzleData(x, n), 0, level)
		if err != nil || new(big.Int).SetBytes(got).Cmp(want) != 0 {
			t.Fatalf("level %d: %x, %v", level, got, err)
		}
	}
}

func TestSolveRsaChallengeCap(t *testing.T) {
	n := big.NewInt(1000003)
	data := puzzleData(big.NewInt(3), n)
	_, err := crypto.NewCrypt(nil).SolveRsaChallenge(context.Background(), data, 0, crypto.MaxRSAChallengeLevel+1)
	if !errors.Is(err, crypto.ErrPuzzleTooHard) {
		t.Fatalf("above the cap: %v", err)
	}
	// The cap itself is a puzzle, not refused: a cancelled context shows it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = crypto.NewCrypt(nil).SolveRsaChallenge(ctx, data, 0, crypto.MaxRSAChallengeLevel)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("at the cap: %v", err)
	}
}

func TestSolveRsaChallengeStopsWhenCancelled(t *testing.T) {
	n := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 511), big.NewInt(1000003))
	data := puzzleData(big.NewInt(7), n)
	reason := errCallerGaveUp
	ctx, cancel := context.WithCancelCause(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel(reason)
	}()
	start := time.Now()
	_, err := crypto.NewCrypt(nil).SolveRsaChallenge(ctx, data, 0, crypto.MaxRSAChallengeLevel)
	if !errors.Is(err, reason) {
		t.Fatalf("err = %v, want the cancel cause", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("stopped after %v", took)
	}
}
