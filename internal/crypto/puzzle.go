package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

var (
	// ErrPuzzleTooHard reports an Init1 puzzle that asks for more squarings
	// than MaxRSAChallengeLevel. Nothing was solved.
	ErrPuzzleTooHard = errors.New("the server's RSA puzzle asks for more work than allowed")

	errRSAChallengeOutRange = errors.New("RSA challenge level out of range")
	errRSAChallengeShort    = errors.New("RSA challenge too short")
	errRSAChallengeModulus  = errors.New("RSA challenge modulus is zero")
)

const (
	rsaChallengeBlockSize = 64

	// MaxRSAChallengeLevel is the most squarings the Init1 puzzle may ask for.
	// A server raises its puzzle level while it is flooded with connections.
	// Measured, TeamSpeak 3.13 and 6.0 both ask for 10000 when calm, 100000 at
	// protection level 1 and 1000000 at level 2, the highest they reach; a
	// level lasts about 75 seconds after the burst that raised it. A squaring
	// takes about 0.25 microseconds here, so those take 2.5 ms, 25 ms and 250 ms.
	// The cap is four times the highest level seen, about a second of work. The solve
	// checks its context every squaringsPerSlice squarings, so a level near
	// the cap costs the caller at most what the caller allows the connect to
	// take; a level above it is refused with ErrPuzzleTooHard.
	MaxRSAChallengeLevel = 4_000_000

	// squaringsPerSlice is how many squarings SolveRsaChallenge does between
	// looks at its context: about 15 ms of work.
	squaringsPerSlice = 50_000
)

// puzzleState is what a connection's Init1 puzzle has done. The puzzle is
// solved off the goroutine that receives packets, so a mutex guards it.
type puzzleState struct {
	// challenge is the Init1 challenge the connection answered, and answer the
	// Init1 packet that answered it; nil until then. One connection answers
	// one challenge.
	challenge []byte
	answer    []byte
	// alpha is the alpha the client sent in clientinitiv.
	alpha []byte
	// duration is the time spent solving the puzzle, and level the level the
	// server demanded; zero until a puzzle was solved.
	duration time.Duration
	level    int
	mu       sync.Mutex
	// solving is set from the claim of a challenge until its answer or failure.
	solving bool
}

// ClaimPuzzle decides what to do with an Init1 challenge. If the connection
// has answered this challenge it returns that answer again, which is the case
// when the server did not get it; a different challenge, or one arriving while
// another is being solved, gets neither an answer nor a claim. A fresh
// challenge is claimed, with solve true, and the caller must follow it with
// FinishPuzzle or AbandonPuzzle.
func (tc *Crypt) ClaimPuzzle(challenge []byte) ([]byte, bool) {
	tc.puzzle.mu.Lock()
	defer tc.puzzle.mu.Unlock()

	if tc.puzzle.challenge != nil {
		if bytes.Equal(tc.puzzle.challenge, challenge) {
			return bytes.Clone(tc.puzzle.answer), false
		}

		return nil, false
	}
	if tc.puzzle.solving {
		return nil, false
	}
	tc.puzzle.solving = true

	return nil, true
}

// FinishPuzzle records the answer to the challenge ClaimPuzzle returned solve
// for, with the alpha it chose and the cost.
func (tc *Crypt) FinishPuzzle(challenge, answer, alpha []byte, level int, duration time.Duration) {
	tc.puzzle.mu.Lock()
	defer tc.puzzle.mu.Unlock()

	tc.puzzle.solving = false
	tc.puzzle.challenge = bytes.Clone(challenge)
	tc.puzzle.answer = bytes.Clone(answer)
	tc.puzzle.alpha = bytes.Clone(alpha)
	tc.puzzle.level = level
	tc.puzzle.duration = duration
}

// AbandonPuzzle gives up the claim of a challenge that was not answered.
func (tc *Crypt) AbandonPuzzle() {
	tc.puzzle.mu.Lock()
	defer tc.puzzle.mu.Unlock()

	tc.puzzle.solving = false
}

// Puzzle returns the level of the RSA puzzle the server demanded and the time
// spent solving it; zero until a puzzle was solved.
func (tc *Crypt) Puzzle() (int, time.Duration) {
	tc.puzzle.mu.Lock()
	defer tc.puzzle.mu.Unlock()

	return tc.puzzle.level, tc.puzzle.duration
}

// Alpha returns the alpha the client sent in clientinitiv: nil until a puzzle
// was answered.
func (tc *Crypt) Alpha() []byte {
	tc.puzzle.mu.Lock()
	defer tc.puzzle.mu.Unlock()

	return bytes.Clone(tc.puzzle.alpha)
}

// SolveRsaChallenge solves the Init1 step 4 puzzle: y = x^(2^level) mod n,
// with x and n the two 64-byte numbers at data[offset:], returned as 64
// big-endian bytes. The server uses it as a proof of work against floods.
//
// A level above MaxRSAChallengeLevel is refused with an error wrapping
// ErrPuzzleTooHard; data too short to hold x and n, and a zero n, are refused
// too. The solve looks at ctx every few thousand squarings and returns
// context.Cause(ctx) once it is done.
func (tc *Crypt) SolveRsaChallenge(ctx context.Context, data []byte, offset int, level int) ([]byte, error) {
	if level < 0 {
		return nil, fmt.Errorf("%w: %d", errRSAChallengeOutRange, level)
	}
	if level > MaxRSAChallengeLevel {
		return nil, fmt.Errorf("%w: %d squarings asked, at most %d", ErrPuzzleTooHard, level, MaxRSAChallengeLevel)
	}
	if offset < 0 || len(data)-offset < 2*rsaChallengeBlockSize {
		return nil, errRSAChallengeShort
	}
	x := new(big.Int).SetBytes(data[offset : offset+rsaChallengeBlockSize])
	n := new(big.Int).SetBytes(data[offset+rsaChallengeBlockSize : offset+2*rsaChallengeBlockSize])
	if n.Sign() == 0 {
		return nil, errRSAChallengeModulus
	}

	// y = x^(2^level) mod n via repeated squaring.
	y := new(big.Int).Set(x)
	for done := 0; done < level; {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		slice := min(level-done, squaringsPerSlice)
		for range slice {
			y.Mul(y, y)
			y.Mod(y, n)
		}
		done += slice
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}

	res := y.Bytes()
	if len(res) < rsaChallengeBlockSize {
		aligned := make([]byte, rsaChallengeBlockSize)
		copy(aligned[rsaChallengeBlockSize-len(res):], res)
		res = aligned
	} else if len(res) > rsaChallengeBlockSize {
		res = res[len(res)-rsaChallengeBlockSize:]
	}

	return res, nil
}
