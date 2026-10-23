package teamspeak

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"
)

// BackoffPolicy is how long to wait before each reconnect attempt. A zero
// field takes its value from DefaultBackoffPolicy; a value that cannot work is
// refused by Validate, which each client's New runs: a delay of nothing or a
// NaN factor would retry in a tight loop.
//
// Backoff is not a nicety here. TeamSpeak bans an IP that opens several
// connections in quick succession — measured at roughly three, after which the
// server answers error 3329 and refuses everything. A reconnect loop without a
// delay therefore bans itself, and the ban outlasts the outage it was
// recovering from.
type BackoffPolicy struct {
	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration
	// MaxDelay is the ceiling; the delay never grows past it.
	MaxDelay time.Duration
	// Factor multiplies the delay after each failed attempt.
	Factor float64
	// Jitter is the fraction of the delay to randomise, up to 1. A negative
	// value turns it off.
	//
	// A fleet of bots that drop together would otherwise retry in lockstep and
	// hit the server in a burst. Jitter spreads them out.
	Jitter float64
	// MaxAttempts gives up after this many consecutive failures. 0 means never
	// give up.
	MaxAttempts int
}

// DefaultBackoffPolicy is a conservative starting point: one second, doubling,
// capped at a minute, with 20% jitter, never giving up.
func DefaultBackoffPolicy() BackoffPolicy {
	return BackoffPolicy{
		InitialDelay: 1 * time.Second,
		MaxDelay:     60 * time.Second,
		Factor:       2,
		Jitter:       0.2,
	}
}

// ShouldRetryFunc decides whether a failure is worth another attempt.
//
// attempt is 1-based and counts consecutive failures. Which failures are worth
// retrying is the client's to decide: each client has its own default, and a
// caller replaces it with one of its own here.
type ShouldRetryFunc func(err error, attempt int) bool

// ReconnectOptions configure reconnection, which a client's WithReconnect
// turns on.
type ReconnectOptions struct {
	// ShouldRetry overrides the client's own default decision; a nil value
	// uses it.
	ShouldRetry ShouldRetryFunc
	// Backoff tunes the retry delays.
	Backoff BackoffPolicy
}

// ErrInvalidBackoff is what BackoffPolicy.Validate wraps when a field cannot
// work.
var ErrInvalidBackoff = errors.New("invalid backoff policy")

// Validate reports whether the policy's fields are usable, with the zero
// fields taken as unset; the error wraps ErrInvalidBackoff. Delays must be positive, a Factor at least 1, a
// Jitter at most 1 (negative turns it off), MaxAttempts not negative, and a
// MaxDelay not below the InitialDelay (an unset one is raised to it), and no
// float may be NaN or infinite.
func (p BackoffPolicy) Validate() error {
	if p.InitialDelay < 0 {
		return fmt.Errorf("%w: InitialDelay is positive, not %v", ErrInvalidBackoff, p.InitialDelay)
	}
	if p.MaxDelay < 0 {
		return fmt.Errorf("%w: MaxDelay is positive, not %v", ErrInvalidBackoff, p.MaxDelay)
	}
	if p.MaxDelay != 0 && p.InitialDelay != 0 && p.MaxDelay < p.InitialDelay {
		return fmt.Errorf("%w: MaxDelay (%v) is below its InitialDelay (%v)", ErrInvalidBackoff, p.MaxDelay, p.InitialDelay)
	}
	if p.MaxDelay != 0 && p.InitialDelay == 0 && p.MaxDelay < DefaultBackoffPolicy().InitialDelay {
		return fmt.Errorf("%w: MaxDelay (%v) is below the default InitialDelay (%v)",
			ErrInvalidBackoff, p.MaxDelay, DefaultBackoffPolicy().InitialDelay)
	}
	if math.IsNaN(p.Factor) || math.IsInf(p.Factor, 0) || p.Factor != 0 && p.Factor < 1 {
		return fmt.Errorf("%w: Factor is 1 or more, not %v", ErrInvalidBackoff, p.Factor)
	}
	if math.IsNaN(p.Jitter) || math.IsInf(p.Jitter, 0) || p.Jitter > 1 {
		return fmt.Errorf("%w: Jitter is a number up to 1, not %v", ErrInvalidBackoff, p.Jitter)
	}
	if p.MaxAttempts < 0 {
		return fmt.Errorf("%w: MaxAttempts is 0 or more, not %d", ErrInvalidBackoff, p.MaxAttempts)
	}

	return nil
}

// Delay reports how long to wait before an attempt, with the policy's defaults
// applied.
//
// attempt is 1-based: the delay before the first retry is InitialDelay, give
// or take the jitter, and the delay never grows past MaxDelay.
func (p BackoffPolicy) Delay(attempt int) time.Duration {
	return p.withDefaults().delay(attempt, rand.Float64)
}

// withDefaults fills unset fields from the default policy.
func (p BackoffPolicy) withDefaults() BackoffPolicy {
	d := DefaultBackoffPolicy()
	if p.InitialDelay <= 0 {
		p.InitialDelay = d.InitialDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = d.MaxDelay
	}
	if p.Factor <= 0 {
		p.Factor = d.Factor
	}
	switch {
	case p.Jitter == 0:
		p.Jitter = d.Jitter
	case p.Jitter < 0:
		p.Jitter = 0
	case p.Jitter > 1:
		p.Jitter = 1
	}
	if p.MaxDelay < p.InitialDelay {
		p.MaxDelay = p.InitialDelay
	}

	return p
}

// delay computes the delay on a policy whose defaults are applied, with random
// supplying the jitter.
func (p BackoffPolicy) delay(attempt int, random func() float64) time.Duration {
	exponent := math.Max(0, float64(attempt-1))
	raw := float64(p.InitialDelay) * math.Pow(p.Factor, exponent)
	capped := math.Min(raw, float64(p.MaxDelay))

	if p.Jitter <= 0 {
		return time.Duration(math.Round(capped))
	}

	// Jitter around the computed delay rather than full jitter, so the trend
	// survives while peers still spread out. Kept under the ceiling, which a
	// caller reasonably reads as a promise.
	spread := capped * p.Jitter
	delay := capped + (random()*2-1)*spread
	delay = math.Max(0, math.Min(delay, float64(p.MaxDelay)))

	return time.Duration(math.Round(delay))
}
