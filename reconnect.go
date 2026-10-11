package teamspeak

// Reconnection policy.
//
// A dropped connection is normal on a UDP voice session, so a bot that cannot
// recover is not usable unattended. Reconnecting is opt-in rather than
// automatic: a silent reconnect makes a dropped session look like a healthy
// one, and a caller that wanted to know about the drop never finds out.
//
// Backoff is not a nicety here. TeamSpeak bans an IP that opens several
// connections in quick succession — measured at roughly three, after which the
// server answers error 3329 and refuses everything. A reconnect loop without a
// delay therefore bans itself, and the ban outlasts the outage it was
// recovering from.

import (
	"errors"
	"math"
	"math/rand"
	"time"
)

// BackoffPolicy is how long to wait before each reconnect attempt.
type BackoffPolicy struct {
	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration
	// MaxDelay is the ceiling; the delay never grows past it.
	MaxDelay time.Duration
	// Factor multiplies the delay after each failed attempt.
	Factor float64
	// Jitter is the fraction of the delay to randomise, 0 to 1.
	//
	// A fleet of bots that drop together would otherwise retry in lockstep and
	// hit the server in a burst. Jitter spreads them out.
	Jitter float64
	// MaxAttempts gives up after this many consecutive failures. 0 means never
	// give up.
	MaxAttempts int
}

// DefaultBackoffPolicy is a conservative starting point: one second, doubling,
// capped at a minute.
var DefaultBackoffPolicy = BackoffPolicy{
	InitialDelay: 1 * time.Second,
	MaxDelay:     60 * time.Second,
	Factor:       2,
	Jitter:       0.2,
	MaxAttempts:  0,
}

// ShouldRetryFunc decides whether a failure is worth another attempt.
type ShouldRetryFunc func(err error, attempt int) bool

// ReconnectOptions configure reconnection.
type ReconnectOptions struct {
	// ShouldRetry overrides the default decision. A nil value uses
	// DefaultShouldRetry.
	ShouldRetry ShouldRetryFunc
	// Backoff tunes the retry delays. Zero fields take the defaults.
	Backoff BackoffPolicy
	// Enabled turns reconnection on. Off by default.
	//
	// A deliberate Disconnect never reconnects, whatever this is set to.
	Enabled bool
}

// withDefaults fills unset fields from the default policy.
func (r ReconnectOptions) withDefaults() ReconnectOptions {
	out := r
	d := DefaultBackoffPolicy

	if out.Backoff.InitialDelay <= 0 {
		out.Backoff.InitialDelay = d.InitialDelay
	}
	if out.Backoff.MaxDelay <= 0 {
		out.Backoff.MaxDelay = d.MaxDelay
	}
	if out.Backoff.Factor <= 0 {
		out.Backoff.Factor = d.Factor
	}
	if out.Backoff.Jitter < 0 {
		out.Backoff.Jitter = d.Jitter
	}
	if out.Backoff.MaxDelay < out.Backoff.InitialDelay {
		out.Backoff.MaxDelay = out.Backoff.InitialDelay
	}

	return out
}

// BackoffDelay computes the delay before an attempt.
//
// attempt is 1-based: the delay before the first retry is InitialDelay, and the
// result is never above MaxDelay.
func BackoffDelay(policy BackoffPolicy, attempt int, random func() float64) time.Duration {
	if random == nil {
		random = rand.Float64
	}

	exponent := math.Max(0, float64(attempt-1))
	raw := float64(policy.InitialDelay) * math.Pow(policy.Factor, exponent)
	capped := math.Min(raw, float64(policy.MaxDelay))

	if policy.Jitter <= 0 {
		return time.Duration(math.Round(capped))
	}

	// Jitter around the computed delay rather than full jitter, so the trend
	// survives while peers still spread out.
	spread := capped * policy.Jitter
	offset := (random()*2 - 1) * spread
	delay := capped + offset
	if delay < 0 {
		delay = 0
	}

	return time.Duration(math.Round(delay))
}

// permanentServerErrors are the codes where retrying cannot help.
//
// Deliberately a short list of known refusals rather than "any server error".
// The server also answers transiently: after a dropped connection it still
// holds the old session, and a reconnect with the same identity is refused with
// 521 "too many clones already connected" until it reaps the zombie — a
// condition that clears itself and is worth retrying.
//
// The asymmetry is deliberate. Retrying a permanent failure costs a few bounded
// attempts; not retrying a transient one means never recovering.
var permanentServerErrors = map[string]bool{
	"3329": true, // connection failed, you are banned
	"3331": true, // banned from the server
	"1029": true, // invalid server password
	"1030": true, // invalid channel password
	"2568": true, // insufficient client permissions
	"2569": true, // insufficient permissions to join
}

// DefaultShouldRetry reports whether a failure is worth another attempt.
//
// Transport failures are retried; so is an unrecognised server error, for the
// reason given on permanentServerErrors.
func DefaultShouldRetry(err error, _ int) bool {
	if err == nil {
		return true
	}

	if serverErr, ok := errors.AsType[*ServerError](err); ok {
		return !permanentServerErrors[serverErr.ID]
	}

	return true
}
