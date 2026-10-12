package client

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
	"math/rand/v2"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// BackoffPolicy is how long to wait before each reconnect attempt. A zero
// field takes its value from DefaultBackoffPolicy.
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
type ShouldRetryFunc func(err error, attempt int) bool

// ReconnectOptions configure reconnection, which WithReconnect turns on.
type ReconnectOptions struct {
	// ShouldRetry overrides the default decision. A nil value uses
	// DefaultShouldRetry.
	ShouldRetry ShouldRetryFunc
	// Backoff tunes the retry delays.
	Backoff BackoffPolicy
}

// withDefaults fills unset fields from the default policy.
func (r ReconnectOptions) withDefaults() ReconnectOptions {
	r.Backoff = r.Backoff.withDefaults()

	return r
}

// Delay returns the delay before an attempt, with the policy's defaults
// applied.
//
// attempt is 1-based: the delay before the first retry is InitialDelay, give
// or take the jitter, and the delay never grows past MaxDelay.
func (p BackoffPolicy) Delay(attempt int) time.Duration {
	return p.withDefaults().delay(attempt, rand.Float64)
}

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
//
// The list used to be magic numbers with comments, and three were wrong: 1029
// and 1030, annotated as the wrong-password codes, are "deployment active" and
// "unable to stop own server", and 2569 is "insufficient group modify power".
// A wrong server password (1028) was therefore retried until the attempts ran
// out.
var permanentServerErrors = map[errcode.Code]bool{
	errcode.ConnectFailedBanned:           true,
	errcode.BanFlooding:                   true, // retrying while flood-banned extends the ban
	errcode.ServerInvalidPassword:         true,
	errcode.ChannelInvalidPassword:        true,
	errcode.PermissionsClientInsufficient: true,
}

// DefaultShouldRetry reports whether a failure is worth another attempt.
//
// Transport failures are retried, and so is a server that stopped. A server
// error is retried unless it is a permanent refusal: banned (3329), flood-banned
// (3331), a wrong server or channel password (1028, 781), or insufficient
// permissions (2568). Others, such as 521 for a session the server has not yet
// reaped, clear themselves. A kick or a ban is not retried: someone removed
// the client on purpose.
func DefaultShouldRetry(err error, _ int) bool {
	if err == nil {
		return true
	}

	if removed, ok := errors.AsType[*RemovedError](err); ok {
		return removed.Reason != teamspeak.ReasonKickServer && removed.Reason != teamspeak.ReasonKickServerBan
	}

	if serverErr, ok := errors.AsType[*teamspeak.ServerError](err); ok {
		return !permanentServerErrors[serverErr.Code]
	}

	return true
}
