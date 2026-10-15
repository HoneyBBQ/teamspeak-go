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
	"sync"
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
// the client on purpose. Nor is ErrInvalidAddress: an address that cannot be
// one stays that way.
func DefaultShouldRetry(err error, _ int) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, ErrInvalidAddress) {
		return false
	}

	if removed, ok := errors.AsType[*RemovedError](err); ok {
		return removed.Reason != teamspeak.ReasonKickServer && removed.Reason != teamspeak.ReasonKickServerBan
	}

	if serverErr, ok := errors.AsType[*teamspeak.ServerError](err); ok {
		return !permanentServerErrors[serverErr.Code]
	}

	return true
}

// retryVerdict is whether the reconnect loop will try again after one failure.
//
// Both the loop and the DisconnectedEvent announcing the failure need the
// answer, and ShouldRetry is the caller's function: the verdict asks it once,
// from whichever of the two comes first, and the other reuses the answer. The
// policy is asked with no lock held.
type retryVerdict struct {
	err     error
	attempt int
	// ask is the policy's decision; nil when reconnection is off or the client
	// has been stopped, either of which rules out another attempt.
	ask func(err error, attempt int) bool
	// inBounds is false once the attempts are used up.
	inBounds bool

	once   sync.Once
	accept bool
}

// policy is whether ShouldRetry accepts the failure, without regard to how
// many attempts are left.
func (v *retryVerdict) policy() bool {
	v.once.Do(func() { v.accept = v.ask != nil && v.ask(v.err, v.attempt) })

	return v.accept
}

// willReconnect is whether the loop will make attempt number v.attempt.
func (v *retryVerdict) willReconnect() bool {
	return v.ask != nil && v.inBounds && v.policy()
}

// newVerdictLocked is the verdict on err, the failure before attempt number
// attempt. The caller holds c.mu.
func (c *Client) newVerdictLocked(err error, attempt int) *retryVerdict {
	v := &retryVerdict{err: err, attempt: attempt}
	if c.reconnectOptions == nil || c.stopped {
		return v
	}
	v.ask = c.reconnectOptions.ShouldRetry
	if v.ask == nil {
		v.ask = DefaultShouldRetry
	}
	maxAttempts := c.reconnectOptions.Backoff.MaxAttempts
	v.inBounds = maxAttempts == 0 || attempt <= maxAttempts

	return v
}

// failedAttemptVerdictLocked is the verdict on a failed connection attempt: a
// reconnect attempt is followed by the next one, if the policy allows, while a
// failed Connect is never retried. It is kept for the loop, which asks it
// again. The caller holds c.mu.
func (c *Client) failedAttemptVerdictLocked(err error) *retryVerdict {
	if !c.attempt.reconnect {
		return &retryVerdict{err: err}
	}
	c.attemptVerdict = c.newVerdictLocked(err, c.attempt.number+1)

	return c.attemptVerdict
}

// takeVerdict returns the verdict left for the reconnect attempt that failed
// with err, or makes one when the attempt failed before it began.
func (c *Client) takeVerdict(err error, attempt int) *retryVerdict {
	c.mu.Lock()
	defer c.mu.Unlock()

	v := c.attemptVerdict
	c.attemptVerdict = nil
	if v == nil {
		v = c.newVerdictLocked(err, attempt)
	}

	return v
}

// emitDisconnectedLocked queues the disconnected event for err. WillReconnect
// is worked out when it is delivered, on the event goroutine, because asking
// ShouldRetry takes no lock and the caller holds c.mu.
func (c *Client) emitDisconnectedLocked(err error, v *retryVerdict) {
	c.events.push(func() {
		c.onDisconnected.deliver(c.logger, "Disconnected", DisconnectedEvent{Err: err, WillReconnect: v.willReconnect()}, nil)
	})
}
