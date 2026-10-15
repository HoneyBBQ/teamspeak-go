package client

// Reconnection policy.
//
// A dropped connection is normal on a UDP voice session, so a bot that cannot
// recover is not usable unattended. Reconnecting is opt-in rather than
// automatic: a silent reconnect makes a dropped session look like a healthy
// one, and a caller that wanted to know about the drop never finds out.
//
// BackoffPolicy and ReconnectOptions themselves are shared with the ServerQuery
// client, so they live in the root package; this file is the voice protocol's
// own retry decision, and the loop that acts on it.

import (
	"errors"
	"sync"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// BackoffPolicy is teamspeak.BackoffPolicy.
type BackoffPolicy = teamspeak.BackoffPolicy

// DefaultBackoffPolicy is teamspeak.DefaultBackoffPolicy.
var DefaultBackoffPolicy = teamspeak.DefaultBackoffPolicy

// ShouldRetryFunc is teamspeak.ShouldRetryFunc.
type ShouldRetryFunc = teamspeak.ShouldRetryFunc

// ReconnectOptions is teamspeak.ReconnectOptions.
type ReconnectOptions = teamspeak.ReconnectOptions

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
	c.events.Push(func() {
		c.onDisconnected.Deliver(c.logger, "Disconnected", DisconnectedEvent{Err: err, WillReconnect: v.willReconnect()}, nil)
	})
}
