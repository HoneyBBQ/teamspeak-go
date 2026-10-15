package serverquery

import (
	"context"
	"errors"
	"log/slog"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// Reconnection, which WithReconnect turns on.
//
// A query connection drops for the same reasons a voice one does — the server
// restarts, the network blinks — and a bot that cannot recover is not usable
// unattended. It is opt-in rather than automatic, as it is for the voice
// client: a silent reconnect makes a drop look like a healthy session, and a
// caller that wanted to know never finds out.

// reconnectAttemptTimeout bounds each reconnection attempt.
const reconnectAttemptTimeout = 30 * time.Second

// permanentQueryErrors are the refusals a retry cannot fix.
//
// The first two are a refused login and a refused server selection: the server
// is saying the credentials, the server id or the server itself is wrong, and
// repeating the same command will be refused the same way. The rest are the
// refusals the voice client's own policy already treats as permanent, kept
// here so the two clients agree about a ban.
var permanentQueryErrors = map[errcode.Code]bool{
	errcode.ClientInvalidPassword:         true, // login: wrong name or password
	errcode.ClientLoginNotPermitted:       true, // login: this account may not log in
	errcode.ServerInvalidID:               true, // use: no such server
	errcode.ServerIsNotRunning:            true, // use: that server is down
	errcode.ConnectFailedBanned:           true, // retrying while banned extends the ban
	errcode.BanFlooding:                   true, // retrying while flood-banned extends the ban
	errcode.PermissionsClientInsufficient: true, // the account lacks the permission it needs
}

// DefaultShouldRetry reports whether a failure is worth another attempt.
//
// Transport failures are retried, and so is a server that stopped answering. A
// server error is retried unless it is one the server would refuse again: a
// bad login, a server id that names nothing, a server that is not running, a
// ban, a flood ban, or a missing permission.
//
// A refused login and a refused `use` are the cases that matter, and they are
// what makes this different from the voice client's own policy: it never sends
// a login, so it has nothing to refuse.
//
// Experimental: this package may change in a minor release.
func DefaultShouldRetry(err error, _ int) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, ErrAuth) {
		// The SSH login was refused; the password will not be right next time.
		return false
	}

	if serverErr, ok := errors.AsType[*teamspeak.ServerError](err); ok {
		return !permanentQueryErrors[serverErr.Code]
	}

	return true
}

// scheduleReconnect retries a dropped connection, in the background, according
// to the policy. It runs at most one loop at a time and never after a
// deliberate Disconnect.
func (c *Client) scheduleReconnect(cause error) {
	c.mu.Lock()
	if c.reconnecting || c.stopped || c.reconnectOptions == nil {
		c.mu.Unlock()

		return
	}
	c.reconnecting = true
	options := *c.reconnectOptions
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.reconnecting = false
			c.mu.Unlock()
		}()
		c.reconnectLoop(cause, options)
	}()
}

// reconnectLoop makes the attempts, sleeping the policy's delay before each.
func (c *Client) reconnectLoop(cause error, options teamspeak.ReconnectOptions) {
	shouldRetry := options.ShouldRetry
	if shouldRetry == nil {
		shouldRetry = DefaultShouldRetry
	}

	for attempt := 1; options.Backoff.MaxAttempts == 0 || attempt <= options.Backoff.MaxAttempts; attempt++ {
		if c.isStopped() {
			return
		}
		if !shouldRetry(cause, attempt) {
			c.logger.Info("not retrying",
				slog.Int("attempt", attempt), slog.Any("error", cause))

			return
		}

		delay := options.Backoff.Delay(attempt)
		c.logger.Info("reconnecting", slog.Int("attempt", attempt), slog.Duration("delay", delay))
		if !c.sleepWhileRunning(delay) {
			return
		}

		err := c.reconnectAttempt()
		if err == nil {
			c.logger.Info("reconnected", slog.Int("attempt", attempt))

			return
		}
		if errors.Is(err, errStopped) {
			return
		}
		if errors.Is(err, teamspeak.ErrAlreadyConnected) {
			c.logger.Info("reconnect no longer needed")

			return
		}
		cause = err
	}

	c.logger.Warn("reconnect attempts exhausted", slog.Int("attempts", options.Backoff.MaxAttempts))
}

// reconnectAttempt runs one connection attempt on the reconnect loop's behalf.
// It is bounded by reconnectAttemptTimeout and by nothing else: the caller's
// Disconnect set the stop, which ends it.
func (c *Client) reconnectAttempt() error {
	ctx, cancel := context.WithTimeout(context.Background(), reconnectAttemptTimeout)
	defer cancel()

	return c.connect(ctx, connectKind{})
}

// isStopped reports whether a deliberate Disconnect has happened.
func (c *Client) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stopped
}

// sleepWhileRunning waits for d, returning false if the client was stopped
// meanwhile so the loop ends promptly rather than finishing its delay.
func (c *Client) sleepWhileRunning(d time.Duration) bool {
	stop := c.stopChan()
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return !c.isStopped()
	case <-stop:
		return false
	}
}
