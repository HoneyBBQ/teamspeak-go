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
	errcode.ClientNotLoggedIn:             true, // use: this session has no login, and none is configured
	errcode.ClientLoginNotPermitted:       true, // login: this account may not log in
	errcode.ServerInvalidID:               true, // use: no such server
	errcode.ServerIsNotRunning:            true, // use: that server is down
	errcode.ConnectFailedBanned:           true, // retrying while banned extends the ban
	errcode.BanFlooding:                   true, // retrying while flood-banned extends the ban
	errcode.PermissionsClientInsufficient: true, // the account lacks the permission it needs
}

// handshakeRefusalError is a `login` or `use` the server refused. The command is
// the one fact the error code alone does not carry: a refusal of either is
// about the account or the target, which a retry does not change, whatever
// code the server gave it. Only the server's flood limit clears by itself,
// and it is not wrapped.
type handshakeRefusalError struct {
	err  error
	step string
}

func (e *handshakeRefusalError) Error() string { return e.step + ": " + e.err.Error() }

func (e *handshakeRefusalError) Unwrap() error { return e.err }

// DefaultShouldRetry reports whether a failure is worth another attempt.
//
// Transport failures are retried, and so is a server that stopped answering. A
// server error is retried unless it is one the server would refuse again: a
// bad login, a server id that names nothing, a server that is not running, a
// ban, a flood ban, or a missing permission.
//
// Whatever code a refused `login` or `use` carried, it is not retried, except
// the query flood limit (client is flooding), which clears by itself and is
// what a reconnect loop most likely meets right after a drop.
//
// A refused login and a refused `use` are the cases that matter, and they are
// what makes this different from the voice client's own policy: it never sends
// a login, so it has nothing to refuse.
//
// An SSH host key that was not accepted is not retried either, whether the
// host is unknown or its key has changed: neither fixes itself by dialling
// again, and looping on a key that may belong to an impersonator is the wrong
// default.
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
	if _, ok := errors.AsType[*handshakeRefusalError](err); ok {
		return false
	}
	if errors.Is(err, ErrHostKey) {
		// An unknown or changed key stays so; redialling only offers it again.
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
	c.loopAttempt = 0
	options := *c.reconnectOptions
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.reconnecting = false
			c.loopAttempt = 0
			c.verdict = nil
			c.mu.Unlock()
		}()
		c.reconnectLoop(cause, options)
	}()
}

// retryVerdict is the policy's answer for a failure, kept so that the
// disconnected event that announces it and the loop that acts on it are one
// question, asked once: a caller's ShouldRetry is not run twice for a failure.
type retryVerdict struct {
	attempt int
	retry   bool
}

// willRetry asks whether attempt number attempt will follow the failure err,
// as the loop will decide it, and remembers the answer for the loop. A client
// with no reconnection, or stopped, never retries.
func (c *Client) willRetry(err error, attempt int) bool {
	c.mu.Lock()
	options := c.reconnectOptions
	stopped := c.stopped
	c.mu.Unlock()
	if options == nil || stopped {
		return false
	}
	retry := options.Backoff.MaxAttempts == 0 || attempt <= options.Backoff.MaxAttempts
	if retry {
		shouldRetry := options.ShouldRetry
		if shouldRetry == nil {
			shouldRetry = DefaultShouldRetry
		}
		retry = shouldRetry(err, attempt)
	}
	c.mu.Lock()
	c.verdict = &retryVerdict{attempt: attempt, retry: retry}
	c.mu.Unlock()

	return retry
}

// takeVerdict returns the answer willRetry gave for attempt, once.
func (c *Client) takeVerdict(attempt int) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.verdict
	c.verdict = nil
	if v == nil || v.attempt != attempt {
		return false, false
	}

	return v.retry, true
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
		retry, announced := c.takeVerdict(attempt)
		if !announced {
			retry = shouldRetry(cause, attempt)
		}
		if !retry {
			c.logger.Info("not retrying",
				slog.Int("attempt", attempt), slog.Any("error", cause))

			return
		}

		delay := options.Backoff.Delay(attempt)
		c.logger.Info("reconnecting", slog.Int("attempt", attempt), slog.Duration("delay", delay))
		if !c.sleepWhileRunning(delay) {
			return
		}

		c.mu.Lock()
		c.loopAttempt = attempt
		c.mu.Unlock()
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

// nextAttempt is the number of the attempt the loop would make after the
// failure just seen: the first when no loop is running.
func (c *Client) nextAttempt() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.loopAttempt + 1
}
