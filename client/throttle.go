package client

import (
	"context"
	"sync"
	"time"
)

// Flood throttle rates: a burst of tokenMax commands, then tokenRate a second,
// which keeps the client under the server's antiflood limit.
const (
	tokenRate    = 4.0
	tokenMax     = 8.0
	tokenInitial = 5.0
)

// commandThrottle is a token-bucket limiter for outbound commands. Waiters are
// released in the order they arrived: one that has waited longest goes first,
// so a burst of commands cannot overtake one already queued.
type commandThrottle struct {
	lastUpdate time.Time
	// holdUntil is when nothing is released until: the server asked this
	// client to wait.
	holdUntil time.Time
	// timer releases the head of queue once a token has accrued; nil when no
	// release is scheduled.
	timer *time.Timer
	// queue holds the waiters not yet released, oldest first.
	queue  []*waiter
	tokens float64
	mu     sync.Mutex
}

// waiter is one command waiting for its turn. Its ready channel is closed when
// it is released or rejected; err, written before, tells which.
type waiter struct {
	ready chan struct{}
	err   error
}

func newCommandThrottle() *commandThrottle {
	return &commandThrottle{
		tokens:     tokenInitial,
		lastUpdate: time.Now(),
	}
}

// wait takes a token, waiting in line for one until ctx is done.
func (t *commandThrottle) wait(ctx context.Context) error {
	t.mu.Lock()
	t.refillLocked()
	if len(t.queue) == 0 && t.tokens >= 1 && !time.Now().Before(t.holdUntil) {
		t.tokens--
		t.mu.Unlock()

		return nil
	}
	w := &waiter{ready: make(chan struct{})}
	t.queue = append(t.queue, w)
	t.releaseLocked()
	t.mu.Unlock()

	select {
	case <-w.ready:
		return w.err
	case <-ctx.Done():
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for i, q := range t.queue {
		if q == w {
			t.queue = append(t.queue[:i], t.queue[i+1:]...)

			return ctx.Err()
		}
	}
	// Released (or rejected) just as ctx ended: a token taken goes to the next
	// in line.
	if w.err == nil {
		t.tokens++
		t.releaseLocked()
	}

	return ctx.Err()
}

// rejectAll fails every waiter still in line with err, so none of them is ever
// released to send. Commands that ask afterwards wait as before.
func (t *commandThrottle) rejectAll(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, w := range t.queue {
		w.err = err
		close(w.ready)
	}
	t.queue = nil
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}

func (t *commandThrottle) refillLocked() {
	now := time.Now()
	// Nothing accrues while held.
	from := t.lastUpdate
	if t.holdUntil.After(from) {
		from = t.holdUntil
	}
	t.tokens = min(t.tokens+max(now.Sub(from).Seconds(), 0)*tokenRate, tokenMax)
	t.lastUpdate = now
}

// hold releases nothing for d, then goes on at the usual rate with no burst
// saved up: the server refused a command as flooding and said when to try
// again, and anything sent sooner is refused too and adds to the debt.
func (t *commandThrottle) hold(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.refillLocked()
	until := time.Now().Add(d)
	if until.After(t.holdUntil) {
		t.holdUntil = until
	}
	t.tokens = 0
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	t.scheduleLocked()
}

// releaseLocked hands the tokens there are to the waiters at the head of the
// queue, in order, and schedules the next release if any are left.
func (t *commandThrottle) releaseLocked() {
	t.refillLocked()
	// Woken early, or the hold was extended meanwhile.
	if time.Now().Before(t.holdUntil) {
		t.scheduleLocked()

		return
	}
	for len(t.queue) > 0 && t.tokens >= 1 {
		t.tokens--
		close(t.queue[0].ready)
		t.queue[0] = nil
		t.queue = t.queue[1:]
	}
	t.scheduleLocked()
}

// scheduleLocked arms the timer for when the head of the queue will have its
// token, unless it is already armed or nobody waits.
func (t *commandThrottle) scheduleLocked() {
	if len(t.queue) == 0 || t.timer != nil {
		return
	}
	// Tokens accrue only once the hold is over.
	delay := time.Duration((1-t.tokens)/tokenRate*float64(time.Second)) + time.Millisecond
	if held := time.Until(t.holdUntil); held > 0 {
		delay += held
	}
	t.timer = time.AfterFunc(delay, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.timer = nil
		t.releaseLocked()
	})
}
