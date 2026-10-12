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
	// timer releases the head of queue once a token has accrued; nil when no
	// release is scheduled.
	timer *time.Timer
	// queue holds the waiters not yet released, oldest first. A released
	// waiter's channel is closed.
	queue  []chan struct{}
	tokens float64
	mu     sync.Mutex
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
	if len(t.queue) == 0 && t.tokens >= 1 {
		t.tokens--
		t.mu.Unlock()

		return nil
	}
	ready := make(chan struct{})
	t.queue = append(t.queue, ready)
	t.releaseLocked()
	t.mu.Unlock()

	select {
	case <-ready:
		return nil
	case <-ctx.Done():
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for i, w := range t.queue {
		if w == ready {
			t.queue = append(t.queue[:i], t.queue[i+1:]...)

			return ctx.Err()
		}
	}
	// Released just as ctx ended: the token goes to the next in line.
	t.tokens++
	t.releaseLocked()

	return ctx.Err()
}

func (t *commandThrottle) refillLocked() {
	now := time.Now()
	t.tokens = min(t.tokens+now.Sub(t.lastUpdate).Seconds()*tokenRate, tokenMax)
	t.lastUpdate = now
}

// releaseLocked hands the tokens there are to the waiters at the head of the
// queue, in order, and schedules the next release if any are left.
func (t *commandThrottle) releaseLocked() {
	t.refillLocked()
	for len(t.queue) > 0 && t.tokens >= 1 {
		t.tokens--
		close(t.queue[0])
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
	delay := time.Duration((1-t.tokens)/tokenRate*float64(time.Second)) + time.Millisecond
	t.timer = time.AfterFunc(delay, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.timer = nil
		t.releaseLocked()
	})
}
