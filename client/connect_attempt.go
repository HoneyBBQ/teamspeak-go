package client

import "time"

// connectAttempt tracks the outcome of one connection attempt, for Connect.
//
// done is closed exactly once, when the handshake either completes or fails.
// err is written before done is closed and never afterwards, so a reader that
// has observed done closed may read err without holding the client's lock.
//
// The attempt's outcome is claimed exactly once, under the client's lock: the
// claim is what makes an attempt end with exactly one of SessionStart and
// AttemptFailed, and done is closed only after that hook has returned, so both
// run before Connect does.
//
// The remaining fields are the trace's record of the attempt and are guarded
// by the client's lock.
type connectAttempt struct {
	// resolveStart, connectStart and sessionStartedAt are the clocks of the
	// durations.
	resolveStart     time.Time
	connectStart     time.Time
	sessionStartedAt time.Time
	err              error
	done             chan struct{}

	// target is the host:port being dialled, set at ResolveDone.
	target string
	// channels counts the channel rows of the welcome sequence.
	channels int
	// number and reconnect are the Attempt and Reconnect of every hook.
	number    int
	reconnect bool
	// claimed is set by the one call that decides the outcome.
	claimed bool
	// traced is set once the attempt has begun, from ResolveStart on. An
	// attempt that never began has nothing to report.
	traced bool
	// opened, handshakeDone, sessionStarted and welcomeDone record the
	// milestones reached, which also say what phase a failure belongs to.
	opened         bool
	handshakeDone  bool
	sessionStarted bool
	// sessionEnded is set by the one call that reports the session's end.
	sessionEnded bool
	welcomeDone  bool
}

func newConnectAttempt() *connectAttempt {
	return &connectAttempt{done: make(chan struct{})}
}

// begin starts the trace record of the attempt, forgetting any earlier one.
// The caller holds the client's lock.
func (a *connectAttempt) begin(number int, reconnect bool) {
	a.traced = true
	a.number = number
	a.reconnect = reconnect
	a.resolveStart = time.Now()
	a.connectStart = time.Time{}
	a.opened = false
	a.handshakeDone = false
	a.sessionStarted = false
	a.sessionEnded = false
	a.welcomeDone = false
	a.target = ""
	a.channels = 0
}

// phase is where the attempt is now, and so where it fails if it fails now.
func (a *connectAttempt) phase() ConnectPhase {
	switch {
	case a.handshakeDone:
		return ConnectPhaseJoin
	case a.opened:
		return ConnectPhaseHandshake
	default:
		return ConnectPhaseOpen
	}
}

// finished reports whether the attempt has already succeeded or failed.
func (a *connectAttempt) finished() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

// claim decides the outcome, recording err. Only the first call has any
// effect, and reports true. The caller must hold the client's lock, which
// serialises claim with other claim calls, and must follow a true with
// complete, once the lock is released.
func (a *connectAttempt) claim(err error) bool {
	if a.claimed {
		return false
	}
	a.claimed = true
	a.err = err

	return true
}

// complete releases whoever waits for the outcome claim decided.
func (a *connectAttempt) complete() {
	close(a.done)
}
