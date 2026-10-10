package teamspeak

// connectAttempt tracks the outcome of one connection attempt for WaitConnected.
//
// done is closed exactly once, when the handshake either completes or fails.
// err is written before done is closed and never afterwards, so a reader that
// has observed done closed may read err without holding the client's lock.
type connectAttempt struct {
	done chan struct{}
	err  error
}

func newConnectAttempt() *connectAttempt {
	return &connectAttempt{done: make(chan struct{})}
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

// finish records the outcome. Only the first call has any effect. The caller
// must hold the client's lock, which serialises finish with other finish calls.
func (a *connectAttempt) finish(err error) {
	if a.finished() {
		return
	}
	a.err = err
	close(a.done)
}
