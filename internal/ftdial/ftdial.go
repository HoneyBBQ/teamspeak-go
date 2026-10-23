// Package ftdial marks a file transfer whose connection was never made, and
// says when such a transfer may still be stopped. The root package and package
// client both upload, so the mark is kept here rather than in either.
package ftdial

import (
	"errors"
	"time"
)

// NeverConnectedError is a dial that failed before the connection opened, so
// nothing reached the server: not the key, and no byte of the file. Not one the
// caller's context ended, nor one after the connection opened.
type NeverConnectedError struct{ Err error }

func (e *NeverConnectedError) Error() string { return e.Err.Error() }

func (e *NeverConnectedError) Unwrap() error { return e.Err }

// StopWithin is how soon after the negotiation a transfer whose dial failed is
// stopped. The server drops a transfer nobody dialled after about 10 seconds
// (measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0: gone from the active
// list at 10.05 s, and the voice client told 2059), and ftstop of a transfer
// the server no longer has crashes TeamSpeak 6, so a stop is only sent well
// inside that. A variable so that tests can shorten it.
var StopWithin = 5 * time.Second

// ShouldStop reports whether the transfer negotiated at negotiated is to be
// stopped after err: a dial that never got a connection, early enough that the
// server still has the transfer.
func ShouldStop(err error, negotiated time.Time) bool {
	var never *NeverConnectedError

	return errors.As(err, &never) && time.Since(negotiated) < StopWithin
}
