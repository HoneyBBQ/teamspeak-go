package teamspeak

import (
	"errors"
	"fmt"
)

// ErrServer is the sentinel wrapped by every ServerError, so a caller can match
// on the class without knowing the id.
var ErrServer = errors.New("TeamSpeak server error")

// ErrNotConnected reports a command sent with no connection to send it on, or
// one whose connection was lost while it waited for its answer. Without it such
// a command would wait out its full timeout and fail as if the server were
// slow.
var ErrNotConnected = errors.New("not connected")

// ErrNoData reports a command that succeeded without the data it should carry,
// such as a channelinfo for a channel the server no longer lists.
var ErrNoData = errors.New("the server answered with no data")

// ErrInvalidCommand reports a command the client refuses to send as given.
var ErrInvalidCommand = errors.New("invalid command")

// ServerError is an error the TeamSpeak server reported.
//
// ID is the server's own error code, kept as a field rather than only formatted
// into the message because callers act on it: a reconnect policy has to tell a
// transient refusal (521, too many clones, which clears once the server reaps
// the dropped session) from a permanent one (3329, banned), and parsing it back
// out of an error string would be a guess.
type ServerError struct {
	// Message is the server's own text, such as "invalid channel password".
	Message string
	// ID is the numeric code as a string, exactly as the server sent it.
	ID string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("%s: %s (id=%s)", ErrServer, e.Message, e.ID)
}

// Unwrap makes errors.Is(err, ErrServer) work.
func (e *ServerError) Unwrap() error {
	return ErrServer
}
