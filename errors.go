package teamspeak

import (
	"errors"
	"fmt"

	"github.com/honeybbq/teamspeak-go/errcode"
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
// It unwraps to both ErrServer and its Code, so a caller can match the class
// or a specific refusal:
//
//	errors.Is(err, teamspeak.ErrServer)
//	errors.Is(err, errcode.PermissionsClientInsufficient)
//
// The code is a typed field rather than only part of the message because
// callers act on it: a reconnect policy has to tell a transient refusal (521,
// too many clones, which clears once the server reaps the dropped session)
// from a permanent one (3329, banned), and parsing it back out of a string
// would be a guess.
type ServerError struct {
	// Message is the server's own text, such as "invalid channel password".
	Message string
	// ExtraMessage is detail the server adds to some refusals (extra_msg).
	ExtraMessage string
	// Code is the server's error code.
	Code errcode.Code
	// FailedPermID is the permission a refused permission check failed on, when
	// the server names one (failed_permid); 0 otherwise.
	FailedPermID PermissionID
}

func (e *ServerError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code.Error()
	}
	if e.ExtraMessage != "" {
		msg += " (" + e.ExtraMessage + ")"
	}

	return fmt.Sprintf("%s: %s (code %d)", ErrServer, msg, uint32(e.Code))
}

// Unwrap returns ErrServer and the code, so errors.Is matches either.
func (e *ServerError) Unwrap() []error {
	return []error{ErrServer, e.Code}
}
