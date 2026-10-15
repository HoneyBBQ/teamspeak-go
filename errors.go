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
// such as a channelinfo for a channel the server no longer lists. Every
// command defined to answer with a row — the Get and Init methods, the
// creating ones that return an id, AddPrivilegeKey, ViewLog — fails with an error wrapping it rather than return a zero
// value. A list that comes back empty is not this error.
var ErrNoData = errors.New("the server answered with no data")

// ErrFileTransfer reports a file transfer that failed: dialling the transfer
// port, sending the key, or moving the data. errors.Is matches it, and the
// underlying error is wrapped too, so errors.Is(err, context.Canceled) still
// holds for a transfer ctx ended, as does os.ErrDeadlineExceeded for one that
// went idle. Every error UploadFileData, DownloadFileData and DialFileTransfer
// return wraps it, a ctx error included: such an error matches both
// ErrFileTransfer and ctx.Err().
var ErrFileTransfer = errors.New("file transfer")

// ErrInvalidCommand reports a command the client refuses to send as given.
var ErrInvalidCommand = errors.New("invalid command")

// ErrAlreadyConnected reports an attempt to connect a client that is already
// connected or connecting.
var ErrAlreadyConnected = errors.New("already connecting or connected")

// ErrMissingDependency reports a client built without a piece it cannot work
// without: an optional dependency left out of the build, so that the transport
// needing it is there but inert.
//
// It exists because the clients promise a transport by name, and a build
// without it should say which one rather than fail at the first dial with a
// message about a symbol. Match it with errors.Is and read the wrapping error
// for which dependency is missing.
var ErrMissingDependency = errors.New("missing dependency")

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

// Error reports the server's message, or the code's description when the
// server sent none, with the extra message and the code.
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
