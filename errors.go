package teamspeak

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

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
// creating ones that return an id, AddPrivilegeKey, ViewLog — fails with an
// error wrapping it rather than return a zero value. A list that comes back
// empty is not this error.
//
// From a command that creates something, this error means the command took
// effect: the object exists, and the server only left its id out of the
// answer, which TeamSpeak 6's WebQuery does while a Server Admin voice client is
// connected (6.0.0-beta13.1). Do not retry such a command blindly, or it
// creates a second object or fails as a duplicate. CreateChannel,
// CreateServerGroup, CreateChannelGroup, CopyServerGroup and CopyChannelGroup
// look the new object up by its unique name first, and return this error only
// when nothing matches; AddPrivilegeKey and AddAPIKey cannot, and return it with
// the object created.
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
	// FailedPermission is the missing permission's name, as WebQuery reports it
	// (failed_permission); "" when the server named none. The voice protocol
	// and raw or SSH ServerQuery report an id instead, in FailedPermID.
	FailedPermission string
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

// floodRetryPattern is the wait in the extra message of a flooding refusal on
// the voice protocol, in milliseconds.
var floodRetryPattern = regexp.MustCompile(`^retry in ([0-9]{1,9})ms$`)

// floodPausePattern is the wait in the extra message of a flooding refusal on
// ServerQuery, in whole seconds.
var floodPausePattern = regexp.MustCompile(`^please wait ([0-9]{1,9}) seconds$`)

// FloodWait reads how long the server asks a client it refused as flooding to
// wait: the "retry in 1985ms" of the extra message of error 524. It reports
// false for any other error, or one that names no wait. The SDK never waits
// or resends on its own; a [LineMiddleware] can use this to do so.
//
// Measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0: a voice client whose
// antiflood points pass virtualserver_antiflood_points_needed_command_block
// gets `error id=524 msg=client\sis\sflooding extra_msg=retry\sin\s1985ms` for
// each command, and the command is not run. The wait is a floor, not a
// promise: a command sent as the wait ends is refused again with a shorter
// one, and the second try went through in every measurement.
//
// A ServerQuery client (raw TCP and SSH; over WebQuery the server closes the
// connection and says nothing) that sends faster than
// serverinstance_serverquery_flood_commands per _flood_time gets the same error
// with the wait in whole seconds, `extra_msg=please\swait\s1\sseconds`, and the
// command is not run. The first refusals say 1; later ones say the instance's
// serverinstance_serverquery_ban_time, as the address is banned for that long
// (new connections are dropped meanwhile). Asking again every half second kept
// the ban going for as long as it was kept up (9 seconds against a ban time of
// 4), while waiting out the pause and asking once got through. The wait is a
// floor here too: about one resend in three after exactly the wait was refused
// again, with the ban time.
func FloodWait(err error) (time.Duration, bool) {
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != errcode.ClientIsFlooding {
		return 0, false
	}
	if match := floodRetryPattern.FindStringSubmatch(serverErr.ExtraMessage); match != nil {
		return parseWait(match[1], time.Millisecond)
	}
	if match := floodPausePattern.FindStringSubmatch(serverErr.ExtraMessage); match != nil {
		return parseWait(match[1], time.Second)
	}

	return 0, false
}

// parseWait reads digits as a count of unit.
func parseWait(digits string, unit time.Duration) (time.Duration, bool) {
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, false
	}

	return time.Duration(n) * unit, true
}
