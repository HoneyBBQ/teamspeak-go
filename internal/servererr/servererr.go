// Package servererr reads the error line that ends every answer, for the
// transports that execute commands.
//
// It is separate from package wire because it builds a teamspeak.ServerError,
// so it imports the root package, which itself imports wire.
package servererr

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// Parse reads an error line's parameters, returning nil for success.
func Parse(params map[string]string) *teamspeak.ServerError {
	code := wire.ParseCode(params["id"])
	if code == errcode.OK {
		return nil
	}
	failedPermID, _ := strconv.ParseUint(params["failed_permid"], 10, 32)

	return &teamspeak.ServerError{
		Code:         code,
		Message:      params["msg"],
		ExtraMessage: params["extra_msg"],
		FailedPermID: teamspeak.PermissionID(failedPermID),

		FailedPermission: params["failed_permission"],
	}
}

// FloodRetries is how many times a command refused as flooding is sent again
// after the pause the server asked for. On the voice protocol the first resend
// is usually refused once more with a shorter wait, and the second goes through
// (measured on TeamSpeak 3 and 6); on ServerQuery a refusal can be answered
// with a longer wait, which the caller's deadline then decides whether to sit
// out.
const FloodRetries = 3

// FloodHold is how long to pause for a refusal that asked for wait. The wait
// is a floor: on the voice protocol a resend after exactly the wait is refused
// again, and one after half as long again goes through; on ServerQuery a resend
// after exactly 1 second was refused 2 times in 5, and one after 2.2 seconds
// went through 5 times in 5 (TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0). Every
// refusal costs a retry and lengthens the server's pause, so the pause is
// twice the wait.
func FloodHold(wait time.Duration) time.Duration {
	return 2 * wait
}

// Affordable reports whether ctx lasts longer than wait.
func Affordable(ctx context.Context, wait time.Duration) bool {
	deadline, ok := ctx.Deadline()

	return !ok || wait < time.Until(deadline)
}

// floodRetryPattern is the wait in the extra message of a flooding refusal on
// the voice protocol, in milliseconds.
var floodRetryPattern = regexp.MustCompile(`^retry in ([0-9]{1,9})ms$`)

// floodPausePattern is the wait in the extra message of a flooding refusal on
// ServerQuery, in whole seconds.
var floodPausePattern = regexp.MustCompile(`^please wait ([0-9]{1,9}) seconds$`)

// FloodRetryDelay reads how long the server asks a client it refused as
// flooding to wait: the "retry in 1985ms" of the extra message of error 524.
// It reports false for any other error, or one that names no wait.
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
func FloodRetryDelay(err error) (time.Duration, bool) {
	var serverErr *teamspeak.ServerError
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
