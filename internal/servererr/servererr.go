// Package servererr reads the error line that ends every answer, for the
// transports that execute commands.
//
// It is separate from package wire because it builds a teamspeak.ServerError,
// so it imports the root package, which itself imports wire.
package servererr

import (
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

// floodRetryPattern is the wait in the extra message of a flooding refusal.
var floodRetryPattern = regexp.MustCompile(`^retry in ([0-9]{1,9})ms$`)

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
func FloodRetryDelay(err error) (time.Duration, bool) {
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != errcode.ClientIsFlooding {
		return 0, false
	}
	match := floodRetryPattern.FindStringSubmatch(serverErr.ExtraMessage)
	if match == nil {
		return 0, false
	}
	ms, parseErr := strconv.ParseUint(match[1], 10, 32)
	if parseErr != nil {
		return 0, false
	}

	return time.Duration(ms) * time.Millisecond, true
}
