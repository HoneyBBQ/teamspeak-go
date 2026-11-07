// Package servererr reads the error line that ends every answer, for the
// transports that execute commands.
//
// It is separate from package wire because it builds a teamspeak.ServerError,
// so it imports the root package, which itself imports wire.
package servererr

import (
	"strconv"

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
