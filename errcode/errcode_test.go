package errcode_test

import (
	"errors"
	"fmt"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

func ExampleCode() {
	err := fmt.Errorf("join channel: %w", &teamspeak.ServerError{
		Code:    errcode.ChannelInvalidPassword,
		Message: "invalid password",
	})

	fmt.Println(errors.Is(err, errcode.ChannelInvalidPassword))
	fmt.Println(errors.Is(err, teamspeak.ErrServer))
	fmt.Println(errors.Is(err, errcode.ChannelNameInUse))
	// Output:
	// true
	// true
	// false
}

func TestCodeError(t *testing.T) {
	if got := errcode.PermissionsClientInsufficient.Error(); got != "insufficient client permissions" {
		t.Errorf("PermissionsClientInsufficient.Error() = %q", got)
	}
	// A code this package does not know still says which code it is.
	if got := errcode.Code(0xfffe).Error(); got != "error 65534" {
		t.Errorf("unknown code = %q, want the number", got)
	}
}
