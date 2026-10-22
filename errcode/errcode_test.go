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

// WebQuery's access refusals carry their own names, and a ServerError with the
// number matches the name.
func TestAPIKeyCodes(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		code errcode.Code
		id   uint32
	}{
		{"out of scope", errcode.APIKeyOutOfScope, 5120},
		{"invalid apikey", errcode.APIKeyInvalid, 5122},
		{"missing apikey", errcode.APIKeyMissing, 5124},
	} {
		err := fmt.Errorf("request: %w", &teamspeak.ServerError{Code: errcode.Code(tc.id), Message: tc.msg})
		if !errors.Is(err, tc.code) {
			t.Errorf("code %d does not match %v", tc.id, tc.code)
		}
		if uint32(tc.code) != tc.id || tc.code.Error() != tc.msg {
			t.Errorf("%d: name = %d %q", tc.id, uint32(tc.code), tc.code.Error())
		}
	}
}

// The stream refusals carry the server's own wording and match by name.
func TestStreamCodes(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		code errcode.Code
		id   uint32
	}{
		{"Stream does not exist", errcode.StreamNotFound, 5635},
		{"You are not participating in this stream", errcode.StreamNotParticipating, 5636},
		{"You already joined this stream", errcode.StreamAlreadyJoined, 5638},
		{"The join request was redacted", errcode.StreamJoinRequestRedacted, 5639},
	} {
		err := fmt.Errorf("stream: %w", &teamspeak.ServerError{Code: errcode.Code(tc.id), Message: tc.msg})
		if !errors.Is(err, tc.code) {
			t.Errorf("code %d does not match %v", tc.id, tc.code)
		}
		if uint32(tc.code) != tc.id || tc.code.Error() != tc.msg {
			t.Errorf("%d: name = %d %q", tc.id, uint32(tc.code), tc.code.Error())
		}
	}
}
