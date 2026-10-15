package serverquery

import (
	"errors"
	"fmt"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

var errNetworkDropped = errors.New("connection reset by peer")

// The default decision separates a failure that redialling can fix from one it
// cannot, and the second kind has to stay un-retried: a loop on a refusal only
// repeats it, and on a host key it repeats an offer to an impersonator.
func TestDefaultShouldRetry(t *testing.T) {
	for _, tc := range []struct {
		err  error
		name string
		want bool
	}{
		{nil, "no error", true},
		{errNetworkDropped, "a dropped connection", true},
		{fmt.Errorf("%w: %w", ErrDial, errNetworkDropped), "a connection that could not be opened", true},
		{&teamspeak.ServerError{Code: errcode.Undefined}, "a refusal that may clear", true},
		{fmt.Errorf("%w: ssh: handshake", ErrAuth), "a refused ssh login", false},
		{&teamspeak.ServerError{Code: errcode.ClientInvalidPassword}, "a refused query login", false},
		{&teamspeak.ServerError{Code: errcode.ServerInvalidID}, "a server id that names nothing", false},
		{&teamspeak.ServerError{Code: errcode.ConnectFailedBanned}, "a ban", false},
		{fmt.Errorf("%w: 127.0.0.1:10022: key mismatch", ErrHostKey), "a host key that changed", false},
		{fmt.Errorf("%w: 127.0.0.1:10022: key is unknown", ErrHostKey), "a host key that is unknown", false},
		// The refusal arrives wrapped by the dial and by the failed handshake, so
		// the decision has to see through both.
		{
			fmt.Errorf("%w: ssh 127.0.0.1:10022: %w", ErrDial, fmt.Errorf("handshake failed: %w", ErrHostKey)),
			"a host key refused inside a dial error",
			false,
		},
	} {
		if got := DefaultShouldRetry(tc.err, 1); got != tc.want {
			t.Errorf("%s: DefaultShouldRetry = %v, want %v", tc.name, got, tc.want)
		}
	}
}
