package commands_test

import (
	"testing"

	"github.com/honeybbq/teamspeak-go/commands"
)

func TestEscapeRoundTrips(t *testing.T) {
	in := "a b|c/d\\e\n"
	escaped := commands.Escape(in)
	if want := `a\sb\pc\/d\\e\n`; escaped != want {
		t.Errorf("Escape(%q) = %q, want %q", in, escaped, want)
	}
	if got := commands.Unescape(escaped); got != in {
		t.Errorf("Unescape(Escape(%q)) = %q", in, got)
	}
}

// The stream commands are named after what goes on the wire.
func TestStreamNames(t *testing.T) {
	for want, got := range map[string]string{
		"setupstream":              commands.SetupStream,
		"stopstream":               commands.StopStream,
		"joinstreamrequest":        commands.JoinStreamRequest,
		"respondjoinstreamrequest": commands.RespondJoinStreamRequest,
		"streamsignaling":          commands.StreamSignaling,
		"requeststreaminfo":        commands.RequestStreamInfo,
	} {
		if got != want {
			t.Errorf("name = %q, want %q", got, want)
		}
	}
}
