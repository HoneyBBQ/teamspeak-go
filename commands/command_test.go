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
