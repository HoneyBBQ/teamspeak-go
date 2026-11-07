package teamspeak

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

var errRetryText = errors.New("retry in 10ms")

func TestFloodWait(t *testing.T) {
	flood := func(extra string) error {
		return &ServerError{Code: errcode.ClientIsFlooding, ExtraMessage: extra}
	}
	for extra, want := range map[string]time.Duration{
		"retry in 1985ms": 1985 * time.Millisecond,
		"retry in 0ms":    0,
		// A ServerQuery client is told in whole seconds.
		"please wait 1 seconds":   time.Second,
		"please wait 600 seconds": 600 * time.Second,
		"please wait 0 seconds":   0,
	} {
		got, ok := FloodWait(flood(extra))
		if !ok || got != want {
			t.Errorf("FloodWait(%q) = %v, %v, want %v", extra, got, ok, want)
		}
	}
	wrapped := fmt.Errorf("whoami: %w", flood("retry in 50ms"))
	if got, ok := FloodWait(wrapped); !ok || got != 50*time.Millisecond {
		t.Errorf("FloodWait(wrapped) = %v, %v, want 50ms", got, ok)
	}
	for _, err := range []error{
		flood(""), flood("retry in 5 seconds"), flood("retry in 99999999999ms"),
		flood("please wait 1.5 seconds"), flood("please wait seconds"), flood("please wait 1 seconds now"),
		&ServerError{Code: errcode.BanFlooding, ExtraMessage: "please wait 5 seconds"},
		&ServerError{Code: errcode.Code(1024), ExtraMessage: "retry in 10ms"},
		errRetryText, nil,
	} {
		if d, ok := FloodWait(err); ok {
			t.Errorf("FloodWait(%v) = %v, want none", err, d)
		}
	}
}
