package discovery

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A nickname answer larger than 8 KiB is refused rather than read whole.
func TestLookupNicknameBoundsTheAnswer(t *testing.T) {
	serve := func(answer string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(answer))
		}))
		t.Cleanup(srv.Close)

		return srv.URL
	}

	got, err := lookupNickname(t.Context(), serve("203.0.113.5:9987\n"), "bot")
	if err != nil || got != "203.0.113.5:9987" {
		t.Fatalf("small answer = %q, %v", got, err)
	}
	_, err = lookupNickname(t.Context(), serve(strings.Repeat("x", maxResponseSize+1)), "bot")
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("9 KiB answer: %v, want errResponseTooLarge", err)
	}
}
