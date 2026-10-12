package discovery

import (
	"errors"
	"net"
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

// A TSDNS answer is read only up to 8 KiB: a longer line is an error.
func TestQueryTSDNSBoundsTheAnswer(t *testing.T) {
	for _, tc := range []struct {
		answer string
		ok     bool
	}{
		{"203.0.113.5:9987\n", true},
		{strings.Repeat("x", maxResponseSize+100) + "\n", false},
	} {
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = conn.Read(make([]byte, 256))
			_, _ = conn.Write([]byte(tc.answer))
		}()
		got, err := queryTSDNS(t.Context(), ln.Addr().String(), "example.com")
		_ = ln.Close()
		if tc.ok && (err != nil || got != "203.0.113.5:9987") {
			t.Errorf("small answer = %q, %v", got, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("a %d-byte answer was accepted", len(tc.answer))
		}
	}
}
