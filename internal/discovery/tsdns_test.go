package discovery

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tsdnsServer answers one connection with answer (after reading the query),
// then closes it unless hold is set, in which case it waits for the client.
func tsdnsServer(t *testing.T, answer string, hold bool) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 256))
		if answer != "" {
			_, _ = conn.Write([]byte(answer))
		}
		if hold {
			_, _ = conn.Read(make([]byte, 1))
		}
	}()

	return ln.Addr().String()
}

func TestLookupTSDNS(t *testing.T) {
	for _, tc := range []struct {
		fail   error
		name   string
		answer string
		want   []string
	}{
		{name: "newline", answer: "203.0.113.5:9987\n", want: []string{"203.0.113.5:9987"}},
		{name: "no newline then close", answer: "203.0.113.5:9987", want: []string{"203.0.113.5:9987"}},
		{name: "not found", answer: "404\n"},
		{name: "errors", answer: "errors"},
		{name: "close with nothing"},
		{
			name: "several entries", answer: "1.2.3.4:9987 [::1]:9988 5.6.7.8\r\n",
			want: []string{"1.2.3.4:9987", "[::1]:9988", "5.6.7.8"},
		},
		{name: "oversize", answer: strings.Repeat("x", maxResponseSize+100) + "\n", fail: errResponseTooLarge},
		{name: "oversize without end", answer: strings.Repeat("x", maxResponseSize), fail: errResponseTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LookupTSDNS(t.Context(), tsdnsServer(t, tc.answer, false), "example.com")
			if !errors.Is(err, tc.fail) || (tc.fail == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.fail)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLookupTSDNSNoAnswerTimesOut(t *testing.T) {
	old := tsdnsTotalTimeout
	tsdnsTotalTimeout = 100 * time.Millisecond
	t.Cleanup(func() { tsdnsTotalTimeout = old })

	_, err := LookupTSDNS(t.Context(), tsdnsServer(t, "", true), "example.com")
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestLookupTSDNSCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	addr := tsdnsServer(t, "", true)
	time.AfterFunc(50*time.Millisecond, cancel)

	_, err := LookupTSDNS(ctx, addr, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestLookupTSDNSUnreachable(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err = LookupTSDNS(t.Context(), addr, "example.com")
	if err == nil {
		t.Fatal("a refused connection gave no error")
	}
}

func TestTSDNSAddrsNormalise(t *testing.T) {
	for entry, want := range map[string]string{
		"1.2.3.4:5000":        "1.2.3.4:5000",
		"1.2.3.4":             "1.2.3.4:9987",
		"1.2.3.4:$PORT":       "1.2.3.4:4321",
		"[2001:db8::1]:$PORT": "[2001:db8::1]:4321",
		"[::1]":               "[::1]:9987",
		"[::1]:9988":          "[::1]:9988",
		"host.example:1":      "host.example:1",
		"host.example:$PORT":  "host.example:4321",
	} {
		got := tsdnsAddrs([]string{entry}, "4321", SourceTSDNSDirect)
		if len(got) != 1 || got[0].Addr != want || got[0].Source != SourceTSDNSDirect {
			t.Errorf("%q = %+v, want %s", entry, got, want)
		}
	}
}

func TestResolverNicknameService(t *testing.T) {
	var calls atomic.Int32
	var gotName atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		gotName.Store(req.URL.Query().Get("name"))
		_, _ = w.Write([]byte("127.0.0.1:9999\n"))
	}))
	t.Cleanup(srv.Close)

	on := NewResolver(nil, true, srv.URL)
	got, err := on.Resolve(t.Context(), "mynick")
	if err != nil || len(got) != 1 || got[0].Addr != "127.0.0.1:9999" || got[0].Source != SourceDirect {
		t.Fatalf("Resolve = %+v, %v", got, err)
	}
	if name, _ := gotName.Load().(string); name != "mynick" {
		t.Fatalf("service saw name %q", name)
	}

	before := calls.Load()
	off := NewResolver(nil, false, srv.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, _ = off.Resolve(ctx, "othernick")
	if calls.Load() != before {
		t.Fatal("service called with NicknameLookup off")
	}
}

func TestResolverNicknameServiceInvalidFallsThrough(t *testing.T) {
	r := NewResolver(nil, true, "ftp://example.invalid/lookup")
	got, err := r.Resolve(t.Context(), "127.0.0.1:1")
	if err != nil || len(got) != 1 {
		t.Fatalf("Resolve = %+v, %v", got, err)
	}
	_, err = lookupNickname(t.Context(), "ftp://example.invalid/lookup", "x")
	if !errors.Is(err, errNicknameScheme) {
		t.Fatalf("err = %v", err)
	}
	_, err = lookupNickname(t.Context(), "://bad", "x")
	if err == nil {
		t.Fatal("unparsable endpoint accepted")
	}
}
