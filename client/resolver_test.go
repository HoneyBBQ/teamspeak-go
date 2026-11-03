package client

import (
	"net"
	"slices"
	"testing"
	"time"
)

func TestResolverResolveConvertsTheAnswer(t *testing.T) {
	got, err := NewResolver(ResolverOptions{}).Resolve(t.Context(), "192.0.2.7:1234")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].Addr != "192.0.2.7:1234" || got[0].Source != ResolveSourceDirect {
		t.Fatalf("got %+v, want 192.0.2.7:1234 from Direct", got)
	}
	if got[0].Expiry != (time.Time{}) {
		t.Fatalf("expiry = %v, want zero for an IP literal", got[0].Expiry)
	}
}

func TestResolverResolveError(t *testing.T) {
	got, err := NewResolver(ResolverOptions{}).Resolve(t.Context(), "")
	if err == nil || got != nil {
		t.Fatalf("Resolve(\"\") = %v, %v; want an error", got, err)
	}
}

func TestLookupTSDNSReadsAnAnswerEndedByTheConnection(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Read(make([]byte, 512))
		// As the official server does: no newline, then close.
		_, _ = conn.Write([]byte("1.2.3.4:$PORT [::1]"))
		_ = conn.Close()
	}()

	got, err := LookupTSDNS(t.Context(), listener.Addr().String(), "voice.example.com")
	if err != nil {
		t.Fatalf("LookupTSDNS: %v", err)
	}
	if want := []string{"1.2.3.4:$PORT", "[::1]"}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
