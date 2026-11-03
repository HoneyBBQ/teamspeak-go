package discovery

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
)

var errNoRecord = errors.New("no such record")

// deadAddr is a local address nothing listens on.
func deadAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	return addr
}

// fakeNet stands in for DNS and the TSDNS servers: SRV answers by
// "service/domain", TSDNS servers by the address the resolver asks for. It
// records every SRV name and TSDNS server asked.
type fakeNet struct {
	dead     string
	srv      map[string][]*net.SRV
	servers  map[string]string
	srvAsked []string
	asked    []string
}

func (f *fakeNet) install(r *Resolver) {
	r.lookupSRV = func(_ context.Context, service, _, name string) (string, []*net.SRV, error) {
		key := service + "/" + name
		f.srvAsked = append(f.srvAsked, key)
		if s, ok := f.srv[key]; ok {
			return "", s, nil
		}

		return "", nil, errNoRecord
	}
	r.lookupTSDNS = func(ctx context.Context, server, host string) ([]string, error) {
		f.asked = append(f.asked, server)
		target, ok := f.servers[server]
		if !ok {
			target = f.dead
		}

		return LookupTSDNS(ctx, target, host)
	}
}

func addrsOf(rs []ResolvedAddr) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Addr
	}

	return out
}

func TestResolveSRVRecords(t *testing.T) {
	f := &fakeNet{srv: map[string][]*net.SRV{"ts3/example.com": {
		{Target: "b.example.net.", Port: 9988}, {Target: "a.example.net.", Port: 9987},
	}}}
	r := newTestResolver()
	f.install(r)

	got, err := r.Resolve(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"b.example.net:9988", "a.example.net:9987"}; !slices.Equal(addrsOf(got), want) {
		t.Fatalf("addrs = %v, want %v", addrsOf(got), want)
	}
	for _, a := range got {
		if a.Source != SourceSRV || a.Expiry.IsZero() {
			t.Fatalf("addr %+v: want source SRV with an expiry", a)
		}
	}
}

func TestResolveTSDNSViaSRVSkipsAFailingTarget(t *testing.T) {
	f := &fakeNet{dead: deadAddr(t)}
	good := tsdnsServer(t, "1.2.3.4:$PORT [::1]", false)
	f.srv = map[string][]*net.SRV{"tsdns/voice.example.com": {
		{Target: "down.example.net.", Port: 41144}, {Target: "up.example.net.", Port: 41144},
	}}
	f.servers = map[string]string{"up.example.net:41144": good}
	r := newTestResolver()
	f.install(r)

	got, err := r.Resolve(t.Context(), "voice.example.com:4321")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"1.2.3.4:4321", "[::1]:9987"}; !slices.Equal(addrsOf(got), want) {
		t.Fatalf("addrs = %v, want %v", addrsOf(got), want)
	}
	for _, a := range got {
		if a.Source != SourceTSDNSSRV {
			t.Fatalf("source = %q, want %q", a.Source, SourceTSDNSSRV)
		}
	}
	if want := []string{"down.example.net:41144", "up.example.net:41144"}; !slices.Equal(f.asked, want) {
		t.Fatalf("asked %v, want %v", f.asked, want)
	}
}

func TestResolveTSDNSDirectAsksTheMostSpecificDomainFirst(t *testing.T) {
	f := &fakeNet{dead: deadAddr(t)}
	f.servers = map[string]string{"example.com:41144": tsdnsServer(t, "203.0.113.9:7000", false)}
	r := newTestResolver()
	f.install(r)

	got, err := r.Resolve(t.Context(), "voice.example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].Addr != "203.0.113.9:7000" || got[0].Source != SourceTSDNSDirect {
		t.Fatalf("got %+v, want 203.0.113.9:7000 from TSDNS-Direct", got)
	}
	if want := []string{"voice.example.com:41144", "example.com:41144"}; !slices.Equal(f.asked, want) {
		t.Fatalf("asked %v, want %v", f.asked, want)
	}
}

func TestResolveFallsBackToDirect(t *testing.T) {
	f := &fakeNet{dead: deadAddr(t)}
	r := newTestResolver()
	f.install(r)

	got, err := r.Resolve(t.Context(), "voice.example.com:5555")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].Addr != "voice.example.com:5555" || got[0].Source != SourceDirect {
		t.Fatalf("got %+v, want voice.example.com:5555 from Direct", got)
	}
}

func TestResolveServesTheSecondCallFromTheCache(t *testing.T) {
	f := &fakeNet{srv: map[string][]*net.SRV{"ts3/example.com": {{Target: "a.example.net.", Port: 9987}}}}
	r := newTestResolver()
	f.install(r)

	first, err := r.Resolve(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	asked := len(f.srvAsked)
	second, err := r.Resolve(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("Resolve again: %v", err)
	}
	if len(f.srvAsked) != asked || len(f.asked) != 0 {
		t.Fatalf("second Resolve asked again: srv %v, tsdns %v", f.srvAsked, f.asked)
	}
	if !slices.Equal(addrsOf(first), addrsOf(second)) {
		t.Fatalf("cached %v differs from first %v", addrsOf(second), addrsOf(first))
	}
}
