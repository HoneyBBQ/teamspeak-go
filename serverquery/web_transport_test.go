package serverquery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A redirect is never followed: the api key is a header, and a client that
// follows one forwards it to the host it names.
func TestWeb_DoesNotFollowARedirect(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" {
			leaked.Add(1)
		}
		_, _ = w.Write([]byte(`{"body":[],"status":{"code":0,"message":"ok"}}`))
	}))
	t.Cleanup(other.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	// A caller's own client is no exception, and is not modified.
	own := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	for name, d := range map[string]Dialer{
		"default":      Web(redirecting.URL, "secret"),
		"own client":   WebWith(redirecting.URL, "secret", WebOptions{Client: own}),
		"guest dialer": WebGuest(redirecting.URL),
	} {
		c, err := New(d, WithServer(1))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Connect(t.Context())

		httpErr, ok := errors.AsType[*WebQueryHTTPError](err)
		if !ok || httpErr.Status != http.StatusTemporaryRedirect {
			t.Errorf("%s: Connect = %v, want a *WebQueryHTTPError of 307", name, err)
		}
	}
	if leaked.Load() != 0 {
		t.Errorf("the api key reached the redirect target %d times", leaked.Load())
	}
	if own.CheckRedirect == nil {
		t.Error("the caller's client was modified")
	}
}

// The name of a transport and its stats carry no credentials from the URL.
func TestWeb_NamesCarryNoUserinfo(t *testing.T) {
	d := Web("http://user:pass@127.0.0.1:10080/", "key")
	if got := d.String(); strings.Contains(got, "user") || strings.Contains(got, "pass") {
		t.Errorf("String() = %q, want no userinfo", got)
	}
	if got := d.String(); got != "web http://127.0.0.1:10080" {
		t.Errorf("String() = %q", got)
	}
	web, ok := d.(webDialer)
	if !ok {
		t.Fatalf("Web returned %T", d)
	}
	tr, err := web.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	query, ok := tr.(*webQuery)
	if !ok {
		t.Fatalf("open returned %T", tr)
	}
	if addr := query.stats().Address; addr != "http://127.0.0.1:10080" {
		t.Errorf("stats address = %q, want the URL without userinfo", addr)
	}
}

// A command that gave up waiting is not answered later with another's answer:
// the next command gets its own.
func TestWeb_LateAnswerIsNotTheNextCommands(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hostinfo") {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			_, _ = w.Write([]byte(`{"body":[{"client_id":"1"}],"status":{"code":0,"message":"ok"}}`))

			return
		}
		_, _ = w.Write([]byte(`{"body":[{"version":"3.13.8","build":"1","platform":"Linux"}],` +
			`"status":{"code":0,"message":"ok"}}`))
	}))
	t.Cleanup(srv.Close)
	c := webClient(t, srv.URL)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Exec(ctx, "hostinfo")
	if err == nil {
		t.Fatal("hostinfo answered before it was released")
	}
	close(release)
	time.Sleep(50 * time.Millisecond)

	v, err := c.GetVersion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != "3.13.8" {
		t.Errorf("version = %q: the next command got another's answer", v.Version)
	}
}
