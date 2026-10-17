package serverquery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"golang.org/x/crypto/ssh"
)

// Credentials that are missing are refused rather than sent: the server would
// answer each of them as a guest.
func TestNew_RefusesMissingCredentialsInsteadOfConnectingAsAGuest(t *testing.T) {
	check := SSHOptions{HostKeyCheck: InsecureIgnoreHostKey()}
	cases := map[string]Dialer{
		"ssh empty password": SSHWith("127.0.0.1:1", "serveradmin", "", check),
		"ssh empty user":     SSHWith("127.0.0.1:1", "", "pw", check),
		"ssh user guest":     SSHWith("127.0.0.1:1", "guest", "pw", check),
		"ssh user Guest":     SSHWith("127.0.0.1:1", "Guest", "", check),
		"web empty api key":  Web("http://127.0.0.1:1", ""),
	}
	for name, d := range cases {
		_, err := New(d)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: New = %v, want ErrInvalidConfig", name, err)

			continue
		}
		if !strings.Contains(err.Error(), "Guest") {
			t.Errorf("%s: the error does not point to the guest constructor: %v", name, err)
		}
	}
}

func TestNew_AcceptsGuestDialers(t *testing.T) {
	for name, d := range map[string]Dialer{
		"ssh": SSHGuestWith("127.0.0.1:1", SSHOptions{HostKeyCheck: InsecureIgnoreHostKey()}),
		"web": WebGuest("http://127.0.0.1:1"),
	} {
		_, err := New(d)
		if err != nil {
			t.Errorf("%s guest: New = %v", name, err)
		}
	}
}

// The guest dialer never dials unchecked: without a policy it is refused just
// as an account login is.
func TestSSHGuest_KeepsTheHostKeyPolicy(t *testing.T) {
	_, err := New(SSHGuest("127.0.0.1:1"))
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "HostKeyCheck") {
		t.Errorf("SSHGuest with no policy: New = %v, want ErrInvalidConfig naming HostKeyCheck", err)
	}
}

// startGuestSSHServer takes the user "guest" with no authentication, as TeamSpeak 6
// does, and records what the client offered.
func startGuestSSHServer(t *testing.T, onlyPassword bool) (*sshTestServer, *guestSeen) {
	t.Helper()
	seen := &guestSeen{}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	private, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			seen.record(meta.User(), "password:"+string(password))
			if meta.User() == "guest" {
				return &ssh.Permissions{}, nil
			}

			return nil, errBadPassword
		},
	}
	if !onlyPassword {
		config.NoClientAuth = true
		config.NoClientAuthCallback = func(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
			seen.record(meta.User(), "none")
			if meta.User() == "guest" {
				return &ssh.Permissions{}, nil
			}

			return nil, errBadPassword
		}
	}
	config.AddHostKey(private)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fresh := &sshTestServer{listener: listener, hostKey: private.PublicKey(), connGone: make(chan struct{})}
	fresh.wg.Add(1)
	go fresh.accept(config)
	t.Cleanup(fresh.stop)

	return fresh, seen
}

type guestSeen struct {
	users   []string
	methods []string
	mu      sync.Mutex
}

func (g *guestSeen) record(user, method string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.users = append(g.users, user)
	g.methods = append(g.methods, method)
}

func (g *guestSeen) get() ([]string, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	return append([]string(nil), g.users...), append([]string(nil), g.methods...)
}

func connectGuest(t *testing.T, server *sshTestServer) *Client {
	t.Helper()
	check := func(key HostKey) error {
		if key.Fingerprint != ssh.FingerprintSHA256(server.hostKey) {
			return errUnexpectedKey
		}

		return nil
	}
	c, err := New(SSHGuestWith(server.addr(), SSHOptions{HostKeyCheck: check}), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.WithoutCancel(ctx)) })

	return c
}

func TestSSHGuest_LogsInAsGuestWithNoPassword(t *testing.T) {
	server, seen := startGuestSSHServer(t, false)
	c := connectGuest(t, server)
	_, err := c.GetVersion(t.Context())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	users, methods := seen.get()
	if len(users) == 0 || users[0] != "guest" || methods[0] != "none" {
		t.Errorf("the server saw users %v by %v, want guest by none", users, methods)
	}
}

// A server that asks for a password first is given an empty one.
func TestSSHGuest_FallsBackToAnEmptyPassword(t *testing.T) {
	server, seen := startGuestSSHServer(t, true)
	connectGuest(t, server)
	_, methods := seen.get()
	if len(methods) == 0 || methods[len(methods)-1] != "password:" {
		t.Errorf("methods = %v, want an empty password", methods)
	}
}

// A server with guest access off refuses the login, reported as ErrAuth.
func TestSSHGuest_RefusedWhenGuestAccessIsOff(t *testing.T) {
	server := startSSHServer(t) // accepts only the test password
	check := func(HostKey) error { return nil }
	c, err := New(SSHGuestWith(server.addr(), SSHOptions{HostKeyCheck: check}), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if !errors.Is(err, ErrAuth) || !errors.Is(err, ErrNoGuestAccess) {
		t.Errorf("Connect = %v, want ErrAuth and ErrNoGuestAccess", err)
	}
	if !strings.Contains(err.Error(), "does not offer guest access") {
		t.Errorf("the error does not say there is no guest access: %v", err)
	}
}

// An account login that is refused is not a refused guest.
func TestSSH_WrongPasswordIsNotAMissingGuestAccess(t *testing.T) {
	server := startSSHServer(t)
	check := func(HostKey) error { return nil }
	c, err := New(SSHWith(server.addr(), "serveradmin", "wrong", SSHOptions{HostKeyCheck: check}), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if !errors.Is(err, ErrAuth) || errors.Is(err, ErrNoGuestAccess) {
		t.Errorf("Connect = %v, want ErrAuth and not ErrNoGuestAccess", err)
	}
}

// webRefusing answers every request with the given WebQuery status code.
func webRefusing(t *testing.T, code int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":{"code":` + strconv.Itoa(code) +
			`,"message":"missing apikey","extra_message":"api key missing"}}`))
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

// WebQuery answers a guest with 5124 where the server has no guest access.
func TestWebGuest_RefusedWhenGuestAccessIsOff(t *testing.T) {
	c, err := New(WebGuest(webRefusing(t, 5124)), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if !errors.Is(err, ErrNoGuestAccess) || !errors.Is(err, errcode.APIKeyMissing) {
		t.Errorf("Connect = %v, want ErrNoGuestAccess and errcode.APIKeyMissing", err)
	}
	if _, ok := errors.AsType[*teamspeak.ServerError](err); !ok {
		t.Errorf("Connect = %v, want the server's error in the chain", err)
	}
}

// 5124 for a connection that sent a key, and any other refusal of a guest, stay
// the server's own error.
func TestWeb_OtherRefusalsAreNotAMissingGuestAccess(t *testing.T) {
	for name, tc := range map[string]struct {
		dialer Dialer
		code   int
	}{
		"guest, wrong key code": {WebGuest(webRefusing(t, 5122)), 5122},
		"api key, 5124":         {Web(webRefusing(t, 5124), "key"), 5124},
	} {
		c, err := New(tc.dialer, WithServer(1))
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		err = c.Connect(t.Context())
		if err == nil || errors.Is(err, ErrNoGuestAccess) || !errors.Is(err, errcode.Code(tc.code)) {
			t.Errorf("%s: Connect = %v, want the server's %d alone", name, err, tc.code)
		}
	}
}

// webRecorder answers WebQuery requests and records whether a key came.
func webRecorder(t *testing.T) (string, func() []http.Header) {
	t.Helper()
	var mu sync.Mutex
	var headers []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Clone())
		mu.Unlock()
		_, _ = w.Write([]byte(`{"body":[{"version":"6.0.0-beta13.1"}],"status":{"code":0,"message":"ok"}}`))
	}))
	t.Cleanup(srv.Close)

	return srv.URL, func() []http.Header {
		mu.Lock()
		defer mu.Unlock()

		return append([]http.Header(nil), headers...)
	}
}

func TestWebGuest_SendsNoAPIKey(t *testing.T) {
	url, got := webRecorder(t)
	c, err := New(WebGuest(url), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Disconnect(t.Context()) }()
	_, err = c.GetVersion(t.Context())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	headers := got()
	if len(headers) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, h := range headers {
		if _, ok := h["X-Api-Key"]; ok {
			t.Errorf("a guest request carried an api key header: %v", h)
		}
	}
}

func TestWeb_SendsTheAPIKey(t *testing.T) {
	url, got := webRecorder(t)
	c, err := New(Web(url, "secret"), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Disconnect(t.Context()) }()
	_, _ = c.GetVersion(t.Context())
	for _, h := range got() {
		if h.Get("X-Api-Key") != "secret" {
			t.Errorf("the api key header = %q, want secret", h.Get("X-Api-Key"))
		}
	}
}
