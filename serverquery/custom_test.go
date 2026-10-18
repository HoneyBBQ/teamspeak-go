package serverquery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

var errNoRoute = errors.New("no route to the tunnel")

// A caller's transport carries the session: Connect runs the handshake over it,
// a typed command goes out and comes back, and Disconnect says quit and closes.
//
//nolint:funlen // one session, step by step
func TestCustom_CarriesASession(t *testing.T) {
	d := &fakeDialer{opened: make(chan *fakeTransport, 8)}
	opened := 0
	c := newClient(t, Custom(func(ctx context.Context) (Transport, error) {
		opened++

		return d.open(ctx)
	}), WithServer(1))

	done := make(chan error, 1)
	go func() { done <- c.Connect(context.Background()) }()
	transport := d.answer(t)
	err := <-done
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if opened != 1 {
		t.Errorf("the open function ran %d times, want 1", opened)
	}
	names := commandNames(transport.sentLines())
	if names[0] != "use" || containsSubstring(names, "login") {
		t.Errorf("handshake = %v, want use first and no login: the transport is already logged in", names)
	}

	go func() {
		line, _ := d.nextWithin(t)
		if strings.HasPrefix(line, "version") {
			transport.reply("version=3.13.8 build=1 platform=Linux", "error id=0 msg=ok")
		}
		line, _ = d.nextWithin(t)
		if strings.HasPrefix(line, "quit") {
			transport.reply("error id=0 msg=ok")
		}
	}()
	v, err := c.GetVersion(context.Background())
	if err != nil || v.Version != "3.13.8" {
		t.Errorf("GetVersion = %+v, %v", v, err)
	}
	err = c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !containsSubstring(transport.sentLines(), "quit") {
		t.Errorf("quit was not sent: %v", transport.sentLines())
	}
	select {
	case <-transport.closed:
	default:
		t.Error("Disconnect left the transport open")
	}
}

func TestCustom_DescribesItselfAndRefusesNoOpen(t *testing.T) {
	d := Custom(func(context.Context) (Transport, error) { return nil, errNoRoute })
	if !d.SupportsNotifications() || d.String() != "custom transport" {
		t.Errorf("dialer = %v, notifications %v", d, d.SupportsNotifications())
	}

	_, err := New(Custom(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(Custom(nil)) = %v, want ErrInvalidConfig", err)
	}
}

func TestCustom_OpenFailuresAreDialErrors(t *testing.T) {
	c := newClient(t, Custom(func(context.Context) (Transport, error) { return nil, errNoRoute }), WithoutEvents())
	err := c.Connect(context.Background())
	if !errors.Is(err, ErrDial) || !errors.Is(err, errNoRoute) {
		t.Errorf("Connect = %v, want ErrDial wrapping the open's error", err)
	}

	noTransport := func(context.Context) (Transport, error) {
		return nil, nil //nolint:nilnil // the case under test
	}
	c = newClient(t, Custom(noTransport), WithoutEvents())
	err = c.Connect(context.Background())
	if !errors.Is(err, ErrDial) {
		t.Errorf("Connect with no transport = %v, want ErrDial", err)
	}
}

// webStatus answers every request with the given HTTP status and body.
func webStatus(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

// A refusal WebQuery sends with an HTTP error keeps the server's own error in
// the chain, as it did before, and is now also a *WebQueryHTTPError.
func TestWeb_HTTPErrorWithAWebQueryBody(t *testing.T) {
	url := webStatus(t, http.StatusUnauthorized,
		`{"status":{"code":5122,"message":"invalid apikey","extra_message":"api key invalid"}}`)
	c, err := New(Web(url, "wrong"), WithServer(1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(t.Context())

	httpErr, ok := errors.AsType[*WebQueryHTTPError](err)
	if !ok {
		t.Fatalf("Connect = %v, want a *WebQueryHTTPError", err)
	}
	if httpErr.Status != 401 || !httpErr.HasCode() || httpErr.Code != errcode.APIKeyInvalid ||
		httpErr.Message != "invalid apikey" || httpErr.ExtraMessage != "api key invalid" {
		t.Errorf("error = %+v, want the status and the body's code and messages", httpErr)
	}
	if !errors.Is(err, errcode.APIKeyInvalid) {
		t.Errorf("Connect = %v, want the code still matched", err)
	}
	serverErr, found := errors.AsType[*teamspeak.ServerError](err)
	if !found || serverErr.Code != errcode.APIKeyInvalid {
		t.Errorf("Connect = %v, want the *ServerError in the chain", err)
	}
	if errors.Is(err, ErrDial) {
		t.Errorf("Connect = %v, a refusal the server explained is not a dial failure", err)
	}
}

// An answer that is not WebQuery's keeps its status and is still a dial error.
func TestWeb_HTTPErrorWithoutAWebQueryBody(t *testing.T) {
	bodies := map[string]string{"html": "<html>bad gateway</html>", "empty": "", "json without a status": "{}"}
	for name, body := range bodies {
		url := webStatus(t, http.StatusBadGateway, body)
		c, err := New(Web(url, "key"), WithServer(1))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Connect(t.Context())

		httpErr, ok := errors.AsType[*WebQueryHTTPError](err)
		if !ok || httpErr.Status != 502 || httpErr.HasCode() {
			t.Errorf("%s: Connect = %v, want a *WebQueryHTTPError of 502 with no code", name, err)
		}
		if !errors.Is(err, ErrDial) {
			t.Errorf("%s: Connect = %v, want ErrDial kept", name, err)
		}
		if _, found := errors.AsType[*teamspeak.ServerError](err); found {
			t.Errorf("%s: Connect = %v, want no server error", name, err)
		}
	}
}

// 200 with a refusal in the body is not an HTTP error: it is the server's error
// alone, as it always was.
func TestWeb_RefusalWithHTTP200IsNotAnHTTPError(t *testing.T) {
	url := webStatus(t, http.StatusOK, `{"status":{"code":512,"message":"invalid clientID"}}`)
	c, err := New(Web(url, "key"), WithServer(1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(t.Context())
	if _, ok := errors.AsType[*WebQueryHTTPError](err); ok {
		t.Errorf("Connect = %v, want no HTTP error for a 200", err)
	}
	if !errors.Is(err, errcode.ClientInvalidID) {
		t.Errorf("Connect = %v, want the server's code", err)
	}
}
