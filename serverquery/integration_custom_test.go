//go:build integration

package serverquery_test

// Integration tests for a transport the caller supplies, and for the HTTP
// error WebQuery's refusals carry. The transports here are written the way a
// caller would: a TCP connection that logs itself in, and a small WebQuery of
// the test's own over net/http.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

var (
	errLoginRefused = errors.New("login refused")
	errEmptyLine    = errors.New("empty command")
)

// lineConn is a TCP connection as a serverquery.Transport.
type lineConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (l *lineConn) WriteLine(ctx context.Context, line string) error {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = l.conn.SetWriteDeadline(deadline)
	}
	_, err := io.WriteString(l.conn, line+"\n")

	return err
}

func (l *lineConn) ReadLine() (string, error) {
	line, err := l.r.ReadString('\n')

	return strings.TrimSpace(line), err
}

func (l *lineConn) Close() error { return l.conn.Close() }

// dialLogged opens the raw protocol, takes the greeting, and logs in, so the
// transport it returns is ready for commands.
func dialLogged(ctx context.Context, addr, login, password string) (serverquery.Transport, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &lineConn{conn: conn, r: bufio.NewReader(conn)}
	// The greeting is two lines, the second ending in a prompt.
	for range 2 {
		_, err = l.ReadLine()
		if err != nil {
			_ = conn.Close()

			return nil, err
		}
	}
	err = l.WriteLine(ctx, fmt.Sprintf("login %s %s", wire.Escape(login), wire.Escape(password)))
	if err != nil {
		_ = conn.Close()

		return nil, err
	}
	for {
		line, readErr := l.ReadLine()
		if readErr != nil {
			_ = conn.Close()

			return nil, readErr
		}
		if strings.HasPrefix(line, "error ") {
			if !strings.Contains(line, "id=0") {
				_ = conn.Close()

				return nil, fmt.Errorf("%w: %s", errLoginRefused, line)
			}

			return l, nil
		}
	}
}

// A TeamSpeak 3 server's raw protocol, carried by the test's own transport.
func TestQueryCustom_OverACallersTCP(t *testing.T) {
	addr, login, password := tcpVars(t)
	waitForOtherSuites()

	opened := 0
	c, err := serverquery.New(serverquery.Custom(func(ctx context.Context) (serverquery.Transport, error) {
		opened++

		return dialLogged(ctx, addr, login, password)
	}), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)
	assertCustomCommands(t, c, teamspeak.ServerFamilyTS3)
	if opened != 1 {
		t.Errorf("the open function ran %d times, want 1", opened)
	}
}

// webLines is a WebQuery connection as a serverquery.Transport: each command
// line is one request, and the answer is handed back as the lines a raw
// connection would send.
type webLines struct {
	client *http.Client
	lines  chan string
	done   chan struct{}
	base   string
	key    string
	prefix string
	once   sync.Once
}

func (w *webLines) WriteLine(ctx context.Context, line string) error {
	cmd := wire.ParseCommand(line)
	if cmd == nil {
		return errEmptyLine
	}
	// WebQuery has no `use`: the server a request addresses is in its path.
	if cmd.Name == "use" {
		w.prefix = "/" + cmd.Params["sid"]
		w.lines <- "error id=0 msg=ok"

		return nil
	}
	body, err := json.Marshal(cmd.Params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+w.prefix+"/"+cmd.Name, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", w.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return w.deliver(resp.Body)
}

func (w *webLines) ReadLine() (string, error) {
	select {
	case line := <-w.lines:
		return line, nil
	case <-w.done:
		return "", io.EOF
	}
}

func (w *webLines) Close() error {
	w.once.Do(func() { close(w.done) })

	return nil
}

// deliver reads WebQuery's JSON answer and queues it as the lines a raw
// connection would send: a line per row, then the error line.
func (w *webLines) deliver(body io.Reader) error {
	var answer struct {
		Body   []map[string]any `json:"body"`
		Status struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"status"`
	}
	err := json.NewDecoder(body).Decode(&answer)
	if err != nil {
		return err
	}
	for _, row := range answer.Body {
		params := make([][2]string, 0, len(row))
		for k, v := range row {
			params = append(params, [2]string{k, fmt.Sprint(v)})
		}
		w.lines <- strings.TrimPrefix(wire.BuildCommandOrdered("", params), " ")
	}
	w.lines <- wire.BuildCommandOrdered("error", [][2]string{
		{"id", strconv.Itoa(answer.Status.Code)}, {"msg", answer.Status.Message},
	})

	return nil
}

// WebQuery, on both generations, carried by a transport of the test's own. TS6
// has no raw protocol, so this is the one custom transport both servers serve.
func TestQueryCustom_OverACallersWebQuery(t *testing.T) {
	base, apiKey := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.Custom(func(context.Context) (serverquery.Transport, error) {
		return &webLines{
			client: &http.Client{Timeout: 20 * time.Second},
			base:   base, key: apiKey,
			lines: make(chan string, 256), done: make(chan struct{}),
		}, nil
	}), serverquery.WithServer(1), serverquery.WithoutEvents())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)
	assertCustomCommands(t, c, c.ServerFamily())
}

// assertCustomCommands runs commands every transport serves.
func assertCustomCommands(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily) {
	t.Helper()
	ctx := adminCtx(t)
	version, err := c.GetVersion(ctx)
	if err != nil || version.Version == "" {
		t.Fatalf("GetVersion = %+v, %v", version, err)
	}
	if got := c.ServerFamily(); got != family {
		t.Errorf("ServerFamily = %v, want %v", got, family)
	}
	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil || len(channels) == 0 {
		t.Errorf("ListChannels = %d channels, %v, want the fixture's", len(channels), err)
	}
	if stats := c.Stats(); stats.Transport != "" {
		t.Errorf("Stats = %+v, want the zero value for a custom transport", stats)
	}
}

// A wrong api key is answered with an HTTP error as well as the server's own:
// both are matched.
func TestQueryWeb_HTTPErrorOfAWrongKey(t *testing.T) {
	base, _ := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.Web(base, "not-a-key"), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(adminCtx(t))
	if err == nil {
		_ = c.Disconnect(context.Background())
		t.Fatal("a wrong api key connected")
	}
	httpErr, ok := errors.AsType[*serverquery.WebQueryHTTPError](err)
	if !ok {
		t.Fatalf("Connect = %v, want a *WebQueryHTTPError", err)
	}
	t.Logf("a wrong key: HTTP %d, code %d (%q)", httpErr.Status, httpErr.Code, httpErr.Message)
	if httpErr.Status != http.StatusUnauthorized || !httpErr.HasCode() || httpErr.Code != errcode.APIKeyInvalid {
		t.Errorf("error = %+v, want HTTP 401 and code 5122", httpErr)
	}
	if !errors.Is(err, errcode.APIKeyInvalid) {
		t.Errorf("Connect = %v, want the code still matched", err)
	}
}

// A guest asking outside its scope is an HTTP 401 with code 5120, on a server
// that has guest access.
func TestQueryWeb_HTTPErrorOutsideTheGuestScope(t *testing.T) {
	guestEnabled(t)
	base, _ := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.WebGuest(base), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := guestCtx(t)
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect as a guest: %v", err)
	}
	defer func() { _ = c.Disconnect(context.Background()) }()

	_, err = c.GetServerInfo(ctx)
	httpErr, ok := errors.AsType[*serverquery.WebQueryHTTPError](err)
	if !ok {
		t.Fatalf("serverinfo as a guest = %v, want a *WebQueryHTTPError", err)
	}
	t.Logf("outside the guest scope: HTTP %d, code %d", httpErr.Status, httpErr.Code)
	if httpErr.Status != http.StatusUnauthorized || httpErr.Code != errcode.APIKeyOutOfScope {
		t.Errorf("error = %+v, want HTTP 401 and code 5120", httpErr)
	}
	if got := serverCode(err); got != codeOutOfScope {
		t.Errorf("serverCode = %d, want %d still found", got, codeOutOfScope)
	}
}

// Where there is no guest access the refusal is an HTTP error too.
func TestQueryWeb_HTTPErrorOfARefusedGuest(t *testing.T) {
	noGuestAccess(t)
	base, _ := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.WebGuest(base), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(guestCtx(t))
	httpErr, ok := errors.AsType[*serverquery.WebQueryHTTPError](err)
	if !ok || !errors.Is(err, serverquery.ErrNoGuestAccess) {
		t.Fatalf("Connect as a guest = %v, want ErrNoGuestAccess and a *WebQueryHTTPError", err)
	}
	t.Logf("a refused guest: HTTP %d, code %d", httpErr.Status, httpErr.Code)
	if httpErr.Code != errcode.APIKeyMissing {
		t.Errorf("error = %+v, want code 5124", httpErr)
	}
}
