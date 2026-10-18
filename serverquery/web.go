package serverquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// WebOptions are the seam [WebWith] leaves open. The zero value is what [Web]
// does.
//
// Experimental: this package may change in a minor release.
type WebOptions struct {
	// Client makes the requests. Without it a plain http.Client is used, which
	// has no timeout: set one, or supply a client that has, for a server that
	// can hang.
	//
	// It is also where a proxy, a custom transport or an instrumented
	// RoundTripper goes. The client is not modified, so one may be shared.
	Client *http.Client
}

// webDialer is WebQuery, the HTTP interface of TeamSpeak 3 (3.12 and later) and
// TeamSpeak 6: each command is one request and the api key is the login.
//
// It has no session. The server cannot push anything to a client that is not
// holding a connection open, so there are no notifications, and the transport
// answers `use` itself by changing the server subsequent requests address.
type webDialer struct {
	client  *http.Client
	baseURL string
	apiKey  string
	// guest reports a connection that sends no api key.
	guest bool
}

// Web returns a Dialer for WebQuery at baseURL, such as
// "http://127.0.0.1:10080", authenticating with apiKey.
//
// TeamSpeak 3 (3.12 and later, with `http` in its query_protocols) and
// TeamSpeak 6 serve it. The api key replaces the query login, so there is
// none to give; the server refuses `login` and `use` as
// commands, and this transport answers `use` by addressing the server the
// following requests name.
//
// An https:// baseURL works as it is, for a server that serves WebQuery over
// HTTPS (port 10443 by default): the certificate is verified against the system
// trust store. For a private CA or a self-signed certificate, supply a client
// whose transport trusts it through [WebWith] and [WebOptions.Client].
//
// An empty apiKey is refused by [New] with [ErrInvalidConfig]: the server
// treats a request without a key as a guest's, so sending one by accident, from
// an unset variable, would be a silent downgrade. [WebGuest] is the explicit
// way to connect as a guest.
//
// WebQuery keeps no session to push notifications to, so [Dialer.SupportsNotifications]
// is false and the On… methods for server events do nothing here. The server
// also refuses every file transfer command over it.
func Web(baseURL, apiKey string) Dialer {
	return WebWith(baseURL, apiKey, WebOptions{})
}

// WebWith returns a WebQuery dialer with options applied; it is [Web] when
// options is the zero value. Use it to supply the *http.Client the requests go
// through, which is where timeouts, a proxy and instrumentation are set.
//
// Experimental: this package may change in a minor release.
func WebWith(baseURL, apiKey string, options WebOptions) Dialer {
	return newWebDialer(baseURL, apiKey, options)
}

func newWebDialer(baseURL, apiKey string, options WebOptions) webDialer {
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}

	return webDialer{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, client: client}
}

// WebGuest returns a Dialer for TeamSpeak 6's WebQuery at baseURL that sends no
// api key, so the server runs every request in its guest scope: the access of
// the Guest ServerQuery group, limited to the commands the guest scope allows.
// Anything outside it answers HTTP 401, code 5120 ([errcode.APIKeyOutOfScope]),
// and a permission the group lacks answers 2568, both as a
// [*teamspeak.ServerError].
//
// TeamSpeak 3 has no guest access, and neither does a TeamSpeak 6 started with
// it off: the server answers 5124 ([errcode.APIKeyMissing]) and Connect returns
// an error wrapping [ErrNoGuestAccess] and that refusal.
//
// TeamSpeak 6 beta13 and later serve it, and it is on unless the server was
// started with --query-http-allow-guest=0 (or TSSERVER_QUERY_HTTP_ALLOW_GUEST=0).
// Guest access is an explicit choice made by calling this: [Web] refuses an
// empty api key with [ErrInvalidConfig]. A wrong key is not a guest either; the
// server answers 5122 ([errcode.APIKeyInvalid]).
//
// Experimental: this package may change in a minor release.
func WebGuest(baseURL string) Dialer {
	return WebGuestWith(baseURL, WebOptions{})
}

// WebGuestWith returns a guest WebQuery dialer with options applied; see
// [WebGuest] and [WebWith].
//
// Experimental: this package may change in a minor release.
func WebGuestWith(baseURL string, options WebOptions) Dialer {
	d := newWebDialer(baseURL, "", options)
	d.guest = true

	return d
}

// SupportsNotifications reports that the server cannot push notifications over
// WebQuery.
func (d webDialer) SupportsNotifications() bool { return false }

// String names the transport by its base URL, never the api key.
func (d webDialer) String() string { return "web " + d.baseURL }

// credentials reports that there is no login command here: the api key
// is the login.
func (d webDialer) credentials() *login { return nil }

// needsQuit reports that there is no session to end: WebQuery has none, and
// refuses `quit` with an out-of-scope error.
func (d webDialer) needsQuit() bool { return false }

// validate refuses a missing api key, which the server would take as a guest's
// request. An http.Client uses the system's own trust store for a https://
// base URL, and nothing else here could be missing the way an SSH host key
// policy can.
func (d webDialer) validate() error {
	if !d.guest && d.apiKey == "" {
		return fmt.Errorf("%w: the web dialer has no api key, which the server would answer as a guest; "+
			"use WebGuest to connect as a guest", ErrInvalidConfig)
	}

	return nil
}

func (d webDialer) open(_ context.Context) (engine.Transport, error) {
	base, err := url.Parse(d.baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("%w: %q is not a base URL", ErrDial, d.baseURL)
	}

	return &webQuery{
		client: d.client,
		base:   base,
		apiKey: d.apiKey,
		guest:  d.guest,
		lines:  make(chan string, 64),
		done:   make(chan struct{}),
		opened: time.Now(),
	}, nil
}

// webQuery is one WebQuery connection. It is not a session on the server: it
// is the state of the addressing, which `use` changes.
type webQuery struct {
	opened        time.Time
	client        *http.Client
	base          *url.URL
	lines         chan string
	done          chan struct{}
	apiKey        string
	prefix        string
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	closeOnce     sync.Once
	mu            sync.Mutex
	guest         bool
}

// WriteLine sends one command line, which is one request, and hands the answer
// on as the lines a raw connection would have sent: one per row, then the
// error line that ends it.
func (w *webQuery) WriteLine(ctx context.Context, line string) error {
	// A command with rows, name=a|name=b, goes as a JSON array with an object
	// per row. The first row carries the parameters the rows share, as it does
	// on the line, and the later rows only their own: measured on TeamSpeak 3
	// and 6, which both read the array as the line.
	segments := strings.Split(line, "|")
	cmd := wire.ParseCommand(segments[0])
	if cmd == nil {
		return fmt.Errorf("%w: empty command line", errEmptyCommand)
	}
	var rows []map[string]string
	for _, segment := range segments[1:] {
		row := wire.ParseCommand(segment)
		if row == nil {
			return fmt.Errorf("%w: an empty row in %s", errEmptyCommand, cmd.Name)
		}
		rows = append(rows, row.Params)
	}

	// WebQuery has no `use`: the server refuses it, and the server a request
	// addresses is part of its path instead.
	if cmd.Name == "use" {
		return w.use(cmd.Params)
	}

	w.mu.Lock()
	path := w.prefix + "/" + cmd.Name
	w.mu.Unlock()

	answer, err := w.request(ctx, path, paramsBody(cmd.Params, rows))
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(answer.Body)+1)
	for _, row := range answer.Body {
		lines = append(lines, rowLine(row))
	}
	lines = append(lines, answer.errorLine())
	w.push(lines...)

	return nil
}

// ReadLine returns the next line of the answer to the last command.
func (w *webQuery) ReadLine() (string, error) {
	select {
	case line := <-w.lines:
		return line, nil
	case <-w.done:
		return "", io.EOF
	}
}

// Close ends the connection. There is nothing to close on the server, which
// holds no session for this client.
func (w *webQuery) Close() error {
	w.closeOnce.Do(func() { close(w.done) })

	return nil
}

// stats reports the connection's identity and counters.
func (w *webQuery) stats() TransportStats {
	return TransportStats{
		Transport:     "web",
		Address:       w.base.String(),
		ConnectedAt:   w.opened,
		BytesSent:     w.bytesSent.Load(),
		BytesReceived: w.bytesReceived.Load(),
	}
}

// use changes the server following commands address. The server answers a
// WebQuery `use` with an error, so the transport answers it here.
func (w *webQuery) use(params map[string]string) error {
	sid, hasSID := params["sid"]
	port, hasPort := params["port"]

	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case hasSID && isDecimal(sid):
		w.prefix = "/" + sid
	case hasPort && isDecimal(port):
		w.prefix = "/byport/" + port
	default:
		return fmt.Errorf("%w: use takes a sid or a port", errInvalidUse)
	}
	w.push("error id=0 msg=ok")

	return nil
}

// request makes one WebQuery call and returns the answer.
func (w *webQuery) request(ctx context.Context, path string, body []byte) (*webAnswer, error) {
	target := *w.base
	target.Path = strings.TrimRight(w.base.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDial, path, err)
	}
	if !w.guest {
		req.Header.Set("X-Api-Key", w.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	w.bytesSent.Add(uint64(len(body)))
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDial, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDial, path, err)
	}
	w.bytesReceived.Add(uint64(len(raw)))

	var answer webAnswer
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// A number keeps the digits the server sent rather than becoming a float:
	// an id is read back as text, and 1e+06 is not one.
	decoder.UseNumber()
	decodeErr := decoder.Decode(&answer)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, httpFailure(path, resp.StatusCode, &answer, decodeErr)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: %s answered HTTP %d, not WebQuery JSON: %w", ErrDial, path, resp.StatusCode, decodeErr)
	}
	// The status code inside the body is what decides, so a missing one means
	// this is not a WebQuery answer at all.
	if answer.Status.Code == nil {
		return nil, fmt.Errorf("%w: %s answered HTTP %d with no command status", ErrDial, path, resp.StatusCode)
	}

	return &answer, nil
}

// httpFailure is the error for an answer whose HTTP status is not 2xx. WebQuery
// answers a refusal with 400 or 401 and a body that says why, and the body's
// status is kept as the server's own error, so a caller matching its code still
// does. An answer that is not WebQuery's, such as a proxy's 502, is also an
// [ErrDial].
func httpFailure(path string, status int, answer *webAnswer, decodeErr error) error {
	failure := &WebQueryHTTPError{Status: status}
	if decodeErr == nil && answer.Status.Code != nil {
		code, err := answer.Status.Code.Int64()
		if err == nil && code >= 0 && code <= math.MaxUint32 {
			failure.Code = errcode.Code(code)
			failure.Message = answer.Status.Message
			failure.ExtraMessage = answer.Status.ExtraMessage
			failure.hasCode = true
		}
	}
	if failure.hasCode {
		return fmt.Errorf("%s: %w", path, failure)
	}

	return fmt.Errorf("%w: %s: %w", ErrDial, path, failure)
}

// WebQueryHTTPError is a WebQuery request the server answered with an HTTP
// status outside 2xx. Match it with errors.As.
//
// WebQuery answers most refusals with 200 and the code in the body, which is a
// [*teamspeak.ServerError] as on every transport. It answers some with an HTTP
// error as well: 401 for a wrong, missing or out-of-scope api key, and 400 for
// a body it cannot read. When the body carries the server's status, the error
// holds it as Code, Message and ExtraMessage, and wraps the same
// [*teamspeak.ServerError], so errors.Is on an [errcode.Code] and errors.As to
// a [*teamspeak.ServerError] match as they do for a 200. An answer with no
// WebQuery body, such as a proxy's 502 or 404, has only Status, and the error
// also wraps [ErrDial].
//
// Experimental: this package may change in a minor release.
type WebQueryHTTPError struct {
	// Message is the status message of the body, "" when it carried none.
	Message string
	// ExtraMessage is the body's extra_message, "" when it carried none.
	ExtraMessage string
	// Status is the HTTP status code of the answer.
	Status int
	// Code is the server's error code from the body. It is meaningful only when
	// HasCode reports true.
	Code    errcode.Code
	hasCode bool
}

// HasCode reports whether the answer carried a WebQuery status, which Code,
// Message and ExtraMessage then hold.
func (e *WebQueryHTTPError) HasCode() bool { return e.hasCode }

// Error describes the status and, when there is one, the server's refusal.
func (e *WebQueryHTTPError) Error() string {
	text := fmt.Sprintf("WebQuery answered HTTP %d", e.Status)
	if e.hasCode {
		text += ": " + e.serverError().Error()
	}

	return text
}

// Unwrap returns the server's error when the body carried one.
func (e *WebQueryHTTPError) Unwrap() error {
	if !e.hasCode {
		return nil
	}

	return e.serverError()
}

func (e *WebQueryHTTPError) serverError() *teamspeak.ServerError {
	return &teamspeak.ServerError{Code: e.Code, Message: e.Message, ExtraMessage: e.ExtraMessage}
}

// push hands an answer's rows and its error line to the reader, in that order.
// It gives up once the connection is closed rather than blocking on a reader
// that has gone.
func (w *webQuery) push(lines ...string) {
	for _, line := range lines {
		select {
		case w.lines <- line:
		case <-w.done:
			return
		}
	}
}

// webAnswer is WebQuery's reply: the rows the command produced, and the status
// of the command itself, which is the error line a raw connection ends with.
//
// The body's values are read as they are rather than as text: WebQuery sends
// most as strings, but a few fields are JSON numbers, and reading them as text
// where it sends a number would fail the whole decode.
type webAnswer struct {
	Status struct {
		Code         *json.Number `json:"code"`
		Message      string       `json:"message"`
		ExtraMessage string       `json:"extra_message"`
	} `json:"status"`
	Body []map[string]any `json:"body"`
}

// errorLine is the status as the error command a raw connection ends an answer
// with. The values are escaped, since the engine reads the line back the same
// way it reads the server's own.
func (a *webAnswer) errorLine() string {
	params := [][2]string{{"id", a.Status.Code.String()}}
	if a.Status.Message != "" {
		params = append(params, [2]string{"msg", a.Status.Message})
	}
	if a.Status.ExtraMessage != "" {
		params = append(params, [2]string{"extra_msg", a.Status.ExtraMessage})
	}

	return wire.BuildCommandOrdered("error", params)
}

// rowLine renders one answer row as the nameless response line a raw
// connection would have sent for it. The name is empty, and BuildCommandOrdered
// writes a space before each parameter, so the leading one is dropped.
func rowLine(row map[string]any) string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	params := make([][2]string, 0, len(keys))
	for _, key := range keys {
		params = append(params, [2]string{key, valueText(row[key])})
	}

	return strings.TrimPrefix(wire.BuildCommandOrdered("", params), " ")
}

// valueText renders one JSON value as the text a command line carries: a
// number with the digits it arrived as, a string as it is, and anything else
// (a nested object, a null) as empty, which is a field the row did not carry.
func valueText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "1"
		}

		return "0"
	default:
		return ""
	}
}

// paramsBody renders a command's parameters as the JSON WebQuery takes them
// in: an object, or an array of objects when the command has rows after the
// first, which is the row of the parameters. A parameter with no value is sent
// as an empty string, which is how WebQuery spells a bare flag such as -groups.
func paramsBody(params map[string]string, rows []map[string]string) []byte {
	var doc any = nonNil(params)
	if len(rows) > 0 {
		all := make([]map[string]string, 0, len(rows)+1)
		all = append(all, nonNil(params))
		for _, row := range rows {
			all = append(all, nonNil(row))
		}
		doc = all
	}
	body, err := json.Marshal(doc)
	if err != nil {
		// Maps of strings cannot fail to marshal.
		return []byte("{}")
	}

	return body
}

func nonNil(params map[string]string) map[string]string {
	if params == nil {
		return map[string]string{}
	}

	return maps.Clone(params)
}

// isDecimal reports whether s is a run of digits, which is what a server id or
// a port is.
func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
