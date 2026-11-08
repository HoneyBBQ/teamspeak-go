package teamspeak

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/request"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// Request is a command as the typed commands describe it, before a transport
// encodes it.
//
// The typed commands run on any connection that can execute a command — the
// voice client today, ServerQuery later — and the two disagree about how some
// values go on the wire. A channel password is the case that matters: the
// voice protocol expects base64(sha1(password)), while ServerQuery takes the
// password itself and hashes it server-side. So a request records which
// parameters are passwords and leaves their encoding to the transport.
type Request struct {
	command   string
	params    []param
	passwords []string
}

// Command returns the command's name.
func (r Request) Command() string {
	return r.command
}

// String returns the command's name only: parameters carry passwords,
// privilege keys and message bodies, so a request printed with %v, %+v or
// %#v, or logged, shows none of them.
func (r Request) String() string {
	return r.command
}

// GoString is String, so %#v redacts too.
func (r Request) GoString() string {
	return r.command
}

// LogValue logs the command's name only, as String does.
func (r Request) LogValue() slog.Value {
	return slog.StringValue(r.command)
}

// init hands the SDK's transports the two things about a Request they need and
// callers must not: building one from parts, and encoding it. An init, because
// the hooks must be in place before any importer of this package runs.
func init() { //nolint:gochecknoinits // see above
	request.New = func(command string, params [][2]string) any {
		req := Request{command: command, params: make([]param, len(params))}
		for i, p := range params {
			req.params[i] = strArg(p[0], p[1])
		}

		return req
	}
	request.NewList = func(command, key string, values []string) any {
		return Request{command: command, params: []param{rowsArg(key, values)}}
	}
	request.NewRowed = func(command string, params [][2]string, passwords []string, rest [][][2]string) any {
		req := Request{command: command, params: make([]param, len(params), len(params)+1), passwords: passwords}
		for i, p := range params {
			req.params[i] = strArg(p[0], p[1])
		}
		if len(rest) > 0 {
			// The empty row stands for the plain parameters, which encode writes
			// as the first row.
			req.params = append(req.params, param{table: append([][][2]string{nil}, rest...)})
		}

		return req
	}
	request.Encode = func(req any, encodePassword func(password string) string) string {
		return req.(Request).encode(encodePassword) //nolint:forcetypeassert // only ever given a Request
	}
}

// encode renders the request as a command line. encodePassword is the
// transport's rule for password parameters; an empty password is sent as is,
// since it means "no password" in every encoding.
//
// A list parameter is written last, as a row group: key=value per value (a
// table has several keys per row), separated by pipes, the other parameters
// applying to every row.
func (r Request) encode(encodePassword func(password string) string) string {
	out := make([][2]string, 0, len(r.params))
	var group *param
	for i, p := range r.params {
		if p.rows != nil || p.table != nil {
			group = &r.params[i]

			continue
		}
		if p.Value == nil {
			continue
		}
		value := *p.Value
		// Flags (-uid) are switches: present when true, absent otherwise.
		if len(p.Key) > 0 && p.Key[0] == '-' {
			if value == "1" {
				out = append(out, [2]string{p.Key, ""})
			}

			continue
		}
		if value != "" && r.isPassword(p.Key) {
			value = encodePassword(value)
		}
		out = append(out, [2]string{p.Key, value})
	}

	line := wire.BuildCommandOrdered(r.command, out)
	if group == nil {
		return line
	}
	var rows []string
	if group.table != nil {
		rows = make([]string, len(group.table))
		for i, row := range group.table {
			rows[i] = rowText(row)
		}
		// A table that opens with an empty row leaves the plain parameters a
		// row of their own, which the rows after it follow.
		if len(group.table) > 0 && len(group.table[0]) == 0 {
			return line + "|" + strings.Join(rows[1:], "|")
		}
	} else {
		rows = make([]string, len(group.rows))
		for i, value := range group.rows {
			rows[i] = group.Key + "=" + wire.Escape(value)
		}
	}

	return line + " " + strings.Join(rows, "|")
}

// rowText renders one row of a table parameter: its keys in order, as
// key=value separated by spaces.
func rowText(row [][2]string) string {
	parts := make([]string, len(row))
	for i, kv := range row {
		parts[i] = kv[0] + "=" + wire.Escape(kv[1])
	}

	return strings.Join(parts, " ")
}

func (r Request) isPassword(key string) bool {
	return slices.Contains(r.passwords, key)
}

// Executor is a connection the typed commands can run on.
//
// It is deliberately this narrow. A caller implements it to run the typed
// commands over a transport of their own, and [CommandMiddleware] wraps it, so
// a method added here would break every implementation and every middleware
// along with it: this interface gains no methods in a minor release. A new
// capability arrives as an interface, a function or an option of its own
// instead, and an implementer or a middleware author may rely on that.
type Executor interface {
	// Send executes a request and returns the rows that answer it.
	Send(ctx context.Context, req Request) ([]map[string]string, error)
}

// ExecutorFunc adapts a function to Executor, the way http.HandlerFunc adapts
// one to http.Handler: it gives a plain function the one method the interface
// needs. That makes it the way to fake or wrap execution — a middleware, or a
// test's stand-in for a client, is one of these rather than a type with a Send
// method of its own.
type ExecutorFunc func(ctx context.Context, req Request) ([]map[string]string, error)

// Send calls f.
func (f ExecutorFunc) Send(ctx context.Context, req Request) ([]map[string]string, error) {
	return f(ctx, req)
}

// CommandMiddleware wraps the typed commands' executor. It sees each request —
// its name with Request.Command, never its parameters' secrets in a log line —
// and the caller's context, and returns the rows or an error: so it can
// observe a command, time it, retry it, or answer it itself without calling
// next.
//
// It is here rather than in a client because every client wraps the same
// Executor, and a caller moving between them should not have to change the
// middleware's type. What a client sends on its own during a handshake or a
// disconnect does not pass through it.
type CommandMiddleware func(next Executor) Executor

// CommandLine is one command line on its way to the server.
type CommandLine struct {
	// Name is the command's name, such as "clientupdate".
	Name string
	// Text is the line as it goes on the wire, escaped, without the
	// return_code the client adds. It can carry secrets (channel password
	// hashes, privilege keys, a ServerQuery login): do not log it.
	Text string
}

// LineSender sends a command line and returns the rows that answer it; for a
// line the server answers with nothing, it returns no rows once the line is
// written. It is what a [LineMiddleware] wraps. Calling it more than once
// sends the line more than once, each time under a return code of its own,
// which is how a middleware resends.
type LineSender func(ctx context.Context, line CommandLine) ([]map[string]string, error)

// LineMiddleware wraps the sending of every command line a client sends once
// it has a session: typed commands after their encoding, raw Exec lines, and
// the commands the SDK sends on its own. It may delay a line, resend it,
// refuse it or answer it without calling next, which is the place to pace
// commands or to wait out a refusal for flooding. See [FloodWait].
//
// The SDK itself never paces and never resends. The command's deadline starts
// when the call starts and bounds the middleware's waits too; the context
// passed down is also cancelled when the client disconnects, and a line the
// middleware hands on after that is not written.
//
// Not seen: the lines of the voice handshake, sent before a session exists,
// and the goodbye of a disconnect (and a ServerQuery quit), which must leave
// at once or the server keeps a session for a client that has gone.
//
// The voice client builds two chains from the same middleware, one for lines
// that are answered and one for lines that are not (ExecNoWait and the answer
// to a connection info request), so a middleware may be called more than
// once: keep state that every line shares, such as a token bucket, outside it.
type LineMiddleware func(next LineSender) LineSender

// Commands are the typed commands, shared by every connection able to execute
// a command. Clients embed them, which is how a client gains its methods.
type Commands struct {
	executor Executor
	// fileTransferID allocates clientftfid values; see nextFileTransferID.
	fileTransferID atomic.Uint32
}

// NewCommands returns the typed commands running on executor. It panics if
// executor is nil: that is a programming error, not a condition to handle.
func NewCommands(executor Executor) *Commands {
	if executor == nil {
		panic("teamspeak: NewCommands needs an Executor")
	}

	return &Commands{executor: executor}
}

// exec sends a command that answers with no data and waits for the answer.
//
// passwords names the parameters that carry a channel password. Naming them,
// rather than encoding them, leaves the encoding to the transport and keeps
// every call site from having to remember — which is how a raw password once
// reached the server and failed 781.
func (c *Commands) exec(ctx context.Context, command string, params []param, passwords ...string) error {
	_, err := c.query(ctx, command, params, passwords...)

	return err
}

// query sends a command and returns its response rows. A parameter that cannot
// be encoded refuses the command before anything is sent.
func (c *Commands) query(
	ctx context.Context, command string, params []param, passwords ...string,
) ([]map[string]string, error) {
	err := firstInvalid(params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}

	return c.executor.Send(ctx, Request{command: command, params: params, passwords: passwords})
}

// queryRow sends a command defined to answer with one row, holding key when
// one is named, and returns that row; without it the error wraps ErrNoData.
func (c *Commands) queryRow(
	ctx context.Context, command, key string, params []param, passwords ...string,
) (map[string]string, error) {
	rows, err := c.query(ctx, command, params, passwords...)
	if err != nil {
		return nil, err
	}

	return requireRow(rows, command, key)
}

// list sends a command that lists something and returns its rows.
//
// The server reports an empty list as error 1281, "database empty result set",
// rather than as no rows — banlist on a server with no bans, messagelist with
// no messages — which made every list method fail where it should have
// returned nothing.
func (c *Commands) list(
	ctx context.Context, command string, params []param, passwords ...string,
) ([]map[string]string, error) {
	rows, err := c.query(ctx, command, params, passwords...)
	if errors.Is(err, errcode.DatabaseEmptyResult) {
		return nil, nil
	}

	return rows, err
}
