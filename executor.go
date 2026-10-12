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
	request.Encode = func(req any, encodePassword func(password string) string) string {
		return req.(Request).encode(encodePassword) //nolint:forcetypeassert // only ever given a Request
	}
}

// encode renders the request as a command line. encodePassword is the
// transport's rule for password parameters; an empty password is sent as is,
// since it means "no password" in every encoding.
//
// A list parameter is written last, as a row group: key=value per value,
// separated by pipes, the other parameters applying to every row.
func (r Request) encode(encodePassword func(password string) string) string {
	out := make([][2]string, 0, len(r.params))
	var group *param
	for i, p := range r.params {
		if p.rows != nil {
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
	rows := make([]string, len(group.rows))
	for i, value := range group.rows {
		rows[i] = group.Key + "=" + wire.Escape(value)
	}

	return line + " " + strings.Join(rows, "|")
}

func (r Request) isPassword(key string) bool {
	return slices.Contains(r.passwords, key)
}

// Executor is a connection the typed commands can run on.
type Executor interface {
	// Send executes a request and returns the rows that answer it.
	Send(ctx context.Context, req Request) ([]map[string]string, error)
}

// ExecutorFunc adapts a function to Executor, the way http.HandlerFunc adapts
// one to http.Handler; command middleware is written with it.
type ExecutorFunc func(ctx context.Context, req Request) ([]map[string]string, error)

// Send calls f.
func (f ExecutorFunc) Send(ctx context.Context, req Request) ([]map[string]string, error) {
	return f(ctx, req)
}

// Commands are the typed commands, shared by every connection able to execute
// a command. Clients embed them, which is how a client gains its methods.
type Commands struct {
	executor Executor
	// fileTransferID allocates clientftfid values; see nextFileTransferID.
	fileTransferID atomic.Uint32
}

// NewCommands returns the typed commands running on executor. A nil executor
// is a programming error, and panics.
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
func (c *Commands) list(ctx context.Context, command string, params []param) ([]map[string]string, error) {
	rows, err := c.query(ctx, command, params)
	if errors.Is(err, errcode.DatabaseEmptyResult) {
		return nil, nil
	}

	return rows, err
}
