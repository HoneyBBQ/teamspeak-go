package teamspeak

import (
	"context"
	"slices"
	"sync/atomic"

	"github.com/honeybbq/teamspeak-go/commands"
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

// Encode renders the request as a command line. encodePassword is the
// transport's rule for password parameters; an empty password is sent as is,
// since it means "no password" in every encoding.
func (r Request) Encode(encodePassword func(password string) string) string {
	out := make([][2]string, 0, len(r.params))
	for _, p := range r.params {
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

	return commands.BuildCommandOrdered(r.command, out)
}

func (r Request) isPassword(key string) bool {
	return slices.Contains(r.passwords, key)
}

// Executor is a connection the typed commands can run on.
type Executor interface {
	// Send executes a request and returns the rows that answer it.
	Send(ctx context.Context, req Request) ([]map[string]string, error)
}

// Commands are the typed commands, shared by every connection able to execute
// a command. Clients embed them, which is how a client gains its methods.
type Commands struct {
	executor Executor
	// fileTransferID allocates clientftfid values; see nextFileTransferID.
	fileTransferID atomic.Uint32
}

// NewCommands returns the typed commands running on executor.
func NewCommands(executor Executor) *Commands {
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

// query sends a command and returns its response rows.
func (c *Commands) query(
	ctx context.Context, command string, params []param, passwords ...string,
) ([]map[string]string, error) {
	return c.executor.Send(ctx, Request{command: command, params: params, passwords: passwords})
}
