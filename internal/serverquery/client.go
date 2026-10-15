// Package serverquery runs the typed commands over ServerQuery, TeamSpeak's
// line-based administration protocol.
//
// A skeleton, kept internal until it is finished: connecting, login and use,
// and notification events are to come. What is here is the part every
// transport shares — sending one command at a time and pairing each answer
// with the command that asked for it.
//
// It imports none of the voice client's cryptography: a ServerQuery program
// should not have to build an ECDH handshake it never runs.
package serverquery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/request"
	"github.com/honeybbq/teamspeak-go/internal/servererr"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// defaultCommandTimeout is how long a command waits for its answer when the
// caller's context sets no deadline.
const defaultCommandTimeout = 10 * time.Second

// Transport is the connection a ServerQuery client talks over.
//
// ServerQuery is a line protocol on three transports: raw TCP (10011), SSH
// (10022) and, on TeamSpeak 6, an HTTP WebQuery (10080) that frames each
// command as a request. The client depends on this interface only, so each
// transport is a separate piece, and a test or a proxy can supply its own.
type Transport interface {
	// WriteLine sends one command line; the transport adds the terminator.
	WriteLine(ctx context.Context, line string) error
	// ReadLine returns the next line the server sent, without its
	// terminator, in the order received. The greeting a raw connection opens
	// with is the transport's to consume. Any error ends the connection; after
	// Close it must return one.
	ReadLine() (string, error)
	// Close ends the connection.
	Close() error
}

type result struct {
	err  error
	rows []map[string]string
}

// pending is the command whose answer is arriving.
type pending struct {
	result chan result
	rows   []map[string]string
}

// Client runs commands over a Transport. It is a teamspeak.Executor, so the
// typed commands run on it through teamspeak.NewCommands.
//
// ServerQuery answers one command at a time, in order: data lines, then an
// error line that ends the answer, with no return_code to say which command it
// was. So commands are sent one after another, each once the previous one is
// answered, which also keeps the server's flood protection from seeing a
// burst. Notifications (notify…) can arrive at any point and are never part
// of an answer.
type Client struct {
	transport Transport
	// OnNotification, when set, sees every notification the server sends, as
	// it arrived: its name and unescaped parameters, one call per row of a
	// batched one. The read loop calls it, so its receiver must not send a
	// command from it: the loop is what would read that command's answer. A
	// client hands it to a goroutine of its own instead.
	OnNotification func(*wire.Command)
	// OnClosed, when set, runs once when the connection ends, with the reason
	// or nil after Close. It runs on the goroutine that noticed, which may be
	// the read loop, so it must not send a command either.
	OnClosed func(error)
	// turn is held by the command on the wire. A channel rather than a mutex so
	// a command can give up waiting for its turn when its context is done.
	turn chan struct{}
	// done is closed once the connection has ended.
	done    chan struct{}
	pending *pending
	// closeErr is why the connection ended, nil after Close.
	closeErr error
	// abandoned counts answers still to come for commands that gave up
	// waiting. With only order to go on, each is read and discarded when it
	// arrives; otherwise it would be taken for the next command's.
	abandoned int
	mu        sync.Mutex
	closeOnce sync.Once
	closed    bool
}

// New returns a client running over transport, and starts reading from it.
func New(transport Transport) *Client {
	c := &Client{
		transport: transport,
		turn:      make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	go c.readLoop()

	return c
}

// Send executes a typed command; it is the Executor the typed commands run
// on.
//
// Passwords go as they are: ServerQuery takes the password itself and hashes
// it server-side, where the voice protocol wants the hash.
func (c *Client) Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	return c.Exec(ctx, request.Encode(req, func(password string) string { return password }))
}

// Exec sends a raw command line and returns the rows that answer it. The line
// is sent as given, so its values must already be escaped (commands.Escape).
//
// Without a deadline on ctx the command gives up after defaultCommandTimeout.
func (c *Client) Exec(ctx context.Context, line string) ([]map[string]string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCommandTimeout)
		defer cancel()
	}
	name := commandName(line)

	select {
	case c.turn <- struct{}{}:
	case <-c.done:
		return nil, c.notConnected()
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	defer func() { <-c.turn }()

	p, err := c.send(ctx, line)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	select {
	case res := <-p.result:
		return res.rows, res.err
	case <-ctx.Done():
	}

	c.mu.Lock()
	if c.pending != p {
		// Answered, or failed, while giving up: the result is waiting.
		c.mu.Unlock()
		res := <-p.result

		return res.rows, res.err
	}
	c.pending = nil
	c.abandoned++
	c.mu.Unlock()

	return nil, fmt.Errorf("%s: %w", name, ctx.Err())
}

// Close ends the connection. Commands still waiting, and any sent later, fail
// with teamspeak.ErrNotConnected.
func (c *Client) Close() error {
	if !c.end(nil) {
		return nil
	}

	return c.transport.Close()
}

// send writes line as the command whose answer the next lines carry. The
// caller holds the turn.
func (c *Client) send(ctx context.Context, line string) (*pending, error) {
	p := &pending{result: make(chan result, 1)}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()

		return nil, c.notConnected()
	}
	c.pending = p
	c.mu.Unlock()

	err := c.transport.WriteLine(ctx, line)
	if err != nil {
		// Not sent, so no answer is coming.
		c.mu.Lock()
		if c.pending == p {
			c.pending = nil
		}
		c.mu.Unlock()

		return nil, err
	}

	return p, nil
}

func (c *Client) readLoop() {
	for {
		line, err := c.transport.ReadLine()
		if err != nil {
			c.end(err)

			return
		}
		c.handleLine(line)
	}
}

func (c *Client) handleLine(line string) {
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return
	}
	cmd := wire.ParseCommand(line)
	if cmd == nil {
		return
	}

	// Before the lock, because it takes none of the state below: a
	// notification is never part of an answer, so it neither waits on a
	// pending command nor is dropped when one was abandoned.
	if strings.HasPrefix(cmd.Name, "notify") {
		c.notify(line)

		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cmd.Name == "error" {
		if c.abandoned > 0 {
			c.abandoned--

			return
		}
		p := c.pending
		c.pending = nil
		if p == nil {
			return
		}
		// Checked as a *ServerError before it becomes an error: a nil pointer
		// in an error interface is not a nil error.
		serverErr := servererr.Parse(cmd.Params)
		if serverErr != nil {
			p.result <- result{err: serverErr}
		} else {
			p.result <- result{rows: p.rows}
		}

		return
	}

	// A data line, possibly several rows separated by "|".
	if c.abandoned > 0 || c.pending == nil {
		return
	}
	for _, row := range wire.SplitRows(line) {
		if parsed := wire.ParseCommand(row); parsed != nil {
			c.pending.rows = append(c.pending.rows, parsed.Params)
		}
	}
}

// notify hands a notification line to the hook, one call per row. A batched
// notification is one line of rows separated by "|", which reading the line
// whole would turn into a single row carrying the rest in its last value.
func (c *Client) notify(line string) {
	if c.OnNotification == nil {
		return
	}
	for _, row := range wire.SplitRows(line) {
		cmd := wire.ParseCommand(row)
		if cmd == nil {
			continue
		}
		c.OnNotification(cmd)
	}
}

// end records the end of the connection and fails the command waiting, if
// any. It reports whether this call was the one that ended it.
func (c *Client) end(cause error) bool {
	ended := false
	c.closeOnce.Do(func() {
		ended = true
		c.mu.Lock()
		c.closed = true
		c.closeErr = cause
		p := c.pending
		c.pending = nil
		c.mu.Unlock()
		close(c.done)

		if p != nil {
			p.result <- result{err: c.notConnected()}
		}
	})

	if ended && c.OnClosed != nil {
		c.OnClosed(cause)
	}

	return ended
}

// notConnected is the error for a command the connection cannot carry, with
// the reason the connection ended when there was one.
func (c *Client) notConnected() error {
	c.mu.Lock()
	cause := c.closeErr
	c.mu.Unlock()
	if cause != nil {
		return fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, cause)
	}

	return teamspeak.ErrNotConnected
}

// commandName is the name a command line starts with: what an error may say
// about a command whose parameters can carry secrets.
func commandName(line string) string {
	name, _, _ := strings.Cut(line, " ")

	return name
}
