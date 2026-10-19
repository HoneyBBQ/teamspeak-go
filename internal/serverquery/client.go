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
	"slices"
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

// nudgeAfter is how long a command waits for its answer before a transport
// that is a [Nudger] is asked to nudge, and nudgeEvery how often after that,
// until the answer is complete or the command ends.
const (
	nudgeAfter = 2 * time.Second
	nudgeEvery = time.Second
)

// Transport is the connection a ServerQuery client talks over.
//
// ServerQuery is a line protocol on three transports: raw TCP (10011), SSH
// (10022) and an HTTP WebQuery (10080) that frames each command as a request.
// TeamSpeak 3 (3.3 and later for SSH, 3.12 for WebQuery) serves them as well as
// TeamSpeak 6. The client depends on this interface only, so each transport is
// a separate piece, and a test or a proxy can supply its own.
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

// Nudger is a transport that can release a reply the server is holding back.
//
// On TeamSpeak 6 over SSH the server may keep the last line of a reply,
// usually "error id=0 msg=ok", until the client writes again. An empty line
// releases it, and the server answers an empty line with nothing. This was
// measured on TeamSpeak 6 (6.0.0-beta13.1) and only over SSH: raw TCP and
// WebQuery do not show it, so only the SSH transport implements this. The
// empty line is harmless on a server that holds nothing back. See the "Server
// behaviour the SDK works around" section of the serverquery package
// documentation.
//
// While a command is outstanding the client calls Nudge once it has waited
// nudgeAfter, then every nudgeEvery, until its answer is complete or it ends by
// timeout, cancel or close. Nudge writes the bare line terminator and adds no
// reply line.
type Nudger interface {
	Nudge() error
}

type result struct {
	err  error
	rows []map[string]string
}

// pending is the command whose answer is arriving.
type pending struct {
	// command is the name of the command, to know what its answer carries.
	command string
	result  chan result
	rows    []map[string]string
	// held is set once the error line has been read and the answer is being
	// kept open for a late row.
	held *held
}

// held is an answer whose error line has come but whose row has not.
type held struct {
	timer *time.Timer
	late  lateRow
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
	// transportErr is what closing the transport reported, kept so Close can
	// return it when the read loop is what ended the connection.
	transportErr error
	// abandoned counts answers still to come for commands that gave up
	// waiting. With only order to go on, each is read and discarded when it
	// arrives; otherwise it would be taken for the next command's.
	abandoned int
	// strayKey is the key of a row that was waited for and did not come before
	// its answer was given up on. Should it arrive later, it belongs to that
	// command, and is dropped rather than handed to the next one.
	strayKey  string
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

	defer c.startNudging(p)()

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
	// An answer held for a late row has had its error line already: nothing
	// more is coming that would need discarding.
	if p.held != nil {
		p.held.timer.Stop()
	} else {
		c.abandoned++
	}
	c.mu.Unlock()

	return nil, fmt.Errorf("%s: %w", name, ctx.Err())
}

// Close ends the connection. Commands still waiting, and any sent later, fail
// with teamspeak.ErrNotConnected.
//
// Ending the connection is end's work, so this is the same thing with no cause
// to report; the transport's error is returned however the connection ended,
// including when the read loop noticed before this was called.
func (c *Client) Close() error {
	c.end(nil)

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.transportErr
}

// send writes line as the command whose answer the next lines carry. The
// caller holds the turn.
func (c *Client) send(ctx context.Context, line string) (*pending, error) {
	p := &pending{command: commandName(line), result: make(chan result, 1)}
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

// startNudging nudges the transport while p, the command on the wire, waits
// for its answer, and returns the function that stops it. It does nothing for
// a transport that is not a [Nudger].
//
// The timing follows p alone: the next command takes the turn only after p's
// Exec has returned, and so has stopped this, so a command waiting for its turn
// is never nudged for. Stopping waits for a nudge in flight, so none is written
// after the command has ended.
func (c *Client) startNudging(p *pending) func() {
	n, ok := c.transport.(Nudger)
	if !ok {
		return func() {}
	}
	var (
		mu      sync.Mutex
		stopped bool
		timer   *time.Timer
	)
	mu.Lock()
	timer = time.AfterFunc(nudgeAfter, func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		c.mu.Lock()
		waiting := c.pending == p && !c.closed
		c.mu.Unlock()
		if !waiting {
			return
		}
		_ = n.Nudge()
		timer.Reset(nudgeEvery)
	})
	mu.Unlock()

	return func() {
		timer.Stop()
		mu.Lock()
		stopped = true
		mu.Unlock()
	}
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
		c.handleError(cmd)

		return
	}
	c.handleRows(line)
}

// handleError ends the answer the error line closes. Called with the lock held.
func (c *Client) handleError(cmd *wire.Command) {
	if c.abandoned > 0 {
		c.abandoned--

		return
	}
	p := c.pending
	if p == nil {
		return
	}
	c.strayKey = ""
	// Checked as a *ServerError before it becomes an error: a nil pointer in an
	// error interface is not a nil error.
	serverErr := servererr.Parse(cmd.Params)
	if serverErr != nil {
		c.pending = nil
		p.result <- result{err: serverErr}

		return
	}
	if late, ok := c.lateRow(p); ok && (late.several || !late.answered(p.rows)) {
		// A create that succeeded and has no row yet: the server may write the
		// row just after this line. Wait briefly, with the command still the
		// one on the wire, so the row is its own and the next command is not
		// sent before it.
		p.held = &held{late: late}
		wait := lateRowGrace
		if late.answered(p.rows) || late.any {
			wait = lateRowQuiet
		}
		p.held.timer = time.AfterFunc(wait, func() { c.giveUp(p) })

		return
	}
	c.pending = nil
	p.result <- result{rows: p.rows}
}

// handleRows adds a data line, possibly several rows separated by "|", to the
// answer being read. Called with the lock held.
func (c *Client) handleRows(line string) {
	if c.abandoned > 0 || c.pending == nil {
		return
	}
	for _, row := range wire.SplitRows(line) {
		parsed := wire.ParseCommand(row)
		if parsed == nil {
			continue
		}
		if c.isStray(parsed.Params) {
			// The late row of an earlier command, which gave up waiting for it.
			c.strayKey = ""

			continue
		}
		p := c.pending
		p.rows = append(p.rows, parsed.Params)
		if p.held != nil && p.held.late.answered(p.rows) && c.rowArrivedWhileHeld(p) {
			return
		}
	}
}

// isStray reports whether a row is the late row of an earlier command: the lone
// key that command's answer was missing. A command whose own answer carries
// that key keeps the row. The two cases cannot be told apart, and lateness was
// measured at under a millisecond against a wait of 250, so the row almost
// certainly belongs to the command asking now. Called with the lock held.
func (c *Client) isStray(params map[string]string) bool {
	if c.strayKey == "" || len(params) != 1 {
		return false
	}
	if _, only := params[c.strayKey]; !only {
		return false
	}
	if own, ok := lateRowOf(c.pending.command); ok && slices.Contains(own.keys, c.strayKey) {
		c.strayKey = ""

		return false
	}

	return true
}

// rowArrivedWhileHeld handles the row that an answer held for a late row was
// waiting for, and reports whether that completed the answer. An answer of
// several rows is complete once they stop, so the wait starts over. Called with
// the lock held.
func (c *Client) rowArrivedWhileHeld(p *pending) bool {
	p.held.timer.Stop()
	if p.held.late.several || p.held.late.any {
		p.held.timer = time.AfterFunc(lateRowQuiet, func() { c.giveUp(p) })

		return false
	}
	c.pending = nil
	p.result <- result{rows: p.rows}

	return true
}

// lateRow is the row p's command is waited for, or false when its answer is
// complete at the error line: a command that makes nothing, or a transport that
// delivers whole answers. Called with the lock held.
func (c *Client) lateRow(p *pending) (lateRow, bool) {
	if _, whole := c.transport.(WholeAnswers); whole {
		return lateRow{}, false
	}

	return lateRowOf(p.command)
}

// giveUp ends the wait for a late row: the answer is what it was at the error
// line, and a row that still comes is not the next command's.
func (c *Client) giveUp(p *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != p {
		return
	}
	c.pending = nil
	// With no row at all, one that still comes is not the next command's.
	if !p.held.late.answered(p.rows) && len(p.held.late.keys) > 0 {
		c.strayKey = p.held.late.keys[0]
	}
	p.result <- result{rows: p.rows}
}

func hasKey(rows []map[string]string, keys []string) bool {
	for _, row := range rows {
		for _, k := range keys {
			if _, ok := row[k]; ok {
				return true
			}
		}
	}

	return false
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

// end records the end of the connection, closes the transport and fails the
// command waiting, if any. The first call does the work and the rest are
// no-ops.
//
// The transport is closed here rather than by Close alone, because the read
// loop is the other way a connection ends: a server that ends the session —
// closing the shell, say — leaves the socket and whatever serves it open until
// someone closes them, and nothing else is coming to. Closing something
// already closed is the transport's to tolerate, and the error is kept for
// Close to return.
func (c *Client) end(cause error) {
	c.closeOnce.Do(func() {
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

		// Outside the lock: closing a connection waits for what serves it.
		err := c.transport.Close()
		c.mu.Lock()
		c.transportErr = err
		c.mu.Unlock()
	})

	if c.OnClosed != nil {
		c.OnClosed(cause)
	}
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
