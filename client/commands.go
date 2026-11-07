package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
	"github.com/honeybbq/teamspeak-go/internal/request"
	"github.com/honeybbq/teamspeak-go/internal/servererr"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

type commandResult struct {
	Err  error
	Data []map[string]string
}

// bufferedRow is a row waiting for the error that says which command it
// answered.
type bufferedRow struct {
	params map[string]string
	// source is the notification that carried the row, or "" for a nameless
	// data row.
	source string
}

type pendingCommand struct {
	spec   *responseSpec
	result chan commandResult
	// settled holds the command's error result while its correlated answer is
	// still due.
	settled *commandResult
	// correlation is the request's value for spec.Correlated.Key.
	correlation string
	// correlated holds answers that arrived before the command's own error.
	correlated     []map[string]string
	hasCorrelation bool
}

// commandTracker matches the server's answers to the commands that asked for
// them.
//
// The server handles one client's commands in order and closes each answer
// with "error … return_code=N", so every row seen since the previous error
// belongs to command N. Rows are therefore held, tagged with where they came
// from, until that error says whose they are. Attributing them on arrival meant
// guessing which in-flight command the server was answering, and the guess —
// the newest — was wrong whenever two were in flight, as when a command
// registered ahead of its turn took the rows of one already answered.
//
// A nameless row always belongs to the command. A notification row belongs to
// it only if the command declared that notification as its answer (see
// responses.go): the same notifyclientmoved that answers nothing can
// arrive between any two commands.
//
// The welcome sequence is the exception. The server pushes channellist,
// channelgrouplist and the rest unprompted right after the handshake, before
// channellistfinished; without the gate they would land in the first command's
// answer as duplicate rows and a phantom cid=0.
type commandTracker struct {
	pending map[uint32]*pendingCommand
	buffer  []bufferedRow
	mu      sync.Mutex
	// nextRC is never reset: a late answer to a command of an earlier connection
	// must not carry the return_code of a later one.
	nextRC          atomic.Uint32
	welcomeComplete bool
}

func newCommandTracker() *commandTracker {
	return &commandTracker{pending: make(map[uint32]*pendingCommand)}
}

// newReadyCommandTracker returns a tracker past the welcome sequence, for tests
// that exercise collection without a handshake.
func newReadyCommandTracker() *commandTracker {
	t := newCommandTracker()
	t.welcomeComplete = true

	return t
}

// register records a command about to be sent. correlation is the request's
// value for the spec's correlation key, when it has one.
func (t *commandTracker) register(
	spec *responseSpec, correlation string, hasCorrelation bool,
) (uint32, <-chan commandResult) {
	rc := t.nextRC.Add(1)
	ch := make(chan commandResult, 1)
	t.mu.Lock()
	t.pending[rc] = &pendingCommand{
		spec:           spec,
		result:         ch,
		correlation:    correlation,
		hasCorrelation: hasCorrelation,
	}
	t.mu.Unlock()

	return rc, ch
}

// setCorrelation records the value an answer echoes for a command whose
// correlation key is its own return_code. The code exists only once the command
// is registered, so the request cannot carry it. It is called
// before the command is sent.
func (t *commandTracker) setCorrelation(rc uint32, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if p, ok := t.pending[rc]; ok {
		p.correlation, p.hasCorrelation = value, true
	}
}

func (t *commandTracker) unregister(rc uint32) {
	t.mu.Lock()
	delete(t.pending, rc)
	t.mu.Unlock()
}

// expects reports whether some in-flight command declared name as its answer.
func (t *commandTracker) expects(name string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, p := range t.pending {
		if p.spec.declares(name) {
			return true
		}
	}

	return false
}

// collect holds a row until the next error says which command it answered.
func (t *commandTracker) collect(params map[string]string, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.welcomeComplete || len(t.pending) == 0 {
		return
	}
	t.buffer = append(t.buffer, bufferedRow{params: params, source: source})
}

// offerCorrelated offers a notification to commands answered after their
// error. Matching is on the echoed request field, so it does not matter whether
// the notification beats the error or follows it.
func (t *commandTracker) offerCorrelated(name string, params map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for rc, p := range t.pending {
		// A command the table has no entry for (whoami, clientlist, anything
		// sent through Exec) has no spec, and so no correlation to match.
		if p.spec == nil || p.spec.Correlated == nil || !p.hasCorrelation {
			continue
		}
		c := p.spec.Correlated
		if !slices.Contains(c.Notifications, name) {
			continue
		}
		if params[c.Key] != p.correlation {
			continue
		}

		if name == c.Failure && params["status"] != "" && params["status"] != "0" {
			t.settleLocked(rc, p, commandResult{Err: &teamspeak.ServerError{
				Code: wire.ParseCode(params["status"]), Message: params["msg"], ExtraMessage: params["extra_msg"],
			}})

			return
		}
		p.correlated = append(p.correlated, params)
		if p.settled != nil {
			t.settleLocked(rc, p, commandResult{Data: append(p.settled.Data, p.correlated...)})
		}
		// Not a return: several commands can ask for the same key (two
		// getconnectioninfo for one client), and each takes the row.
	}
}

// resolve hands the rows held since the previous error to command rc.
// ownClientID filters answers that keep only the rows this client invoked.
func (t *commandTracker) resolve(rc uint32, err error, ownClientID teamspeak.ClientID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rows := t.buffer
	t.buffer = nil
	p, ok := t.pending[rc]
	if !ok {
		return
	}

	own := strconv.FormatUint(uint64(ownClientID), 10)
	var data []map[string]string
	for _, row := range rows {
		if answers(p, row, own) {
			data = append(data, row.params)
		}
	}

	if err != nil {
		t.settleLocked(rc, p, commandResult{Err: err, Data: data})

		return
	}
	// Answered after the error: hold the result until the answer arrives, or
	// the caller gives up on it.
	if p.spec != nil && p.spec.Correlated != nil && p.hasCorrelation && len(p.correlated) == 0 {
		p.settled = &commandResult{Data: data}

		return
	}
	t.settleLocked(rc, p, commandResult{Data: append(data, p.correlated...)})
}

func answers(p *pendingCommand, row bufferedRow, ownClientID string) bool {
	if row.source == "" {
		return true
	}
	spec := p.spec
	if !spec.isInline(row.source) {
		return false
	}
	if spec.OwnRowsOnly && row.params["invokerid"] != ownClientID {
		return false
	}
	return true
}

// settleLocked delivers a command's result exactly once. The channel has room
// for that one value, so the send cannot block while the lock is held.
func (t *commandTracker) settleLocked(rc uint32, p *pendingCommand, result commandResult) {
	delete(t.pending, rc)
	p.result <- result
}

// discardBuffered drops the rows held since the previous error, which an
// error naming no command has just closed.
func (t *commandTracker) discardBuffered() {
	t.mu.Lock()
	t.buffer = nil
	t.mu.Unlock()
}

// signalWelcomeComplete marks the end of the server's welcome sequence and
// discards whatever was held while it was still arriving.
func (t *commandTracker) signalWelcomeComplete() {
	t.mu.Lock()
	t.welcomeComplete = true
	t.buffer = nil
	t.mu.Unlock()
}

// reset forgets every command and fails it with err. Dropping them silently
// would leave each caller waiting out its full timeout for an answer that can
// no longer come.
func (t *commandTracker) reset(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for rc, p := range t.pending {
		t.settleLocked(rc, p, commandResult{Err: err})
	}
	t.buffer = nil
	t.welcomeComplete = false
}

// handlePacket handles a packet handler h received. A packet from a handler
// that a later Connect has already replaced is dropped: its connection, and
// the crypto state it carries, are no longer the client's.
func (c *Client) handlePacket(h *transport.PacketHandler, p *transport.Packet) {
	if c.currentHandler() != h {
		return
	}
	switch p.Type() {
	case transport.PacketTypeInit1:
		c.handleInit1(h, p.Data)
	case transport.PacketTypeCommand, transport.PacketTypeCommandLow:
		if len(p.Data) == 0 {
			return
		}
		c.handleCommandLines(h, string(p.Data))
	case transport.PacketTypeVoice, transport.PacketTypeVoiceWhisper:
		c.handleVoicePacket(p)
	case transport.PacketTypePing, transport.PacketTypePong, transport.PacketTypeAck, transport.PacketTypeAckLow:
		return
	}
}

// handleInit1 answers a step of the Init1 exchange. Once the shared secret
// exists the exchange is over, and a late or replayed Init1 is ignored.
//
// The puzzle is the one step that takes time, up to seconds when a flooded
// server asks for a lot, so it is solved on a goroutine of its own and the
// connection goes on receiving meanwhile. Closing the connection, which is
// what cancelling Connect does, stops the solve.
func (c *Client) handleInit1(h *transport.PacketHandler, data []byte) {
	if h.TsCrypt.InitComplete() {
		return
	}
	if handshake.IsPuzzleStep(data) {
		c.setStage(h, stagePuzzleSolve, -1)
		// A copy: the packet's bytes are not the solver's to keep.
		go c.answerInit1(h, bytes.Clone(data))

		return
	}
	c.answerInit1(h, data)
}

// answerInit1 answers one Init1 step on handler h, and ends the attempt if the
// step cannot be answered.
func (c *Client) answerInit1(h *transport.PacketHandler, data []byte) {
	// Cancelled when h closes: the attempt ended, for whatever reason.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-h.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	response, err := handshake.ProcessInit1(ctx, h.TsCrypt, data)
	if err != nil {
		// Init1 is not authenticated: a step that cannot be answered is
		// ignored, not a reason to end the attempt, or anyone could end it with
		// one datagram. The real server's steps go on.
		if errors.Is(err, handshake.ErrMalformedInit1) {
			c.logger.Debug("ignoring a malformed Init1 step", slog.Any("error", err))

			return
		}
		// An attempt that ended did so for its own reason; the abandoned
		// solve has nothing more to report.
		if ctx.Err() == nil {
			c.failHandshake(h, err)
		}

		return
	}
	if response == nil {
		c.logger.Debug("ignoring a second RSA challenge")

		return
	}
	err = h.SendPacket(byte(transport.PacketTypeInit1), response, 0)
	if err != nil {
		c.logger.Warn("failed to send init1 response", slog.Any("error", err))

		return
	}
	switch {
	case handshake.IsPuzzleStep(data):
		c.setStage(h, stagePuzzleAnswer, -1)
	case len(data) > 0 && data[0] != 0x7F:
		c.setStage(h, stageInit1, int(data[0]))
	default:
		c.setStage(h, stageInit1, -1)
	}
}

// setStage records the step of the key exchange h's attempt has reached, for
// the error of an attempt that stalls there.
func (c *Client) setStage(h *transport.PacketHandler, stage handshakeStage, step int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handler != h || c.status != StatusConnecting {
		return
	}
	c.attempt.stage = stage
	c.attempt.init1Step = step
}

// failHandshake ends a connection attempt whose handshake cannot go on, with a
// cause wrapping ErrHandshake. Once connected there is no handshake left to
// fail, and the step is dropped instead.
func (c *Client) failHandshake(h *transport.PacketHandler, err error) {
	c.mu.Lock()
	if c.handler != h || c.status != StatusConnecting {
		c.mu.Unlock()
		c.logger.Debug("ignoring a handshake step outside a handshake", slog.Any("error", err))

		return
	}
	// Debug, not Error: the error reaches Connect, which returns it.
	c.logger.Debug("handshake failed", slog.Any("error", err))
	c.failConnectionLocked(fmt.Errorf("%w: %w", ErrHandshake, err))
}

func (c *Client) handleCommandLines(h *transport.PacketHandler, s string) {
	if s == "" {
		return
	}
	revision := c.viewRevision()
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' || s[i] == 0x00 {
			part := strings.TrimSuffix(s[start:i], "\r")
			if part != "" {
				rows := wire.SplitRows(part)
				for _, row := range rows {
					c.handleCommand(h, row)
				}
				// A group list is one command line, and replaces the groups
				// the view holds, so it is applied when the line is done.
				c.applyGroupLists(h)
			}
			start = i + 1
		}
	}
	// After the typed events of this packet, which are already queued.
	c.announceViewChange(revision)
}

func (c *Client) handleCommand(h *transport.PacketHandler, s string) {
	cmd := wire.ParseCommand(s)
	if cmd == nil {
		return
	}

	// The name and the parameter count only: parameters carry privilege
	// keys, file transfer keys, temporary passwords and message bodies.
	c.logger.Debug("processing command", slog.String("name", cmd.Name), slog.Int("params", len(cmd.Params)))

	// Until the shared secret exists, packets are sealed with the public dummy
	// key, so anyone on the path can forge them. Only the key exchange and an
	// error are handled then; notifications, data rows and the rest are
	// dropped.
	if !h.TsCrypt.InitComplete() && !handledBeforeCryptoInit(cmd.Name) {
		c.logger.Debug("dropping a command that arrived before crypto init", slog.String("name", cmd.Name))

		return
	}

	// An empty name means a response row: the server sends data without echoing
	// the command, so the row belongs to whichever command awaits a result.
	if cmd.Name == "" {
		if len(cmd.Params) > 0 {
			c.cmdTrack.collect(cmd.Params, "")
		}

		return
	}

	// channellistfinished ends the server's unprompted welcome sequence. It
	// carries no data of its own, so it is the only reliable marker.
	if cmd.Name == "channellistfinished" {
		c.finishViewWelcome(h)
		c.cmdTrack.signalWelcomeComplete()
		c.traceWelcomeDone(h)

		return
	}

	if strings.HasPrefix(cmd.Name, "notify") {
		c.receiveNotification(h, cmd)

		return
	}

	switch cmd.Name {
	case "clientinitiv":
		c.handleHandshakeInitIV(h, cmd)
	case "initivexpand2":
		c.handleHandshakeExpand2(h, cmd)
	case "initserver":
		c.handleInitServer(h, cmd)
	case "error":
		c.handleError(h, cmd)
	default:
		c.handleOtherCommand(h, cmd)
	}
}

// handleOtherCommand holds a named command the SDK does not model under its
// own name, so it answers a command only if that command declared it — not
// merely by arriving while one is in flight.
func (c *Client) handleOtherCommand(h *transport.PacketHandler, cmd *wire.Command) {
	if cmd.Name == "channellist" {
		// A channel of the welcome sequence, counted for the trace; the answer
		// to a command that asked for the list is held as any named row is.
		c.countWelcomeChannel(h)
		c.collectViewChannel(h, cmd.Params)
	}
	c.cmdTrack.collect(cmd.Params, cmd.Name)
	c.logger.Debug("unhandled or data command", slog.String("name", cmd.Name), slog.Int("params", len(cmd.Params)))
}

// handledBeforeCryptoInit reports whether a command named name is handled
// before crypto init completes: the key exchange's two steps, and an error,
// which may fail the attempt.
func handledBeforeCryptoInit(name string) bool {
	switch name {
	case "clientinitiv", "initivexpand2", "error":
		return true
	default:
		return false
	}
}

// receiveNotification hands a notification to the command awaiting it, if
// any, and then to its handlers.
func (c *Client) receiveNotification(h *transport.PacketHandler, cmd *wire.Command) {
	// Some commands are answered by a notification instead of data rows. It
	// still goes on to be dispatched as an event, since the same notification
	// also arrives unprompted.
	if c.cmdTrack.expects(cmd.Name) {
		c.cmdTrack.collect(cmd.Params, cmd.Name)
		c.cmdTrack.offerCorrelated(cmd.Name, cmd.Params)
	}
	c.handleNotification(h, cmd)
	// After the typed event, so a handler of both sees the typed one first.
	// Built only for someone who will see it: a copy of every notification is
	// not free. A copy because the command tracker hands the same map to the
	// command that asked for it.
	if c.onNotification.Any() || len(c.eventMiddlewares) > 0 {
		c.emitEvent(NotificationEvent{Name: cmd.Name, Params: maps.Clone(cmd.Params)})
	}
}

// handleError settles the command an error answers. A server error before the
// handshake completed also fails the connection attempt h runs, unless a later
// Connect has replaced h meanwhile.
func (c *Client) handleError(h *transport.PacketHandler, cmd *wire.Command) {
	rcStr := cmd.Params["return_code"]

	var err error
	serverErr := servererr.Parse(cmd.Params)
	if serverErr != nil {
		err = serverErr
		// Debug, not Error: the error goes back to whoever sent the command,
		// and logging it as well reported every refusal twice.
		c.logger.Debug("server refused a command",
			slog.Uint64("code", uint64(serverErr.Code)), slog.String("message", serverErr.Message))

		// Only once crypto init is complete: before it, the error is sealed
		// with the public dummy key, and a forged ban must not stop the
		// client for good. It still fails this attempt, below.
		if serverErr.Code == errcode.ConnectFailedBanned && h.TsCrypt.InitComplete() {
			c.logger.Warn("banned by the server, closing the connection")
			c.background.Go(func() { c.disconnectBanned(h) })
		}
	}

	// An error closes the answer the rows since the previous one belong to,
	// whether or not it names the command: without a return_code, as for
	// clientinit, the rows were no command's and are dropped, rather than
	// handed to the next command answered.
	rc, parseErr := strconv.ParseUint(rcStr, 10, 32)
	if rcStr != "" && parseErr == nil {
		c.cmdTrack.resolve(uint32(rc), err, c.ClientID())
	} else {
		c.cmdTrack.discardBuffered()
	}

	// A server error before the handshake completed is the connection failure
	// itself: a rejected password, or an invalid clientinit parameter.
	// failConnection is a no-op once connected.
	if err != nil {
		c.failConnection(h, err)
	}
}

// disconnectBanned disconnects after the server banned the connection h ran,
// unless a later Connect has replaced it by the time this goroutine runs.
func (c *Client) disconnectBanned(h *transport.PacketHandler) {
	// Detached on purpose: nobody is waiting on this goroutine and there is no
	// caller context. It is bounded all the same: the goodbye waits
	// disconnectTimeout at most, and joining a Disconnect already in progress
	// waits for that one's goodbye, which has the same bound.
	disconnectErr := c.disconnect(context.Background(), h, defaultLeaveMessage)
	if disconnectErr != nil {
		c.logger.Warn("disconnect after fatal error failed", slog.Any("error", disconnectErr))
	}
}

// ExecNoWait sends a raw command line without waiting for an answer, for the
// few commands the server answers with nothing at all. Like Exec, it sends the
// line as given, through the line middleware; ctx bounds the middleware's
// waits. Without an open connection it returns teamspeak.ErrNotConnected.
func (c *Client) ExecNoWait(ctx context.Context, cmd string) error {
	parsed := wire.ParseCommand(cmd)
	if parsed == nil {
		return fmt.Errorf("%w: empty command", teamspeak.ErrInvalidCommand)
	}
	_, err := c.throughLines(ctx, teamspeak.CommandLine{Name: parsed.Name, Text: cmd}, c.lineNoWait)

	return err
}

// Exec sends a raw command line and returns the rows that answer it: the
// escape hatch for a command the typed methods do not cover; the commands
// package names commands and escapes values. The line is sent as given, so its
// values must already be escaped (commands.Escape) and any channel password
// already hashed.
//
// Without a deadline on ctx the command gives up after ten seconds.
//
// The line passes the line middleware (WithLineMiddleware). The client never
// resends: a command the server refuses as flooding (errcode.ClientIsFlooding)
// returns that error, and teamspeak.FloodWait reads the wait it names.
func (c *Client) Exec(ctx context.Context, cmd string) ([]map[string]string, error) {
	return c.send(ctx, cmd)
}

// defaultCommandTimeout is how long a command waits for its answer when the
// caller's context sets no deadline.
const defaultCommandTimeout = 10 * time.Second

// Send executes a typed command, through the command middleware; it is the
// Executor the client's typed commands run on.
//
// Channel passwords are hashed here because that is this protocol's rule: the
// voice protocol expects base64(sha1(password)), where ServerQuery takes the
// password itself. Without a deadline on ctx the command gives up after ten
// seconds, since an answer that never comes would otherwise hold the caller
// forever.
func (c *Client) Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	return c.executor.Send(ctx, req)
}

// sendRequest is the executor the command middleware wraps: it encodes the
// request for the voice protocol and sends it.
func (c *Client) sendRequest(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	return c.send(ctx, request.Encode(req, prepareClientPassword))
}

// send executes a command line, applying defaultCommandTimeout when ctx sets
// no deadline.
func (c *Client) send(ctx context.Context, cmd string) ([]map[string]string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCommandTimeout)
		defer cancel()
	}

	return c.execWithResponse(ctx, cmd)
}

// execWithResponse sends a raw command and waits, until ctx is done, for the
// answer the tracker pairs with it.
func (c *Client) execWithResponse(ctx context.Context, cmd string) ([]map[string]string, error) {
	parsed, err := parseLine(cmd)
	if err != nil {
		return nil, err
	}

	return c.throughLines(ctx, teamspeak.CommandLine{Name: parsed.Name, Text: cmd}, c.lineSend)
}

// parseLine parses a raw command line, refusing what cannot be sent.
func parseLine(cmd string) (*wire.Command, error) {
	parsed := wire.ParseCommand(cmd)
	if parsed == nil {
		return nil, fmt.Errorf("%w: empty command", teamspeak.ErrInvalidCommand)
	}
	// Checked as a parameter rather than as text: a message body that merely
	// contains "return_code=" used to suppress the real one and time the
	// command out. A caller-supplied one would detach the command from its
	// answer, so it is refused.
	if _, ok := parsed.Params["return_code"]; ok {
		return nil, fmt.Errorf("%w: commands must not carry their own return_code", teamspeak.ErrInvalidCommand)
	}

	return parsed, nil
}

// throughLines runs line through chain, the line middleware around one of the
// client's two bases. The context the middleware gets ends when the client
// starts to disconnect, so a line waiting in a middleware is not written
// afterwards; the call then returns teamspeak.ErrNotConnected.
func (c *Client) throughLines(
	ctx context.Context, line teamspeak.CommandLine, chain teamspeak.LineSender,
) ([]map[string]string, error) {
	ctx, release, err := c.enterLine(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	rows, err := chain(ctx, line)
	if err != nil && errors.Is(context.Cause(ctx), teamspeak.ErrNotConnected) {
		return nil, teamspeak.ErrNotConnected
	}

	return rows, err
}

// enterLine registers a line about to enter the middleware, so that a
// disconnect starting meanwhile cancels its context. It refuses a client with
// no connected session.
func (c *Client) enterLine(ctx context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.status != StatusConnected || c.handler == nil {
		return nil, nil, teamspeak.ErrNotConnected
	}
	ctx, cancel := context.WithCancelCause(ctx)
	if c.lineCalls == nil {
		c.lineCalls = make(map[*context.CancelCauseFunc]struct{})
	}
	key := &cancel
	c.lineCalls[key] = struct{}{}

	return ctx, func() {
		c.mu.Lock()
		delete(c.lineCalls, key)
		c.mu.Unlock()
		cancel(nil)
	}, nil
}

// abortLinesLocked cancels the context of every line still inside the line
// middleware. The caller holds c.mu and has already left StatusConnected, so
// no line enters after it.
func (c *Client) abortLinesLocked() {
	for cancel := range c.lineCalls {
		(*cancel)(teamspeak.ErrNotConnected)
	}
	clear(c.lineCalls)
}

// buildLineChains wraps the two bases in the line middleware. It runs once, in
// New, like buildMiddlewareChains.
func (c *Client) buildLineChains() {
	c.lineSend = c.baseLine
	c.lineNoWait = c.baseLineNoWait
	for _, middleware := range slices.Backward(c.lineMiddlewares) {
		c.lineSend = middleware(c.lineSend)
		c.lineNoWait = middleware(c.lineNoWait)
	}
}

// baseLine is the sender the line middleware wraps for a command with an
// answer: it re-checks the connection, then sends the line once under a return
// code of its own and waits for the answer.
func (c *Client) baseLine(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
	h := c.connectedHandler()
	if h == nil {
		return nil, teamspeak.ErrNotConnected
	}

	return c.execOn(ctx, h, line.Text, false)
}

// baseLineNoWait is baseLine for a command the server answers with nothing:
// it resolves with no rows once the line is written.
func (c *Client) baseLineNoWait(ctx context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
	h := c.connectedHandler()
	if h == nil {
		return nil, teamspeak.ErrNotConnected
	}
	parsed, err := parseLine(line.Text)
	if err != nil {
		return nil, err
	}
	c.logger.DebugContext(ctx, "sending command without waiting", slog.String("command", parsed.Name))

	return nil, c.sendLine(h, line.Text)
}

// execOn sends a raw command on h and waits, until ctx is done, for its
// answer, under a return code registered afresh on every call. The goodbye of
// a Disconnect (goodbye) is sent by Disconnect itself, past the line
// middleware and with the status already Disconnected: held up, it would not
// leave in time, and the server would keep the session.
func (c *Client) execOn(
	ctx context.Context, h *transport.PacketHandler, cmd string, goodbye bool,
) ([]map[string]string, error) {
	if !h.IsOpen() {
		return nil, teamspeak.ErrNotConnected
	}

	parsed, err := parseLine(cmd)
	if err != nil {
		return nil, err
	}

	// Which notifications answer this command, and — for answers that arrive
	// after the error — the request field they echo back.
	spec := responseFor(parsed.Name)
	var correlation string
	var hasCorrelation bool
	if spec != nil && spec.Correlated != nil {
		correlation, hasCorrelation = parsed.Params[spec.Correlated.Key]
	}

	return c.sendAndAwait(ctx, h, cmd, parsed, spec, correlation, hasCorrelation, goodbye)
}

// sendAndAwait sends parsed, the command cmd, once under a return code of its
// own, and waits until ctx is done for the answer the tracker pairs with it.
func (c *Client) sendAndAwait(
	ctx context.Context, h *transport.PacketHandler, cmd string, parsed *wire.Command,
	spec *responseSpec, correlation string, hasCorrelation, goodbye bool,
) ([]map[string]string, error) {
	// A Disconnect that began while the line was inside the middleware has
	// said goodbye already: what was handed on afterwards is not written.
	if !goodbye && c.connectedHandler() != h {
		return nil, teamspeak.ErrNotConnected
	}
	rc, ch := c.cmdTrack.register(spec, correlation, hasCorrelation)
	defer c.cmdTrack.unregister(rc)
	if spec != nil && spec.Correlated != nil && spec.Correlated.Key == "return_code" {
		c.cmdTrack.setCorrelation(rc, strconv.FormatUint(uint64(rc), 10))
	}

	// The name and code only: the full command carries password hashes the
	// server accepts as passwords, and privilege keys.
	c.logger.DebugContext(ctx, "sending command",
		slog.String("command", parsed.Name), slog.Uint64("return_code", uint64(rc)))

	err := c.sendLine(h, fmt.Sprintf("%s return_code=%d", cmd, rc))
	if err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		if res.Err == nil {
			c.noteRename(parsed)
		}

		return res.Data, res.Err
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", parsed.Name, ctx.Err())
	}
}

// noteRename makes a nickname the server accepted in this client's own
// clientupdate the one it asks for on every reconnection.
func (c *Client) noteRename(cmd *wire.Command) {
	if cmd.Name != "clientupdate" {
		return
	}
	nickname, ok := cmd.Params["client_nickname"]
	if !ok {
		return
	}
	c.mu.Lock()
	c.requestedNickname = nickname
	c.mu.Unlock()
}

// handleVoicePacket parses an incoming voice or whisper packet and hands it to
// the voice receivers. Voice is not an event: it never enters the event queue.
//
// Server-to-client layout differs from what the client sends: the server
// prepends the speaker's client ID, so the payload is
// [voiceID: u16][speakerID: u16][codec: u8][audio...]. Whisper target lists are
// not echoed back.
//
// A packet with no audio is how a speaker's end of speech arrives: the server
// relays the empty frame a client sends when it stops talking, and it is
// delivered to receivers with empty Data. Measured on TeamSpeak 3 3.13.8 and
// TeamSpeak 6 6.0.0: the frames of SendVoice arrive as 45-byte packets and an
// empty one as a 5-byte packet.
func (c *Client) handleVoicePacket(p *transport.Packet) {
	if len(p.Data) < 5 {
		return
	}

	// Audio arrives fifty times a second per speaker; do nothing when no
	// receiver wants it.
	if !c.hasVoiceReceivers() {
		return
	}

	c.mu.Lock()
	selfID := c.clid
	session := c.session
	c.mu.Unlock()

	speakerID := teamspeak.ClientID(binary.BigEndian.Uint16(p.Data[2:4]))
	if speakerID == selfID {
		return
	}

	c.deliverVoice(p, session, speakerID)
}
