package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

var (
	errCommandTimed = errors.New("command timeout")
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
// the newest — was wrong whenever two were in flight: a command is registered
// before it waits on the throttle, so one not yet sent took the rows of one
// already answered.
//
// A nameless row always belongs to the command. A notification row belongs to
// it only if the command declared that notification as its answer (see
// commands.Response): the same notifyclientmoved that answers nothing can
// arrive between any two commands.
//
// The welcome sequence is the exception. The server pushes channellist,
// channelgrouplist and the rest unprompted right after the handshake, before
// channellistfinished; without the gate they would land in the first command's
// answer as duplicate rows and a phantom cid=0.
type commandTracker struct {
	pending         map[uint32]*pendingCommand
	buffer          []bufferedRow
	mu              sync.Mutex
	nextRC          uint32
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
	rc := atomic.AddUint32(&t.nextRC, 1)
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
		c := p.spec.Correlated
		if c == nil || !p.hasCorrelation || !slices.Contains(c.Notifications, name) {
			continue
		}
		if params[c.Key] != p.correlation {
			continue
		}

		if name == c.Failure && params["status"] != "" && params["status"] != "0" {
			t.settleLocked(rc, p, commandResult{Err: &teamspeak.ServerError{
				Code: parseCode(params["status"]), Message: params["msg"], ExtraMessage: params["extra_msg"],
			}})

			return
		}
		p.correlated = append(p.correlated, params)
		if p.settled != nil {
			t.settleLocked(rc, p, commandResult{Data: append(p.settled.Data, p.correlated...)})
		}

		return
	}
}

// resolve hands the rows held since the previous error to command rc.
// ownClientID filters answers that keep only the rows this client invoked.
func (t *commandTracker) resolve(rc uint32, err error, ownClientID uint16) {
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
		if answers(p.spec, row, own) {
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

func answers(spec *responseSpec, row bufferedRow, ownClientID string) bool {
	if row.source == "" {
		return true
	}
	if !spec.isInline(row.source) {
		return false
	}

	return !spec.OwnRowsOnly || row.params["invokerid"] == ownClientID
}

// settleLocked delivers a command's result exactly once. The channel has room
// for that one value, so the send cannot block while the lock is held.
func (t *commandTracker) settleLocked(rc uint32, p *pendingCommand, result commandResult) {
	delete(t.pending, rc)
	p.result <- result
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

func (c *Client) handlePacket(p *transport.Packet) {
	c.logger.Debug("received packet", slog.Uint64("type", uint64(p.Type())), slog.Int("length", len(p.Data)))
	switch p.Type() {
	case transport.PacketTypeInit1:
		c.logger.Debug("processing init1 packet")
		response := handshake.ProcessInit1(c.crypt, p.Data)
		if response != nil {
			c.logger.Debug("sending init1 response")
			err := c.handler.SendPacket(byte(transport.PacketTypeInit1), response, 0)
			if err != nil {
				c.logger.Warn("failed to send init1 response", slog.Any("error", err))
			}
		}
	case transport.PacketTypeCommand, transport.PacketTypeCommandLow:
		if len(p.Data) == 0 {
			return
		}
		dataStr := string(p.Data)
		c.logger.Debug("received command data", slog.String("data", dataStr))
		c.handleCommandLines(dataStr)
	case transport.PacketTypeVoice, transport.PacketTypeVoiceWhisper:
		c.handleVoicePacket(p)
	case transport.PacketTypePing, transport.PacketTypePong, transport.PacketTypeAck, transport.PacketTypeAckLow:
		return
	}
}

func (c *Client) handleCommandLines(s string) {
	if s == "" {
		return
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' || s[i] == 0x00 {
			part := strings.TrimSuffix(s[start:i], "\r")
			if part != "" {
				rows := splitCommandRows(part)
				for _, row := range rows {
					c.handleCommand(row)
				}
			}
			start = i + 1
		}
	}
}

func (c *Client) handleCommand(s string) {
	cmd := commands.ParseCommand(s)
	if cmd == nil {
		return
	}

	c.logger.Debug("processing command", slog.String("name", cmd.Name), slog.Any("params", cmd.Params))

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
		c.cmdTrack.signalWelcomeComplete()

		return
	}

	if strings.HasPrefix(cmd.Name, "notify") {
		// Some commands are answered by a notification instead of data rows.
		// It still goes on to be dispatched as an event, since the same
		// notification also arrives unprompted.
		if c.cmdTrack.expects(cmd.Name) {
			c.cmdTrack.collect(cmd.Params, cmd.Name)
			c.cmdTrack.offerCorrelated(cmd.Name, cmd.Params)
		}
		c.handleNotification(cmd)

		return
	}

	switch cmd.Name {
	case "clientinitiv":
		c.handleHandshakeInitIV(cmd)
	case "initivexpand2":
		c.handleHandshakeExpand2(cmd)
	case "initserver":
		c.handleInitServer(cmd)
	case "error":
		c.handleError(cmd)
	default:
		// A named command the SDK does not model. Held under its own name, so
		// it answers a command only if that command declared it — not merely
		// by arriving while one is in flight.
		c.cmdTrack.collect(cmd.Params, cmd.Name)
		c.logger.Debug("unhandled or data command", slog.String("name", cmd.Name), slog.Any("params", cmd.Params))
	}
}

func (c *Client) handleError(cmd *commands.Command) {
	rcStr := cmd.Params["return_code"]

	var err error
	serverErr := parseServerError(cmd.Params)
	if serverErr != nil {
		err = serverErr
		// Debug, not Error: the error goes back to whoever sent the command,
		// and logging it as well reported every refusal twice.
		c.logger.Debug("server refused a command",
			slog.Uint64("code", uint64(serverErr.Code)), slog.String("message", serverErr.Message))

		if serverErr.Code == errcode.ConnectFailedBanned {
			c.logger.Warn("banned by the server, closing the connection")
			go func() {
				disconnectErr := c.Disconnect()
				if disconnectErr != nil {
					c.logger.Warn("disconnect after fatal error failed", slog.Any("error", disconnectErr))
				}
			}()
		}
	}

	if rcStr != "" {
		rc, parseErr := strconv.ParseUint(rcStr, 10, 32)
		if parseErr == nil {
			c.cmdTrack.resolve(uint32(rc), err, c.ClientID())
		}
	}

	// A server error before the handshake completed is the connection failure
	// itself: a rejected password, or an invalid clientinit parameter.
	// failConnection is a no-op once connected.
	if err != nil {
		c.failConnection(err)
	}
}

// SendCommandNoWait sends a command without waiting for return_code.
func (c *Client) SendCommandNoWait(cmd string) error {
	err := c.throttle.wait(context.Background())
	if err != nil {
		return err
	}
	c.logger.Debug("sending command without waiting", slog.String("raw", cmd))

	return c.finalCmdHandler(cmd)
}

// ExecCommand sends a command and waits for its return_code response.
func (c *Client) ExecCommand(cmd string, timeout time.Duration) error {
	_, err := c.ExecCommandWithResponse(cmd, timeout)

	return err
}

// defaultCommandTimeout is how long a command waits for its answer when the
// caller's context sets no deadline.
const defaultCommandTimeout = 10 * time.Second

// Send executes a typed command; it is the Executor the embedded Commands run
// on.
//
// Channel passwords are hashed here because that is this protocol's rule: the
// voice protocol expects base64(sha1(password)), where ServerQuery takes the
// password itself. Without a deadline on ctx the command gives up after
// defaultCommandTimeout, since an answer that never comes would otherwise hold
// the caller forever.
func (c *Client) Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	return c.send(ctx, req.Encode(prepareClientPassword))
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

// ExecCommandWithResponse sends a command and waits for its return_code response and data.
func (c *Client) ExecCommandWithResponse(cmd string, timeout time.Duration) ([]map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return c.execWithResponse(ctx, cmd)
}

// execWithResponse sends a raw command and waits, until ctx is done, for the
// answer the tracker pairs with it.
func (c *Client) execWithResponse(ctx context.Context, cmd string) ([]map[string]string, error) {
	// A command sent on no socket used to vanish and surface later as a
	// timeout, which reads like a slow server rather than a usage error.
	if !c.handler.IsOpen() {
		return nil, teamspeak.ErrNotConnected
	}

	parsed := commands.ParseCommand(cmd)
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

	// Which notifications answer this command, and — for answers that arrive
	// after the error — the request field they echo back.
	spec := responseFor(parsed.Name)
	var correlation string
	var hasCorrelation bool
	if spec != nil && spec.Correlated != nil {
		correlation, hasCorrelation = parsed.Params[spec.Correlated.Key]
	}

	rc, ch := c.cmdTrack.register(spec, correlation, hasCorrelation)
	defer c.cmdTrack.unregister(rc)

	// The name and code only: the full command carries password hashes the
	// server accepts as passwords, and privilege keys.
	c.logger.DebugContext(ctx, "sending command",
		slog.String("command", parsed.Name), slog.Uint64("return_code", uint64(rc)))

	err := c.throttle.wait(ctx)
	if err != nil {
		return nil, err
	}

	err = c.finalCmdHandler(fmt.Sprintf("%s return_code=%d", cmd, rc))
	if err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		return res.Data, res.Err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %s: %w", errCommandTimed, parsed.Name, ctx.Err())
	}
}

// handleVoicePacket parses an incoming voice or whisper packet and dispatches a
// VoiceData event.
//
// Server-to-client layout differs from what the client sends: the server
// prepends the speaker's client ID, so the payload is
// [voiceID: u16][speakerID: u16][codec: u8][audio...]. Whisper target lists are
// not echoed back.
func (c *Client) handleVoicePacket(p *transport.Packet) {
	if len(p.Data) < 6 {
		return
	}

	c.mu.Lock()
	handlers := c.voiceDataHandlers
	selfID := c.clid
	c.mu.Unlock()

	if len(handlers) == 0 {
		return
	}

	speakerID := binary.BigEndian.Uint16(p.Data[2:4])
	if speakerID == selfID {
		return
	}

	vd := VoiceData{
		ClientID: speakerID,
		Codec:    p.Data[4],
		Data:     append([]byte(nil), p.Data[5:]...),
	}

	c.finalEvtHandler(vd)
}

// parseServerError reads an error line, returning nil for success.
func parseServerError(params map[string]string) *teamspeak.ServerError {
	code := parseCode(params["id"])
	if code == errcode.OK {
		return nil
	}
	failedPermID, _ := strconv.ParseUint(params["failed_permid"], 10, 64)

	return &teamspeak.ServerError{
		Code:         code,
		Message:      params["msg"],
		ExtraMessage: params["extra_msg"],
		FailedPermID: failedPermID,
	}
}

// parseCode reads an error id. One that is missing or unreadable is reported
// as errcode.Undefined: an error line that does not say what went wrong has
// still not said that nothing did.
func parseCode(raw string) errcode.Code {
	code, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return errcode.Undefined
	}

	return errcode.Code(code)
}
