package client

import (
	"context"
	"encoding/binary"
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
// the newest — was wrong whenever two were in flight: a command is registered
// before it waits on the throttle, so one not yet sent took the rows of one
// already answered.
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
	pending         map[uint32]*pendingCommand
	buffer          []bufferedRow
	mu              sync.Mutex
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

		return
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
func (c *Client) handleInit1(h *transport.PacketHandler, data []byte) {
	if h.TsCrypt.InitComplete() {
		return
	}
	response, err := handshake.ProcessInit1(h.TsCrypt, data)
	if err != nil {
		c.failHandshake(h, err)

		return
	}
	if response == nil {
		c.logger.Debug("ignoring a second RSA challenge")

		return
	}
	err = h.SendPacket(byte(transport.PacketTypeInit1), response, 0)
	if err != nil {
		c.logger.Warn("failed to send init1 response", slog.Any("error", err))
	}
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
	c.logger.Error("handshake failed", slog.Any("error", err))
	c.failConnectionLocked(fmt.Errorf("%w: %w", ErrHandshake, err))
}

func (c *Client) handleCommandLines(h *transport.PacketHandler, s string) {
	if s == "" {
		return
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' || s[i] == 0x00 {
			part := strings.TrimSuffix(s[start:i], "\r")
			if part != "" {
				rows := wire.SplitRows(part)
				for _, row := range rows {
					c.handleCommand(h, row)
				}
			}
			start = i + 1
		}
	}
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
	if c.onNotification.any() || len(c.eventMiddlewares) > 0 {
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
			go c.disconnectBanned(h)
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
	disconnectErr := c.disconnect(context.Background(), h)
	if disconnectErr != nil {
		c.logger.Warn("disconnect after fatal error failed", slog.Any("error", disconnectErr))
	}
}

// ExecNoWait sends a raw command line without waiting for an answer, for the
// few commands the server answers with nothing at all. Like Exec, it sends the
// line as given. ctx bounds only the wait for the flood throttle. Without an
// open connection it returns teamspeak.ErrNotConnected.
func (c *Client) ExecNoWait(ctx context.Context, cmd string) error {
	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}
	err := c.throttle.wait(ctx)
	if err != nil {
		return err
	}
	c.logger.DebugContext(ctx, "sending command without waiting", slog.String("command", commandName(cmd)))

	return c.sendLine(h, cmd)
}

// Exec sends a raw command line and returns the rows that answer it: the
// escape hatch for a command the typed methods do not cover; the commands
// package names commands and escapes values. The line is sent as given, so its
// values must already be escaped (commands.Escape) and any channel password
// already hashed.
//
// Without a deadline on ctx the command gives up after ten seconds.
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
	h := c.connectedHandler()
	if h == nil {
		return nil, teamspeak.ErrNotConnected
	}

	return c.execOn(ctx, h, cmd)
}

// execOn sends a raw command on h and waits, until ctx is done, for its
// answer.
func (c *Client) execOn(ctx context.Context, h *transport.PacketHandler, cmd string) ([]map[string]string, error) {
	if !h.IsOpen() {
		return nil, teamspeak.ErrNotConnected
	}

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

	err = c.sendLine(h, fmt.Sprintf("%s return_code=%d", cmd, rc))
	if err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		return res.Data, res.Err
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", parsed.Name, ctx.Err())
	}
}

// handleVoicePacket parses an incoming voice or whisper packet and dispatches a
// VoiceDataEvent event.
//
// Server-to-client layout differs from what the client sends: the server
// prepends the speaker's client ID, so the payload is
// [voiceID: u16][speakerID: u16][codec: u8][audio...]. Whisper target lists are
// not echoed back.
func (c *Client) handleVoicePacket(p *transport.Packet) {
	if len(p.Data) < 6 {
		return
	}

	// Audio arrives fifty times a second per speaker; build no event nobody
	// will see.
	if !c.onVoiceData.any() && len(c.eventMiddlewares) == 0 {
		return
	}

	c.mu.Lock()
	selfID := c.clid
	c.mu.Unlock()

	speakerID := teamspeak.ClientID(binary.BigEndian.Uint16(p.Data[2:4]))
	if speakerID == selfID {
		return
	}

	vd := VoiceDataEvent{
		ClientID: speakerID,
		Codec:    teamspeak.Codec(p.Data[4]),
		Data:     append([]byte(nil), p.Data[5:]...),
	}

	c.emitEvent(vd)
}

// commandName is the name a command line starts with: what the log may say
// about a command whose parameters can carry secrets.
func commandName(cmd string) string {
	name, _, _ := strings.Cut(cmd, " ")

	return name
}
