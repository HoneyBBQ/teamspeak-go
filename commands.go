package teamspeak

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/handshake"
	"github.com/honeybbq/teamspeak-go/transport"
)

var (
	errTeamSpeakCommand = errors.New("TeamSpeak server error")
	errCommandTimed     = errors.New("command timeout")
)

type commandResult struct {
	Err  error
	Data []map[string]string
}

// commandTracker matches return_code values to pending commands and response rows.
type commandTracker struct {
	pending    map[uint32]chan commandResult
	collecting map[uint32][]map[string]string
	mu         sync.Mutex
	nextRC     uint32
	// welcomeComplete is set by channellistfinished, which ends the server's
	// unprompted welcome sequence. It is NOT set by our own
	// notifycliententerview: the server sends more welcome data after that.
	welcomeComplete bool
}

func newCommandTracker() *commandTracker {
	return &commandTracker{
		pending:    make(map[uint32]chan commandResult),
		collecting: make(map[uint32][]map[string]string),
	}
}

// newReadyCommandTracker returns a tracker past the welcome sequence, for tests
// that exercise collection without a handshake.
func newReadyCommandTracker() *commandTracker {
	t := newCommandTracker()
	t.welcomeComplete = true

	return t
}

func (t *commandTracker) register() (uint32, <-chan commandResult) {
	rc := atomic.AddUint32(&t.nextRC, 1)
	ch := make(chan commandResult, 1)
	t.mu.Lock()
	t.pending[rc] = ch
	t.mu.Unlock()

	return rc, ch
}

func (t *commandTracker) unregister(rc uint32) {
	t.mu.Lock()
	delete(t.pending, rc)
	t.mu.Unlock()
}

// collect appends a parameter row to the pending command with the largest return_code.
//
// Rows arriving before the welcome sequence ends are dropped: the server sends
// its own channellist, channelgrouplist and so on unprompted, and without this
// they land in the first command's response. That is how a client that asks for
// channellist immediately after connecting used to get duplicate rows and a
// phantom cid=0.
func (t *commandTracker) collect(params map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.welcomeComplete {
		return
	}

	var maxRC uint32
	for rc := range t.pending {
		if rc > maxRC {
			maxRC = rc
		}
	}
	if maxRC > 0 {
		t.collecting[maxRC] = append(t.collecting[maxRC], params)
	}
}

func (t *commandTracker) resolve(rc uint32, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch, ok := t.pending[rc]; ok {
		data := t.collecting[rc]
		delete(t.collecting, rc)
		ch <- commandResult{Data: data, Err: err}
	}
}

// signalWelcomeComplete marks the end of the server's welcome sequence and
// discards whatever was buffered while it was still arriving.
func (t *commandTracker) signalWelcomeComplete() {
	t.mu.Lock()
	t.welcomeComplete = true
	t.collecting = make(map[uint32][]map[string]string)
	t.mu.Unlock()
}

func (t *commandTracker) reset() {
	t.mu.Lock()
	t.pending = make(map[uint32]chan commandResult)
	t.collecting = make(map[uint32][]map[string]string)
	t.welcomeComplete = false
	t.mu.Unlock()
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
			c.cmdTrack.collect(cmd.Params)
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
		// A command the SDK does not model, carrying its own data rows.
		c.cmdTrack.collect(cmd.Params)
		c.logger.Debug("unhandled or data command", slog.String("name", cmd.Name), slog.Any("params", cmd.Params))
	}
}

func (c *Client) handleError(cmd *commands.Command) {
	id := cmd.Params["id"]
	msg := cmd.Params["msg"]
	rcStr := cmd.Params["return_code"]

	var err error
	if id != "0" {
		err = fmt.Errorf("%w: %s (id=%s)", errTeamSpeakCommand, msg, id)
		c.logger.Error("server returned error", slog.String("id", id), slog.String("message", msg))

		if id == "3329" {
			c.logger.Warn("fatal connection error detected, closing connection", slog.String("id", id))
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
			c.cmdTrack.resolve(uint32(rc), err)
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

// ExecCommandWithResponse sends a command and waits for its return_code response and data.
func (c *Client) ExecCommandWithResponse(cmd string, timeout time.Duration) ([]map[string]string, error) {
	rc, ch := c.cmdTrack.register()
	defer c.cmdTrack.unregister(rc)

	withReturnCode := cmd
	if !strings.Contains(cmd, "return_code=") {
		withReturnCode = fmt.Sprintf("%s return_code=%d", cmd, rc)
	}

	c.logger.Debug("sending command", slog.String("raw", withReturnCode))

	err := c.throttle.wait(context.Background())
	if err != nil {
		return nil, err
	}

	err = c.finalCmdHandler(withReturnCode)
	if err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		return res.Data, res.Err
	case <-time.After(timeout):
		return nil, fmt.Errorf("%w: %s", errCommandTimed, cmd)
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
