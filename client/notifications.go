package client

import (
	"log/slog"
	"slices"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// Reading a notification into its event lives in internal/servernotify, which
// the ServerQuery client uses too. What is here is the state a notification
// changes: the client list, which clid is ours, and whether a leave answers
// this client's own Disconnect — none of which the other client has.

func (c *Client) handleNotification(h *transport.PacketHandler, cmd *wire.Command) {
	switch cmd.Name {
	case "notifycliententerview":
		c.handleClientEnterView(h, cmd)
	case "notifyclientleftview":
		c.handleClientLeftView(h, cmd)
	case "notifyclientmoved":
		c.handleClientMoved(h, cmd)
	case "notifytextmessage":
		c.handleTextMessage(cmd)
	case "notifyclientpoke":
		c.handleClientPoke(cmd)
	case "notifyclientneededpermissions":
		c.logger.Debug("insufficient permissions",
			slog.String("permid", cmd.Params["permid"]),
			slog.String("permvalue", cmd.Params["permvalue"]))
	default:
		c.logger.Debug("unhandled notification", slog.String("name", cmd.Name))
	}
}

func (c *Client) handleClientEnterView(h *transport.PacketHandler, cmd *wire.Command) {
	info := servernotify.ClientEnter(cmd.Params)
	if info.ID == 0 {
		return
	}

	c.mu.Lock()
	if c.handler != h {
		c.mu.Unlock()

		return
	}
	c.clients[info.ID] = info
	// Identify self by the clid initserver assigned, never by nickname alone:
	// another client whose nickname is "<our nick><digits>" (the server's
	// rename for a taken nickname) would otherwise be mistaken for us,
	// poisoning every outgoing packet header with a foreign clientID until
	// the server drops the connection for command-resend timeout.
	switch {
	case info.ID == c.clid:
		// Carries the rename the server applied if our nickname was taken.
		c.nickname = info.Nickname
	case c.clid == 0 && isAutoNicknameMatch(c.nickname, info.Nickname):
		// initserver carried no aclid, so the welcome enter is the only way
		// to learn our clid. Once known, a later lookalike cannot take over.
		c.clid = info.ID
		h.SetClientID(uint16(info.ID))
		c.nickname = info.Nickname
	}
	c.mu.Unlock()

	// The event's groups are its own: the last handler gets the event
	// itself, and must not be able to edit the client list through it.
	info.ServerGroups = slices.Clone(info.ServerGroups)
	c.emitEvent(ClientEnterEvent{ClientEntry: info})
}

func (c *Client) handleClientLeftView(h *transport.PacketHandler, cmd *wire.Command) {
	evt := servernotify.ClientLeave(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	// Under the lock with the state it changes: a late notification from a
	// replaced connection must not edit the next one's client list, or be
	// taken for this client leaving.
	if c.handler != h {
		c.mu.Unlock()

		return
	}
	isSelf := evt.ClientID == c.clid
	delete(c.clients, evt.ClientID)
	// This client leaving while a Disconnect waits is the answer to its
	// goodbye, not the server removing it.
	answersGoodbye := isSelf && c.goodbye != nil
	if answersGoodbye {
		close(c.goodbye)
		c.goodbye = nil
	}
	c.mu.Unlock()

	c.emitEvent(evt)

	if !isSelf || answersGoodbye {
		return
	}
	if evt.Reason == teamspeak.ReasonKickServer || evt.Reason == teamspeak.ReasonKickServerBan {
		emit(c, &c.onKicked, "KickedEvent", servernotify.Kicked(evt.Reason, cmd.Params))
	}
	c.removedByServer(h, &RemovedError{ReasonMessage: evt.ReasonMessage, InvokerName: evt.InvokerName, Reason: evt.Reason})
}

// removedByServer ends the session h ran, which the server has ended. The
// server stops answering a client it has removed, so waiting for the transport
// to notice reported the end a minute late, without its cause, and with the
// client claiming to be connected meanwhile.
func (c *Client) removedByServer(h *transport.PacketHandler, cause error) {
	c.handleConnectionClosed(h, cause)
	_ = h.Close()
}

func (c *Client) handleClientMoved(h *transport.PacketHandler, cmd *wire.Command) {
	evt := servernotify.ClientMoved(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	if c.handler != h {
		c.mu.Unlock()

		return
	}
	if info, ok := c.clients[evt.ClientID]; ok {
		info.ChannelID = evt.TargetChannelID
		c.clients[evt.ClientID] = info
	}
	isSelf := evt.ClientID == c.clid
	c.mu.Unlock()

	c.emitEvent(evt)

	// A channel kick moves the client to the default channel; it arrives as
	// a move, not as leaving view, which is where it used to be looked for.
	if isSelf && evt.Reason == teamspeak.ReasonKickChannel {
		emit(c, &c.onKicked, "KickedEvent", servernotify.Kicked(evt.Reason, cmd.Params))
	}
}

func (c *Client) handleTextMessage(cmd *wire.Command) {
	msg := servernotify.TextMessage(cmd.Params)

	c.mu.Lock()
	if info, ok := c.clients[msg.InvokerID]; ok {
		if msg.InvokerUID == "" {
			msg.InvokerUID = info.UID
		}
		msg.InvokerGroups = slices.Clone(info.ServerGroups)
	}
	c.mu.Unlock()

	// Not the message itself: a message body is the sender's, not the log's.
	c.logger.Debug("text message received",
		slog.String("target_mode", msg.TargetMode.String()),
		slog.Uint64("invoker_id", uint64(msg.InvokerID)))

	c.emitEvent(msg)
}

func (c *Client) handleClientPoke(cmd *wire.Command) {
	evt := PokeEvent{
		InvokerID:   servernotify.ParseClientID(cmd.Params["invokerid"]),
		InvokerName: cmd.Params["invokername"],
		InvokerUID:  teamspeak.UID(cmd.Params["invokeruid"]),
		Message:     cmd.Params["msg"],
	}

	c.logger.Debug("client poked", slog.Uint64("invoker_id", uint64(evt.InvokerID)))

	c.emitEvent(evt)
}
