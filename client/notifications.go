package client

import (
	"log/slog"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
)

func (c *Client) handleNotification(cmd *commands.Command) {
	switch cmd.Name {
	case "notifycliententerview":
		c.handleClientEnterView(cmd)
	case "notifyclientleftview":
		c.handleClientLeftView(cmd)
	case "notifyclientmoved":
		c.handleClientMoved(cmd)
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

func (c *Client) handleClientEnterView(cmd *commands.Command) {
	nick := cmd.Params["client_nickname"]
	uid := cmd.Params["client_unique_identifier"]
	groupsStr := cmd.Params["client_servergroups"]

	clid, _ := parseUint16Value(cmd.Params["clid"])
	ctid, _ := parseUint64Value(cmd.Params["ctid"])
	clientType, _ := parseIntValue(cmd.Params["client_type"])

	if clid != 0 {
		info := teamspeak.ClientInfo{
			ID:           clid,
			Nickname:     nick,
			UID:          uid,
			ChannelID:    ctid,
			Type:         clientType,
			ServerGroups: parseUint64List(groupsStr),
		}

		c.mu.Lock()
		c.clients[clid] = info
		// Identify self by the clid initserver assigned, never by nickname alone:
		// another client whose nickname is "<our nick><digits>" (the server's
		// rename for a taken nickname) would otherwise be mistaken for us,
		// poisoning every outgoing packet header with a foreign clientID until
		// the server drops the connection for command-resend timeout.
		switch {
		case clid == c.clid:
			// Carries the rename the server applied if our nickname was taken.
			c.nickname = nick
		case c.clid == 0 && isAutoNicknameMatch(c.nickname, nick):
			// initserver carried no aclid, so the welcome enter is the only way
			// to learn our clid. Once known, a later lookalike cannot take over.
			c.clid = clid
			c.handler.SetClientID(clid)
			c.nickname = nick
		}
		c.mu.Unlock()

		c.emitEvent(info)
	}
}

func (c *Client) handleClientLeftView(cmd *commands.Command) {
	clid, _ := parseUint16Value(cmd.Params["clid"])
	if clid == 0 {
		return
	}
	reasonID, _ := parseIntValue(cmd.Params["reasonid"])
	invokerID, _ := parseUint16Value(cmd.Params["invokerid"])
	evt := ClientLeftViewEvent{
		ID:            clid,
		Reason:        teamspeak.Reason(reasonID),
		ReasonMessage: cmd.Params["reasonmsg"],
		InvokerID:     invokerID,
		InvokerName:   cmd.Params["invokername"],
		InvokerUID:    cmd.Params["invokeruid"],
	}

	c.mu.Lock()
	isSelf := clid == c.clid
	delete(c.clients, clid)
	c.mu.Unlock()

	c.emitEvent(evt)

	if !isSelf {
		return
	}
	if evt.Reason == teamspeak.ReasonKickServer || evt.Reason == teamspeak.ReasonKickServerBan {
		emit(c, &c.onKicked, KickedEvent{
			Message:     evt.ReasonMessage,
			InvokerName: evt.InvokerName,
			InvokerUID:  evt.InvokerUID,
			Reason:      evt.Reason,
			InvokerID:   evt.InvokerID,
		})
	}
	c.removedByServer(&RemovedError{Message: evt.ReasonMessage, InvokerName: evt.InvokerName, Reason: evt.Reason})
}

// removedByServer ends a session the server has ended. The server stops
// answering a client it has removed, so waiting for the transport to notice
// reported the end a minute late, without its cause, and with the client
// claiming to be connected meanwhile.
func (c *Client) removedByServer(cause error) {
	c.handleConnectionClosed(cause)
	_ = c.currentHandler().Close()
}

func (c *Client) handleClientMoved(cmd *commands.Command) {
	clid, _ := parseUint16Value(cmd.Params["clid"])
	ctid, _ := parseUint64Value(cmd.Params["ctid"])
	reasonID, _ := parseIntValue(cmd.Params["reasonid"])
	invokerID, _ := parseUint16Value(cmd.Params["invokerid"])

	if clid == 0 {
		return
	}
	c.mu.Lock()
	if info, ok := c.clients[clid]; ok {
		info.ChannelID = ctid
		c.clients[clid] = info
	}
	isSelf := clid == c.clid
	c.mu.Unlock()

	evt := ClientMovedEvent{
		ID:              clid,
		TargetChannelID: ctid,
		Reason:          teamspeak.Reason(reasonID),
		InvokerID:       invokerID,
		InvokerName:     cmd.Params["invokername"],
		InvokerUID:      cmd.Params["invokeruid"],
	}
	c.emitEvent(evt)

	// A channel kick moves the client to the default channel; it arrives as
	// a move, not as leaving view, which is where it used to be looked for.
	if isSelf && evt.Reason == teamspeak.ReasonKickChannel {
		emit(c, &c.onKicked, KickedEvent{
			Message:     cmd.Params["reasonmsg"],
			InvokerName: evt.InvokerName,
			InvokerUID:  evt.InvokerUID,
			Reason:      evt.Reason,
			InvokerID:   evt.InvokerID,
		})
	}
}

func (c *Client) handleTextMessage(cmd *commands.Command) {
	targetMode, _ := parseIntValue(cmd.Params["targetmode"])
	targetID, _ := parseUint64Value(cmd.Params["target"])
	invokerID, _ := parseUint16Value(cmd.Params["invokerid"])
	msg := TextMessage{
		TargetMode:  targetMode,
		TargetID:    targetID,
		InvokerID:   invokerID,
		InvokerName: cmd.Params["invokername"],
		InvokerUID:  cmd.Params["invokeruid"],
		Message:     cmd.Params["msg"],
	}

	c.mu.Lock()
	if info, ok := c.clients[invokerID]; ok {
		if msg.InvokerUID == "" {
			msg.InvokerUID = info.UID
		}
		msg.InvokerGroups = info.ServerGroups
	}
	c.mu.Unlock()

	c.logger.Debug("text message received",
		slog.Int("target_mode", targetMode),
		slog.String("invoker_id", cmd.Params["invokerid"]),
		slog.String("invoker_name", cmd.Params["invokername"]),
		slog.String("invoker_uid", msg.InvokerUID),
		slog.String("message", cmd.Params["msg"]))

	c.emitEvent(msg)
}

func (c *Client) handleClientPoke(cmd *commands.Command) {
	invokerID, _ := parseUint16Value(cmd.Params["invokerid"])
	evt := PokeEvent{
		InvokerID:   invokerID,
		InvokerName: cmd.Params["invokername"],
		InvokerUID:  cmd.Params["invokeruid"],
		Message:     cmd.Params["msg"],
	}

	c.logger.Debug("client poked",
		slog.String("invoker_name", evt.InvokerName),
		slog.String("invoker_uid", evt.InvokerUID),
		slog.String("message", evt.Message))

	c.emitEvent(evt)
}
