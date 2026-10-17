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
	case "notifyclientupdated":
		c.handleClientUpdated(h, cmd)
	case "notifyservergroupclientadded":
		c.emitEvent(ClientServerGroupAddedEvent{ClientServerGroupChange: servernotify.ClientServerGroup(cmd.Params)})
	case "notifyservergroupclientdeleted":
		c.emitEvent(ClientServerGroupRemovedEvent{ClientServerGroupChange: servernotify.ClientServerGroup(cmd.Params)})
	case "notifyclientchannelgroupchanged":
		c.handleClientChannelGroupChanged(h, cmd)
	case "notifyconnectioninforequest":
		c.answerConnectionInfoRequest(h)
	case "notifyclientneededpermissions":
		c.logger.Debug("insufficient permissions",
			slog.String("permid", cmd.Params["permid"]),
			slog.String("permvalue", cmd.Params["permvalue"]))
	default:
		if !c.handleChannelNotification(cmd) {
			c.logger.Debug("unhandled notification", slog.String("name", cmd.Name))
		}
	}
}

// handleChannelNotification reports the channel, server, subscription and
// plugin notifications, none of which changes state the client keeps. It
// returns false for any other.
func (c *Client) handleChannelNotification(cmd *wire.Command) bool {
	switch cmd.Name {
	case "notifychannelcreated":
		if evt, ok := servernotify.ChannelCreated(cmd.Params); ok {
			c.emitEvent(evt)
		}
	case "notifychanneledited":
		// Not the answer to channelgetdescription, which is no edit; see
		// servernotify.ChannelEdited.
		if evt, ok := servernotify.ChannelEdited(cmd.Params); ok {
			c.emitEvent(evt)
		}
	case "notifychannelmoved":
		if evt, ok := servernotify.ChannelMoved(cmd.Params); ok {
			c.emitEvent(evt)
		}
	case "notifychanneldeleted":
		if evt, ok := servernotify.ChannelDeleted(cmd.Params); ok {
			c.emitEvent(evt)
		}
	case "notifychanneldescriptionchanged":
		c.emitForChannel(cmd, func(id teamspeak.ChannelID) Event { return ChannelDescriptionChangedEvent{ChannelID: id} })
	case "notifychannelpasswordchanged":
		c.emitForChannel(cmd, func(id teamspeak.ChannelID) Event { return ChannelPasswordChangedEvent{ChannelID: id} })
	default:
		return c.handleServerNotification(cmd)
	}

	return true
}

// handleServerNotification reports the server, subscription, plugin command and
// typing notifications. It returns false for any other.
func (c *Client) handleServerNotification(cmd *wire.Command) bool {
	switch cmd.Name {
	case "notifyserveredited":
		c.emitEvent(servernotify.ServerEdited(cmd.Params))
	case "notifychannelsubscribed":
		c.emitForChannel(cmd, func(id teamspeak.ChannelID) Event { return ChannelSubscribedEvent{ChannelID: id} })
	case "notifychannelunsubscribed":
		c.emitForChannel(cmd, func(id teamspeak.ChannelID) Event { return ChannelUnsubscribedEvent{ChannelID: id} })
	case "notifyplugincmd":
		c.emitEvent(servernotify.PluginCommand(cmd.Params))
	case "notifyclientchatcomposing":
		if evt, ok := servernotify.ClientChatComposing(cmd.Params); ok {
			c.emitEvent(evt)
		}
	default:
		return false
	}

	return true
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

	// The event's record is its own: the last handler gets the event itself,
	// and must not be able to edit the client list through it.
	c.emitEvent(ClientEnterEvent{ClientEntry: info.Clone()})
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

// handleClientUpdated applies an update to what the client knows of the client
// it names, and then reports it. It is the only writer of a client's server
// groups: the update carries the complete list, whereas the notifications that
// name the group (and arrive before or after it, as the server pleases) carry
// one group and would need a rule for merging.
func (c *Client) handleClientUpdated(h *transport.PacketHandler, cmd *wire.Command) {
	evt := servernotify.ClientUpdated(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	if c.handler != h {
		c.mu.Unlock()

		return
	}
	// A client not in view is not added: an entry needs the uid and channel an
	// update does not carry. Apply returns a record of its own, so the event's
	// Changes and the client list share nothing.
	if info, ok := c.clients[evt.ClientID]; ok {
		c.clients[evt.ClientID] = evt.Changes.Apply(info)
	}
	if evt.ClientID == c.clid && evt.Changes.Nickname != nil {
		c.nickname = *evt.Changes.Nickname
	}
	c.mu.Unlock()

	c.emitEvent(evt)
}

// handleClientChannelGroupChanged refreshes the channel group the client knows
// of the client, which no update carries and a move leaves behind. The group
// is per channel, so an event about a channel the client is not in is not its
// group here.
func (c *Client) handleClientChannelGroupChanged(h *transport.PacketHandler, cmd *wire.Command) {
	evt := servernotify.ClientChannelGroupChanged(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	if c.handler != h {
		c.mu.Unlock()

		return
	}
	if info, ok := c.clients[evt.ClientID]; ok && info.ChannelID == evt.ChannelID {
		info.ChannelGroupID = evt.ChannelGroupID
		info.ChannelGroupInheritedChannelID = evt.ChannelGroupInheritedChannelID
		c.clients[evt.ClientID] = info
	}
	c.mu.Unlock()

	c.emitEvent(evt)
}

// emitForChannel queues the event build makes of the channel cmd names; a
// notification that names none describes nothing.
func (c *Client) emitForChannel(cmd *wire.Command, build func(teamspeak.ChannelID) Event) {
	if id := servernotify.ParseChannelID(cmd.Params["cid"]); id != 0 {
		c.emitEvent(build(id))
	}
}
