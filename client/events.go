package client

import (
	"maps"
	"slices"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/eventbus"
	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// Event delivery
//
// Handlers run one at a time, in the order their events arrived, on a goroutine
// of the client's own, so a handler may call the client — send a command and
// wait for its answer — without stalling the connection. The queue itself, and
// the rule about a panic in a handler, are shared with the ServerQuery client;
// see internal/eventbus.

// The handlers registered for each event, and the queue they are delivered on.
// The types come from internal/eventbus, which both clients use.
type (
	subscribers[E any] = eventbus.Subscribers[E]
	eventQueue         = eventbus.Queue
)

// OnTextMessage registers a handler for incoming text messages. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnTextMessage(handler func(TextMessageEvent)) func() {
	return c.onTextMessage.Add(handler)
}

// OnClientEnter registers a handler for clients entering view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientEnter(handler func(ClientEnterEvent)) func() {
	return c.onClientEnter.Add(handler)
}

// OnClientLeave registers a handler for clients leaving view. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientLeave(handler func(ClientLeaveEvent)) func() {
	return c.onClientLeave.Add(handler)
}

// OnPoked registers a handler for pokes this client receives. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnPoked(handler func(PokeEvent)) func() {
	return c.onPoked.Add(handler)
}

// OnClientUpdated registers a handler for clients changing their properties:
// nickname, away or mute state, server groups, talk power and the like, this
// client's own included. The event's Changes hold only what changed, and
// ClientChanges.Apply merges them into a ClientEntry. It returns a function
// that removes the handler.
//
// The client has updated what it remembers of the client, so the groups of a
// following TextMessageEvent are current. Only a voice connection hears
// these; ServerQuery clients have no such method.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientUpdated(handler func(ClientUpdatedEvent)) func() {
	return c.onClientUpdated.Add(handler)
}

// OnClientServerGroupAdded registers a handler for a client being added to a
// server group, which names the group and who added it. It returns a function
// that removes the handler.
//
// The client's complete new list of groups arrives as a ClientUpdatedEvent,
// before or after this one.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientServerGroupAdded(handler func(ClientServerGroupAddedEvent)) func() {
	return c.onSGAdded.Add(handler)
}

// OnClientServerGroupRemoved registers a handler for a client being removed
// from a server group. It returns a function that removes the handler.
//
// The client's complete new list of groups arrives as a ClientUpdatedEvent,
// before or after this one.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientServerGroupRemoved(handler func(ClientServerGroupRemovedEvent)) func() {
	return c.onSGRemoved.Add(handler)
}

// OnClientChannelGroupChanged registers a handler for a client's channel group
// changing in a channel, which includes every move of a client, since the
// group is per channel. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientChannelGroupChanged(handler func(ClientChannelGroupChangedEvent)) func() {
	return c.onCGChanged.Add(handler)
}

// OnChannelCreated registers a handler for channels being created. The event's
// Changes hold the properties the server sent, which are those that differ from
// a new channel's defaults; ChannelChanges.Apply merges them into a Channel. It
// returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelCreated(handler func(ChannelCreatedEvent)) func() {
	return c.onChCreated.Add(handler)
}

// OnChannelEdited registers a handler for channels being edited. The event's
// Changes hold only what changed. The answer to GetChannelDescription also
// arrives as a channel edit, with no invoker; it is not a change and produces
// no event. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelEdited(handler func(ChannelEditedEvent)) func() {
	return c.onChEdited.Add(handler)
}

// OnChannelMoved registers a handler for channels being moved under another
// channel or reordered. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelMoved(handler func(ChannelMovedEvent)) func() {
	return c.onChMoved.Add(handler)
}

// OnChannelDeleted registers a handler for channels being deleted, including a
// temporary channel the server deletes once it has emptied. It returns a
// function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelDeleted(handler func(ChannelDeletedEvent)) func() {
	return c.onChDeleted.Add(handler)
}

// OnChannelDescriptionChanged registers a handler for a channel's description
// changing. The event does not carry the text; GetChannelDescription fetches
// it. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelDescriptionChanged(handler func(ChannelDescriptionChangedEvent)) func() {
	return c.onChDescription.Add(handler)
}

// OnChannelPasswordChanged registers a handler for a channel's password being
// set, changed or removed. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelPasswordChanged(handler func(ChannelPasswordChangedEvent)) func() {
	return c.onChPassword.Add(handler)
}

// OnServerEdited registers a handler for the virtual server's settings being
// edited. The event's Changes are the changed properties by their wire names;
// a change of the welcome message names none. It returns a function that
// removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnServerEdited(handler func(ServerEditedEvent)) func() {
	return c.onServerEdited.Add(handler)
}

// OnChannelSubscribed registers a handler for this client being subscribed to a
// channel, by SubscribeChannel, SubscribeAllChannels or the server. Only a voice
// connection has subscriptions; ServerQuery clients have no such method. It
// returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelSubscribed(handler func(ChannelSubscribedEvent)) func() {
	return c.onChSubscribed.Add(handler)
}

// OnChannelUnsubscribed registers a handler for this client no longer being
// subscribed to a channel, by request or because the server withdrew the
// subscription. Unsubscribing from a channel it is not subscribed to sends
// nothing. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnChannelUnsubscribed(handler func(ChannelUnsubscribedEvent)) func() {
	return c.onChUnsubscribed.Add(handler)
}

// OnPluginCommand registers a handler for plugin commands, which Commands.
// SendPluginCommand sends. The sender receives its own command when it was sent
// to its channel or to the server. Only a voice connection hears these;
// ServerQuery clients have no such method. It returns a function that removes
// the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnPluginCommand(handler func(PluginCommandEvent)) func() {
	return c.onPluginCommand.Add(handler)
}

// OnClientChatComposing registers a handler for a client typing a private
// message to this client, which Commands.SendChatComposing sends. Only the
// target is told. Only a voice connection hears it. It returns a function that
// removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientChatComposing(handler func(ClientChatComposingEvent)) func() {
	return c.onChatComposing.Add(handler)
}

// OnClientChatClosed registers a handler for a client closing its private chat
// with this client, which Commands.ClosePrivateChat sends. Only the target is
// told, and only when the closing client has sent it a private message. Only a
// voice connection hears it. It returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientChatClosed(handler func(ClientChatClosedEvent)) func() {
	return c.onChatClosed.Add(handler)
}

// OnKicked registers a handler for this client being kicked from its channel
// or the server. A kick from the server also ends the connection, which
// OnDisconnected reports with a *RemovedError. It returns a function that
// removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnKicked(handler func(KickedEvent)) func() {
	return c.onKicked.Add(handler)
}

// OnClientMoved registers a handler for clients moving between channels. It
// returns a function that removes the handler.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnClientMoved(handler func(ClientMovedEvent)) func() {
	return c.onClientMoved.Add(handler)
}

// OnVoiceData registers a handler for incoming voice or whisper audio. It
// returns a function that removes the handler.
//
// Voice is the one event that can be dropped: when more than 256 deliveries
// of any kind are waiting for the handlers, incoming voice is discarded until
// they catch up, and the client logs a warning, at most once every ten
// seconds, with how much it dropped. Every other event is always delivered.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnVoiceData(handler func(VoiceDataEvent)) func() {
	return c.onVoiceData.Add(handler)
}

// OnNotification registers a handler for every notification the server sends,
// as it arrived: the way to hear one the SDK does not model. It runs after the
// typed handlers for the same notification. It returns a function that removes
// the handler. The notify package names the notifications to match on.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnNotification(handler func(NotificationEvent)) func() {
	return c.onNotification.Add(handler)
}

// OnConnected registers a handler for the handshake completing, on Connect and
// on every reconnection; the event's Reconnected tells them apart. It returns a function that removes the handler.
//
// The event is queued as the handshake completes, when Connect returns nil,
// and delivered on the event goroutine: register the handler before Connect
// to be sure to hear it.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnConnected(handler func(ConnectedEvent)) func() {
	return c.onConnected.Add(handler)
}

// OnDisconnected registers a handler for the connection ending, or a
// connection attempt failing. The event's Err is nil after Disconnect, and the
// cause otherwise: a failed handshake, ErrConnectionTimeout for a server that
// stopped answering, or a *RemovedError for a kick, a ban or a server
// stopping; its WillReconnect says whether the reconnect loop will try again.
// It returns a function that removes the handler.
//
// Disconnect returns once the connection is closed and this event queued;
// the handlers run later, in order. Events go through one ordered queue, and
// a session's disconnected is queued before the next Connect can queue
// anything, so handlers see it before that session's connected and before
// any other event of it. A handler may call Connect and Disconnect.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnDisconnected(handler func(DisconnectedEvent)) func() {
	return c.onDisconnected.Add(handler)
}

// currentHandler returns the packet handler of the current connection.
func (c *Client) currentHandler() *transport.PacketHandler {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.handler
}

// connectedHandler returns the current packet handler if its handshake has
// completed, or nil. Commands and voice go only to a connected session: sent
// mid-handshake they would reach a server that cannot read them yet, under
// the dummy key.
func (c *Client) connectedHandler() *transport.PacketHandler {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.status != StatusConnected {
		return nil
	}

	return c.handler
}

// sendLine sends a command line on h.
func (c *Client) sendLine(h *transport.PacketHandler, line string) error {
	if c.wireHook != nil {
		err := c.wireHook(line)
		if err != nil {
			return err
		}
	}

	return notConnected(h.SendPacket(byte(transport.PacketTypeCommand), []byte(line), 0))
}

// buildMiddlewareChains wraps the typed commands and the event dispatch in
// the configured middleware. It runs once, in New: the chains are read on every
// command and event, so changing them afterwards would race with both.
func (c *Client) buildMiddlewareChains() {
	c.executor = teamspeak.ExecutorFunc(c.sendRequest)
	for _, middleware := range slices.Backward(c.cmdMiddlewares) {
		c.executor = middleware(c.executor)
	}

	c.evtChain = c.dispatchEvent
	for _, middleware := range slices.Backward(c.eventMiddlewares) {
		c.evtChain = middleware(c.evtChain)
	}
}

// emitEvent queues a server event. The middleware runs on the delivery
// goroutine too, so a slow middleware does not stall the read loop either.
func (c *Client) emitEvent(evt Event) {
	run := func() { eventbus.CallHandler(c.logger, eventbus.EventName(evt), func() { c.evtChain(evt) }) }
	if _, voice := evt.(VoiceDataEvent); voice {
		c.events.PushVoice(run, c.logger)

		return
	}
	c.events.Push(run)
}

// emit queues a lifecycle event, which middleware does not see.
func emit[E any](c *Client, subs *subscribers[E], name string, evt E) {
	c.events.Push(func() { subs.Deliver(c.logger, name, evt, nil) })
}

// dispatchEvent hands a server event, as the middleware left it, to its
// handlers.
func (c *Client) dispatchEvent(evt Event) {
	switch e := evt.(type) {
	case TextMessageEvent:
		c.onTextMessage.Deliver(c.logger, eventbus.EventName(e), e, func(m TextMessageEvent) TextMessageEvent {
			m.InvokerGroups = slices.Clone(m.InvokerGroups)

			return m
		})
	case ClientEnterEvent:
		c.onClientEnter.Deliver(c.logger, eventbus.EventName(e), e, func(enter ClientEnterEvent) ClientEnterEvent {
			return enter.Clone()
		})
	case ClientUpdatedEvent:
		c.onClientUpdated.Deliver(c.logger, eventbus.EventName(e), e, func(u ClientUpdatedEvent) ClientUpdatedEvent {
			u.Changes = cloneChanges(u.Changes)

			return u
		})
	case ClientServerGroupAddedEvent:
		c.onSGAdded.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientServerGroupRemovedEvent:
		c.onSGRemoved.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientChannelGroupChangedEvent:
		c.onCGChanged.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientLeaveEvent:
		c.onClientLeave.Deliver(c.logger, eventbus.EventName(e), e, func(v ClientLeaveEvent) ClientLeaveEvent {
			v = servernotify.CloneClientLeave(v)
			if v.Previous != nil {
				v.Previous = new(v.Previous.Clone())
			}

			return v
		})
	case ClientMovedEvent:
		c.onClientMoved.Deliver(c.logger, eventbus.EventName(e), e, servernotify.CloneClientMoved)
	case PokeEvent:
		c.onPoked.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case VoiceDataEvent:
		c.onVoiceData.Deliver(c.logger, eventbus.EventName(e), e, func(v VoiceDataEvent) VoiceDataEvent {
			v.Data = slices.Clone(v.Data)

			return v
		})
	case NotificationEvent:
		c.onNotification.Deliver(c.logger, eventbus.EventName(e), e, func(n NotificationEvent) NotificationEvent {
			n.Params = maps.Clone(n.Params)

			return n
		})
	default:
		c.dispatchChannelEvent(evt)
	}
}

// dispatchChannelEvent hands a channel, server, subscription or plugin event to
// its handlers.
func (c *Client) dispatchChannelEvent(evt Event) {
	switch e := evt.(type) {
	case ChannelCreatedEvent:
		c.onChCreated.Deliver(c.logger, eventbus.EventName(e), e, func(v ChannelCreatedEvent) ChannelCreatedEvent {
			v.Changes = servernotify.CloneChannelChanges(v.Changes)

			return v
		})
	case ChannelEditedEvent:
		c.onChEdited.Deliver(c.logger, eventbus.EventName(e), e, func(v ChannelEditedEvent) ChannelEditedEvent {
			v.Changes = servernotify.CloneChannelChanges(v.Changes)

			return v
		})
	case ChannelMovedEvent:
		c.onChMoved.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ChannelDeletedEvent:
		c.onChDeleted.Deliver(c.logger, eventbus.EventName(e), e, func(v ChannelDeletedEvent) ChannelDeletedEvent {
			if v.Previous != nil {
				v.Previous = new(v.Previous.Clone())
			}

			return v
		})
	case ChannelDescriptionChangedEvent:
		c.onChDescription.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ChannelPasswordChangedEvent:
		c.onChPassword.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ServerEditedEvent:
		c.onServerEdited.Deliver(c.logger, eventbus.EventName(e), e, func(v ServerEditedEvent) ServerEditedEvent {
			v.Changes = maps.Clone(v.Changes)

			return v
		})
	case ChannelSubscribedEvent:
		c.onChSubscribed.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ChannelUnsubscribedEvent:
		c.onChUnsubscribed.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case PluginCommandEvent:
		c.onPluginCommand.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientChatComposingEvent:
		c.onChatComposing.Deliver(c.logger, eventbus.EventName(e), e, nil)
	case ClientChatClosedEvent:
		c.onChatClosed.Deliver(c.logger, eventbus.EventName(e), e, nil)
	}
}

// cloneChanges returns a copy of c that shares no memory with it, so a handler
// editing what it was given cannot change what the next one sees. Every field
// is a pointer; a field added to ClientChanges must be added here, and the
// tests fail until it is.
//
//nolint:funlen // one line per field
func cloneChanges(c teamspeak.ClientChanges) teamspeak.ClientChanges {
	c.Created = clonePtr(c.Created)
	c.LastConnected = clonePtr(c.LastConnected)
	c.IdleTime = clonePtr(c.IdleTime)
	c.Nickname = clonePtr(c.Nickname)
	c.UID = clonePtr(c.UID)
	if c.ServerGroups != nil {
		c.ServerGroups = new(slices.Clone(*c.ServerGroups))
	}
	c.ChannelID = clonePtr(c.ChannelID)
	c.ChannelGroupID = clonePtr(c.ChannelGroupID)
	c.Type = clonePtr(c.Type)
	c.IsAway = clonePtr(c.IsAway)
	c.IsRecording = clonePtr(c.IsRecording)
	c.IsTalker = clonePtr(c.IsTalker)
	c.DatabaseID = clonePtr(c.DatabaseID)
	c.AwayMessage = clonePtr(c.AwayMessage)
	c.IsInputMuted = clonePtr(c.IsInputMuted)
	c.IsOutputMuted = clonePtr(c.IsOutputMuted)
	c.IsOutputOnlyMuted = clonePtr(c.IsOutputOnlyMuted)
	c.HasInputHardware = clonePtr(c.HasInputHardware)
	c.HasOutputHardware = clonePtr(c.HasOutputHardware)
	c.IsChannelCommander = clonePtr(c.IsChannelCommander)
	c.IsPrioritySpeaker = clonePtr(c.IsPrioritySpeaker)
	c.TalkPower = clonePtr(c.TalkPower)
	c.IsRequestingTalk = clonePtr(c.IsRequestingTalk)
	c.TalkRequestedAt = clonePtr(c.TalkRequestedAt)
	c.TalkRequestMessage = clonePtr(c.TalkRequestMessage)
	c.Description = clonePtr(c.Description)
	c.MetaData = clonePtr(c.MetaData)
	c.Avatar = clonePtr(c.Avatar)
	c.IconID = clonePtr(c.IconID)
	c.NicknamePhonetic = clonePtr(c.NicknamePhonetic)
	c.UnreadMessages = clonePtr(c.UnreadMessages)
	c.NeededServerQueryViewPower = clonePtr(c.NeededServerQueryViewPower)
	c.ChannelGroupInheritedChannelID = clonePtr(c.ChannelGroupInheritedChannelID)
	c.Country = clonePtr(c.Country)
	c.Version = clonePtr(c.Version)
	c.Platform = clonePtr(c.Platform)
	c.IP = clonePtr(c.IP)
	c.Badges = clonePtr(c.Badges)
	c.SignedBadges = clonePtr(c.SignedBadges)
	c.MyTeamSpeakID = clonePtr(c.MyTeamSpeakID)
	c.MyTeamSpeakAvatar = clonePtr(c.MyTeamSpeakAvatar)
	c.Integrations = clonePtr(c.Integrations)
	c.UserTag = clonePtr(c.UserTag)
	c.IsStreaming = clonePtr(c.IsStreaming)

	return c
}

// clonePtr returns a pointer to a copy of what p points at, or nil.
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p

	return &v
}
