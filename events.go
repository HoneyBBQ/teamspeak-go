package teamspeak

// Event is a server event: a TextMessageEvent, ClientEnterEvent,
// ClientLeaveEvent, ClientMovedEvent, PokeEvent, VoiceDataEvent,
// NotificationEvent, ClientUpdatedEvent, ClientServerGroupAddedEvent,
// ClientServerGroupRemovedEvent or ClientChannelGroupChangedEvent. Code that
// receives events of any kind tells them apart with a type switch.
//
// The set is closed — the method is unexported — because a client delivers
// only the events it knows: a type invented elsewhere would have no handler to
// receive it. Later versions may add events, so a type switch over them should
// pass on what it does not handle.
//
// Lifecycle events (connected, disconnected, kicked) are not server events;
// they report the connection, not what happened on it.
type Event interface {
	serverEvent()
}

func (TextMessageEvent) serverEvent()  {}
func (ClientLeaveEvent) serverEvent()  {}
func (ClientMovedEvent) serverEvent()  {}
func (PokeEvent) serverEvent()         {}
func (VoiceDataEvent) serverEvent()    {}
func (NotificationEvent) serverEvent() {}

func (ClientUpdatedEvent) serverEvent()             {}
func (ClientServerGroupAddedEvent) serverEvent()    {}
func (ClientServerGroupRemovedEvent) serverEvent()  {}
func (ClientChannelGroupChangedEvent) serverEvent() {}

// ClientEnterEvent is emitted when a client enters view
// (notifycliententerview): on connecting, for everyone already there, and
// whenever someone joins or becomes visible.
//
// It embeds the ClientEntry the server described, so its fields read as the
// event's own (evt.Nickname). It is a struct of its own rather than ClientEntry
// itself so that ClientEntry stays a plain description of a client, which also
// answers a client list, and only the event is an Event.
type ClientEnterEvent struct {
	ClientEntry
}

// Clone returns a copy of the event whose record shares no memory with e's; see
// ClientEntry.Clone. It is here because the embedded record's Clone would
// otherwise be promoted and return the record alone.
func (e ClientEnterEvent) Clone() ClientEnterEvent {
	e.ClientEntry = e.ClientEntry.Clone()

	return e
}

func (ClientEnterEvent) serverEvent() {}

// NotificationEvent is a notification exactly as the server sent it: its name,
// such as "notifychanneledited", and its parameters, unescaped. The notify
// package names the notifications.
//
// It is the escape hatch for a notification the SDK does not model. Every
// notification is delivered as one, after the typed event it produces, if
// any. A batched notification arrives as one NotificationEvent per row, with
// the fields the server left out of later rows filled in.
type NotificationEvent struct {
	// Params are the notification's parameters. Each handler gets its own
	// copy.
	Params map[string]string
	// Name is the notification's name.
	Name string
}

// TextMessageEvent is an incoming notifytextmessage payload.
type TextMessageEvent struct {
	// InvokerName is the sender's nickname (invokername).
	InvokerName string
	// InvokerUID is the sender's identity (invokeruid). A client that tracks
	// the clients in view may fill it in when the server leaves it out.
	InvokerUID UID
	// Message is the message's text (msg).
	Message string
	// InvokerGroups are the sender's server groups. A notification does not
	// carry them, so a client fills them in from what it knows of the sender;
	// nil means the notification did not carry them and the client did not
	// know them either, which is not the same as the sender holding none.
	InvokerGroups []ServerGroupID
	// TargetMode is whether the message went to a client, a channel or the
	// server (targetmode).
	TargetMode TextMessageTarget
	// TargetID is the client a private message was sent to. Channel and
	// server messages carry no target, so it is 0 for them.
	TargetID ClientID
	// InvokerID is the sender's client id (invokerid).
	InvokerID ClientID
}

// ClientMovedEvent is emitted when a client changes channel (notifyclientmoved).
type ClientMovedEvent struct {
	// InvokerName is who moved the client (invokername); empty when it moved
	// itself.
	InvokerName string
	// InvokerUID is the identity of who moved the client (invokeruid); empty
	// when it moved itself.
	InvokerUID UID
	// ReasonMessage is the reason the invoker gave (reasonmsg), if any.
	ReasonMessage string
	// TargetChannelID is the channel the client moved to (ctid).
	TargetChannelID ChannelID
	// Reason is why it moved (reasonid): ReasonMoved for a move by someone,
	// ReasonKickChannel for a channel kick, ReasonNone for its own.
	Reason Reason
	// ClientID is the client that moved.
	ClientID ClientID
	// InvokerID is the client id of who moved the client (invokerid); 0 when it
	// moved itself.
	InvokerID ClientID
}

// PokeEvent is emitted when the connected client is poked (notifyclientpoke).
type PokeEvent struct {
	// InvokerName is the poker's nickname (invokername).
	InvokerName string
	// InvokerUID is the poker's identity (invokeruid).
	InvokerUID UID
	// Message is the poke's text (msg).
	Message string
	// InvokerID is the poker's client id (invokerid).
	InvokerID ClientID
}

// ClientLeaveEvent is emitted when a client leaves view (notifyclientleftview).
type ClientLeaveEvent struct {
	// ReasonMessage is the reason given for a kick or a ban, or the client's
	// own parting message.
	ReasonMessage string
	// InvokerName, InvokerUID and InvokerID name who kicked or banned the
	// client; they are empty otherwise.
	InvokerName string
	// InvokerUID is the identity of who kicked or banned the client
	// (invokeruid).
	InvokerUID UID
	// Reason is why the client left (reasonid): a disconnect, a kick, a ban, a
	// timeout, or leaving view.
	Reason Reason
	// ClientID is the client that left.
	ClientID ClientID
	// InvokerID is the client id of who kicked or banned the client (invokerid).
	InvokerID ClientID
}

// KickedEvent is the connected client being kicked from its channel or the server.
type KickedEvent struct {
	// ReasonMessage is the reason the invoker gave (reasonmsg), if any.
	ReasonMessage string
	// InvokerName is who kicked the client (invokername).
	InvokerName string
	// InvokerUID is the identity of who kicked the client (invokeruid).
	InvokerUID UID
	// Reason is ReasonKickChannel, ReasonKickServer or
	// ReasonKickServerBan.
	Reason Reason
	// InvokerID is the client id of who kicked the client (invokerid).
	InvokerID ClientID
}

// VoiceDataEvent is voice or whisper audio received from another client. Only
// the voice protocol delivers it.
type VoiceDataEvent struct {
	// Data is the encoded audio, one frame in Codec. Each handler gets its own
	// copy.
	Data []byte
	// ClientID is the client speaking.
	ClientID ClientID
	// Codec is the codec Data is encoded in.
	Codec Codec
}

// ClientUpdatedEvent is emitted when a client in view changes some of its
// properties (notifyclientupdated): its nickname, away or mute state, server
// groups, talk power, description. It can be this client itself. Only the voice
// client delivers it: a TeamSpeak 3 ServerQuery connection is not sent it.
//
// Changes holds only what the notification named; a nil field did not change.
// Server groups arrive as the complete new list. Whoever invoked the change is
// named only when someone edited the client (clientedit): the client changing
// itself, and the server changing its groups, name no one.
//
// The client has already applied the change to what it knows of that client
// when a handler runs, so a TextMessageEvent that follows carries the new
// InvokerGroups. A client the voice client does not know, because it is in no
// channel in view, is reported without being added.
type ClientUpdatedEvent struct {
	// Changes are the properties the notification carried. Each handler gets
	// its own copy.
	Changes ClientChanges
	// InvokerName is who edited the client (invokername); empty when no one did.
	InvokerName string
	// InvokerUID is the identity of who edited the client (invokeruid).
	InvokerUID UID
	// ClientID is the client that changed (clid).
	ClientID ClientID
	// InvokerID is the client id of who edited the client (invokerid); 0 when
	// no one did.
	InvokerID ClientID
}

// ClientServerGroupChange is what a server group being granted or taken away
// reports (notifyservergroupclientadded, notifyservergroupclientdeleted). Two
// event types wrap it so that a type switch can tell them apart, as
// ClientEnterEvent wraps ClientEntry.
//
// The notification names the group and who did it. It does not carry the
// client's complete list of groups: that arrives as a ClientUpdatedEvent, in
// either order relative to this one, and is what the client's own record of
// the client follows.
type ClientServerGroupChange struct {
	// InvokerName is who changed the group (invokername); "Server" when the
	// server did.
	InvokerName string
	// InvokerUID is the identity of who changed the group (invokeruid).
	InvokerUID UID
	// Nickname is the affected client's nickname (name).
	Nickname string
	// UID is the affected client's identity (cluid).
	UID UID
	// GroupID is the server group (sgid).
	GroupID ServerGroupID
	// ClientID is the affected client (clid).
	ClientID ClientID
	// InvokerID is the client id of who changed the group (invokerid); 0 when the
	// server did.
	InvokerID ClientID
}

// ClientServerGroupAddedEvent is emitted when a client is added to a server
// group (notifyservergroupclientadded). Only the voice client delivers it.
type ClientServerGroupAddedEvent struct {
	ClientServerGroupChange
}

// ClientServerGroupRemovedEvent is emitted when a client is removed from a
// server group (notifyservergroupclientdeleted). Only the voice client delivers
// it.
type ClientServerGroupRemovedEvent struct {
	ClientServerGroupChange
}

// ClientChannelGroupChangedEvent is emitted when a client's channel group in a
// channel changes (notifyclientchannelgroupchanged), which also happens
// whenever the client moves, since the group is per channel. Only the voice
// client delivers it.
//
// The voice client updates the channel group it remembers for the client when
// ChannelID is the channel the client is in.
type ClientChannelGroupChangedEvent struct {
	// InvokerName is who changed the group (invokername); "Server" for a move.
	InvokerName string
	// InvokerUID is the identity of who changed the group (invokeruid).
	InvokerUID UID
	// ChannelID is the channel the group applies in (cid).
	ChannelID ChannelID
	// ChannelGroupID is the client's channel group there (cgid).
	ChannelGroupID ChannelGroupID
	// ChannelGroupInheritedChannelID is the channel the group is inherited from
	// (cgi).
	ChannelGroupInheritedChannelID ChannelID
	// ClientID is the client whose group changed (clid).
	ClientID ClientID
	// InvokerID is the client id of who changed the group (invokerid); 0 for a
	// move or when the server did.
	InvokerID ClientID
}
