package teamspeak

// Event is a server event: a TextMessageEvent, ClientEnterEvent,
// ClientLeaveEvent, ClientMovedEvent, PokeEvent, VoiceDataEvent,
// NotificationEvent, ClientUpdatedEvent, ClientServerGroupAddedEvent,
// ClientServerGroupRemovedEvent, ClientChannelGroupChangedEvent,
// ChannelCreatedEvent, ChannelEditedEvent, ChannelMovedEvent,
// ChannelDeletedEvent, ChannelDescriptionChangedEvent,
// ChannelPasswordChangedEvent, ServerEditedEvent, ChannelSubscribedEvent,
// ChannelUnsubscribedEvent, PluginCommandEvent, ClientChatComposingEvent or
// ClientChatClosedEvent.
// Code that receives events of any kind tells them apart with a type switch.
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

func (ChannelCreatedEvent) serverEvent()            {}
func (ChannelEditedEvent) serverEvent()             {}
func (ChannelMovedEvent) serverEvent()              {}
func (ChannelDeletedEvent) serverEvent()            {}
func (ChannelDescriptionChangedEvent) serverEvent() {}
func (ChannelPasswordChangedEvent) serverEvent()    {}
func (ServerEditedEvent) serverEvent()              {}
func (ChannelSubscribedEvent) serverEvent()         {}
func (ChannelUnsubscribedEvent) serverEvent()       {}
func (PluginCommandEvent) serverEvent()             {}
func (ClientChatComposingEvent) serverEvent()       {}
func (ClientChatClosedEvent) serverEvent()          {}

// ClientEnterEvent is emitted when a client enters view
// (notifycliententerview): on connecting, for everyone already there, and
// whenever someone joins or becomes visible.
//
// What the client is told is limited to the channels it is subscribed to. On
// connecting that is its own channel alone, so the clients in every other
// channel are not announced, and the absence of an event does not mean a client
// is absent: ListClients lists everyone. SubscribeChannel and
// SubscribeAllChannels announce the clients of the channels they subscribe to,
// each with an event of this kind before the ChannelSubscribedEvent. After
// that, a client moving into a subscribed channel from one the client does not
// see arrives as this event, and one moving out to such a channel as a
// ClientLeaveEvent. The server does not tell the client when a subscription
// ends; see ChannelUnsubscribedEvent.
//
// It embeds the ClientEntry the server described, so its fields read as the
// event's own (evt.Nickname). It is a struct of its own rather than ClientEntry
// itself so that ClientEntry stays a plain description of a client, which also
// answers a client list, and only the event is an Event.
//
// FromChannelID and Reason are the event's own, not the client's: the server
// sends them with the enter notification (cfid and reasonid) and they describe
// this entry into view only.
type ClientEnterEvent struct {
	ClientEntry

	// FromChannelID is the channel the client came from (cfid). It points at 0
	// when the client connected, which both TeamSpeak 3 and 6 send as cfid 0,
	// and is nil when the server sends none.
	FromChannelID *ChannelID
	// Reason is why the client came into view (reasonid): ReasonNone when it
	// connected, ReasonSubscription when it was already on the server and came
	// into view by this client moving into its channel. Measured on TeamSpeak
	// 3.13.8 and 6.0.0-beta13.1; both send cfid 0 with it. It is nil when the
	// server sends none.
	Reason *Reason
}

// Clone returns a copy of the event whose record shares no memory with e's; see
// ClientEntry.Clone. It is here because the embedded record's Clone would
// otherwise be promoted and return the record alone.
func (e ClientEnterEvent) Clone() ClientEnterEvent {
	e.ClientEntry = e.ClientEntry.Clone()
	e.FromChannelID = clonePtr(e.FromChannelID)
	e.Reason = clonePtr(e.Reason)

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
	//
	// A ServerQuery connection is not sent notifyclientupdated, so for a
	// ServerQuery client they are the groups from the listing taken on
	// connecting, kept current only by clients entering, leaving and moving: a
	// change of groups made since is not in them.
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
	// FromChannelID is the channel the client moved from: cfid, or when the
	// server sends none (TeamSpeak 3.13.8 sends none on a move, TeamSpeak 6.0.0
	// does) the channel the client was known to be in. The client's record is
	// updated before the event is delivered, so this is where its previous
	// channel is told. It is nil only when the server sent none and the client
	// was not known.
	FromChannelID *ChannelID
	// InvokerName is who moved the client (invokername); empty when the server
	// names no one, which it does not for a client that moved itself
	// (ReasonNone).
	InvokerName string
	// InvokerUID is the identity of who moved the client (invokeruid); empty
	// when the server names no one, as for a client that moved itself.
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
	// InvokerID is the client id of who moved the client (invokerid); 0 when the
	// server names no one, as for a client that moved itself.
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
	// Previous is the client as the voice client knew it just before it left, a
	// copy of the handler's own. It is nil when the client had not been
	// announced to this one, and always on the ServerQuery client, which keeps
	// no record of clients.
	//
	// Experimental: this may change in a minor release.
	Previous *ClientEntry
	// FromChannelID is the channel the client was in (cfid), nil when the server
	// sends none. Both TeamSpeak 3.13.8 and 6.0.0-beta13.1 send it.
	FromChannelID *ChannelID
	// TargetChannelID is the channel the client went to (ctid): a pointer to 0
	// when it left the server, the channel it moved into when it left view by
	// moving out of the channels this client is subscribed to, and nil when the
	// server sends none.
	TargetChannelID *ChannelID
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
	// copy. It is empty when the speaker stopped talking: that is the end of
	// the speech, not a frame to decode.
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

// ChannelCreatedEvent is emitted when a channel is created
// (notifychannelcreated), by a client or by the server.
//
// Changes holds the properties the server sent, which are those that differ
// from a new channel's defaults: for a channel left at its defaults, little
// more than the name and the position. A property that is nil there has the
// server's default; it is not unknown. The description is never among them;
// GetChannelInfo has it. ChannelChanges.Apply merges them into a Channel.
type ChannelCreatedEvent struct {
	// Changes are the properties the notification carried. Each handler gets
	// its own copy.
	Changes ChannelChanges
	// InvokerName is who created the channel (invokername).
	InvokerName string
	// InvokerUID is the identity of who created the channel (invokeruid).
	InvokerUID UID
	// ChannelID is the new channel (cid).
	ChannelID ChannelID
	// ParentID is the channel it was created under (cpid); 0 for the top
	// level.
	ParentID ChannelID
	// InvokerID is the client id of who created the channel (invokerid).
	InvokerID ClientID
}

// ChannelEditedEvent is emitted when a channel's properties are edited
// (notifychanneledited).
//
// Changes holds only the properties the notification named. Editing a
// description names none: ChannelDescriptionChangedEvent follows, and the text
// is fetched. The answer to a description fetch is not an edit and produces no
// event: it arrives with ReasonChannelUpdate and no invoker.
type ChannelEditedEvent struct {
	// Changes are the properties the notification carried. Each handler gets
	// its own copy.
	Changes ChannelChanges
	// InvokerName is who edited the channel (invokername).
	InvokerName string
	// InvokerUID is the identity of who edited the channel (invokeruid).
	InvokerUID UID
	// ChannelID is the channel that changed (cid).
	ChannelID ChannelID
	// Reason is why it changed (reasonid); ReasonChannelEdit for an edit.
	Reason Reason
	// InvokerID is the client id of who edited the channel (invokerid).
	InvokerID ClientID
}

// ChannelMovedEvent is emitted when a channel is moved under another or
// reordered (notifychannelmoved).
type ChannelMovedEvent struct {
	// InvokerName is who moved the channel (invokername).
	InvokerName string
	// InvokerUID is the identity of who moved the channel (invokeruid).
	InvokerUID UID
	// ChannelID is the channel that moved (cid).
	ChannelID ChannelID
	// ParentID is the channel it is now under (cpid); 0 for the top level.
	ParentID ChannelID
	// Order is the sibling it is now sorted after (order); 0 sorts it first.
	Order ChannelID
	// Reason is why it moved (reasonid).
	Reason Reason
	// InvokerID is the client id of who moved the channel (invokerid).
	InvokerID ClientID
}

// ChannelDeletedEvent is emitted when a channel is deleted
// (notifychanneldeleted).
type ChannelDeletedEvent struct {
	// Previous is the channel as the voice client's view held it just before
	// the deletion, a copy of the handler's own: its Order is its place in the
	// tree, and its TotalClients and TotalFamilyClients are nil. It is nil when
	// the view did not hold the channel, as while it is loading, and always on
	// the ServerQuery client, which has no view. A channel deleted with its
	// subchannels gives one event for each, the subchannels first, each with
	// its own record.
	//
	// Experimental: this may change in a minor release.
	Previous *Channel
	// InvokerName is who deleted the channel (invokername); "Server" when the
	// server did, as it does for a temporary channel that has emptied.
	InvokerName string
	// InvokerUID is the identity of who deleted the channel (invokeruid).
	InvokerUID UID
	// ChannelID is the channel that was deleted (cid).
	ChannelID ChannelID
	// InvokerID is the client id of who deleted the channel (invokerid); 0 when
	// the server did.
	InvokerID ClientID
}

// ChannelDescriptionChangedEvent is emitted when a channel's description
// changed (notifychanneldescriptionchanged). It does not carry the text, nor
// does the ChannelEditedEvent that accompanies it: fetch it.
type ChannelDescriptionChangedEvent struct {
	// ChannelID is the channel (cid).
	ChannelID ChannelID
}

// ChannelPasswordChangedEvent is emitted when a channel's password was set,
// changed or removed (notifychannelpasswordchanged). The ChannelEditedEvent
// that accompanies it names the password flag only when the flag flipped.
type ChannelPasswordChangedEvent struct {
	// ChannelID is the channel (cid).
	ChannelID ChannelID
}

// ServerEditedEvent is emitted when the virtual server's settings are edited
// (notifyserveredited).
//
// Changes are the changed properties by their wire names, such as
// "virtualserver_name"; the prop package names them. They are raw because the
// SDK has no typed record of the server. A change of the welcome message names
// no property, so Changes may be empty.
type ServerEditedEvent struct {
	// Changes are the changed properties. Each handler gets its own copy.
	Changes Properties
	// InvokerName is who edited the server (invokername).
	InvokerName string
	// InvokerUID is the identity of who edited the server (invokeruid).
	InvokerUID UID
	// InvokerID is the client id of who edited the server (invokerid).
	InvokerID ClientID
}

// ChannelSubscribedEvent is emitted when this client is subscribed to a
// channel (notifychannelsubscribed), by SubscribeChannel or by the server. Only
// the voice client delivers it: subscriptions are a voice-protocol concept.
type ChannelSubscribedEvent struct {
	// ChannelID is the channel (cid).
	ChannelID ChannelID
}

// ChannelUnsubscribedEvent is emitted when this client is no longer subscribed
// to a channel (notifychannelunsubscribed), by request or because the server
// withdrew the subscription. Only the voice client delivers it.
//
// The server does not say that the clients in the channel are gone from view:
// it sends no ClientLeaveEvent for them, and nothing about them afterwards, not
// their moves and not their leaving. What was known of them is therefore stale
// from this event on, and the voice client forgets them, in the view and in the
// groups of a TextMessageEvent, when the event arrives; a program that follows
// the clients from the events alone has to do the same. Subscribing again
// announces the clients then in the channel with a ClientEnterEvent each, in
// the channel they are in now. The client itself is kept, in whatever channel
// it is. Which channels the client is subscribed to is not told either; it can
// only be worked out from these events.
type ChannelUnsubscribedEvent struct {
	// ChannelID is the channel (cid).
	ChannelID ChannelID
}

// PluginCommandEvent is a plugin command from a client (notifyplugincmd), sent
// with SendPluginCommand. The sender receives its own command when it was sent
// to the channel or to the server. Only the voice client delivers it.
type PluginCommandEvent struct {
	// Name is the command's name (name).
	Name string
	// Data is its payload (data); it may be empty.
	Data string
	// InvokerName is the sender's nickname (invokername).
	InvokerName string
	// InvokerUID is the sender's identity (invokeruid).
	InvokerUID UID
	// InvokerID is the sender's client id (invokerid).
	InvokerID ClientID
}

// ClientChatComposingEvent is emitted when a client is typing a private message
// to this client (notifyclientchatcomposing), sent with SendChatComposing. Only
// the voice client delivers it.
type ClientChatComposingEvent struct {
	// UID is the typing client's identity (cluid).
	UID UID
	// ClientID is the typing client (clid).
	ClientID ClientID
}

// ClientChatClosedEvent is emitted when a client closes its private chat with
// this client (notifyclientchatclosed), sent with ClosePrivateChat. The server
// sends it only after that client has sent this one a private message. Only the
// voice client delivers it.
type ClientChatClosedEvent struct {
	// UID is the closing client's identity (cluid).
	UID UID
	// ClientID is the closing client (clid).
	ClientID ClientID
}
