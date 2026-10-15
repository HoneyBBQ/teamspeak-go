package teamspeak

// Event is a server event: a TextMessageEvent, ClientEnterEvent,
// ClientLeaveEvent, ClientMovedEvent, PokeEvent, VoiceDataEvent or
// NotificationEvent. Code that receives events of any kind tells them apart
// with a type switch.
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
func (ClientEnterEvent) serverEvent()  {}
func (ClientLeaveEvent) serverEvent()  {}
func (ClientMovedEvent) serverEvent()  {}
func (PokeEvent) serverEvent()         {}
func (VoiceDataEvent) serverEvent()    {}
func (NotificationEvent) serverEvent() {}

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
