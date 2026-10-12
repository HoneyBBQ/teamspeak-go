package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// Event is a server event as event middleware sees it: a TextMessageEvent,
// ClientEnterEvent, ClientLeaveEvent, ClientMovedEvent, PokeEvent,
// VoiceDataEvent or NotificationEvent. A middleware tells them apart with a type
// switch.
//
// The set is closed — the method is unexported — because the client delivers
// only the events it knows: a middleware that invented a type of its own would
// have it dropped with no handler to receive it. Later versions may add
// events, so a type switch over them should pass on what it does not handle.
//
// Lifecycle events (connected, disconnected, kicked) are not server events
// and do not pass through middleware: they report the connection, not what
// happened on it, and a middleware dropping one would leave the application
// unaware of its own state.
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
// It wraps the teamspeak.ClientInfo the server described, so its fields read
// as the event's own (evt.Nickname). A type of this package rather than
// ClientInfo itself, because Event's method is unexported and the root
// package's type cannot implement it.
type ClientEnterEvent struct {
	teamspeak.ClientInfo
}

// NotificationEvent is a notification exactly as the server sent it: its name,
// such as "notifychanneledited", and its parameters, unescaped.
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
	InvokerName string
	InvokerUID  teamspeak.UID
	Message     string
	// InvokerGroups are the sender's server groups, as this client last saw
	// them.
	InvokerGroups []teamspeak.ServerGroupID
	TargetMode    teamspeak.TextMessageTarget
	// TargetID is the client a private message was sent to. Channel and
	// server messages carry no target, so it is 0 for them.
	TargetID  teamspeak.ClientID
	InvokerID teamspeak.ClientID
}

// ClientMovedEvent is emitted when a client changes channel (notifyclientmoved).
type ClientMovedEvent struct {
	InvokerName     string
	InvokerUID      teamspeak.UID
	TargetChannelID teamspeak.ChannelID
	Reason          teamspeak.Reason
	// ClientID is the client that moved.
	ClientID  teamspeak.ClientID
	InvokerID teamspeak.ClientID
}

// PokeEvent is emitted when this client is poked (notifyclientpoke).
type PokeEvent struct {
	InvokerName string
	InvokerUID  teamspeak.UID
	Message     string
	InvokerID   teamspeak.ClientID
}

// ClientLeaveEvent is emitted when a client leaves view (notifyclientleftview).
type ClientLeaveEvent struct {
	// ReasonMessage is the reason given for a kick or a ban, or the client's
	// own parting message.
	ReasonMessage string
	// InvokerName, InvokerUID and InvokerID name who kicked or banned the
	// client; they are empty otherwise.
	InvokerName string
	InvokerUID  teamspeak.UID
	Reason      teamspeak.Reason
	// ClientID is the client that left.
	ClientID  teamspeak.ClientID
	InvokerID teamspeak.ClientID
}

// KickedEvent is this client being kicked from its channel or the server.
type KickedEvent struct {
	// Message is the reason the invoker gave.
	Message     string
	InvokerName string
	InvokerUID  teamspeak.UID
	// Reason is teamspeak.ReasonKickChannel, ReasonKickServer or
	// ReasonKickServerBan.
	Reason    teamspeak.Reason
	InvokerID teamspeak.ClientID
}

// VoiceDataEvent is voice or whisper audio received from another client.
type VoiceDataEvent struct {
	Data     []byte
	ClientID teamspeak.ClientID
	Codec    teamspeak.Codec
}
