package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// TextMessage is an incoming notifytextmessage payload.
type TextMessage struct {
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
	ID              teamspeak.ClientID
	InvokerID       teamspeak.ClientID
}

// PokeEvent is emitted when this client is poked (notifyclientpoke).
type PokeEvent struct {
	InvokerName string
	InvokerUID  teamspeak.UID
	Message     string
	InvokerID   teamspeak.ClientID
}

// ClientLeftViewEvent is emitted when a client leaves view (notifyclientleftview).
type ClientLeftViewEvent struct {
	// ReasonMessage is the reason given for a kick or a ban, or the client's
	// own parting message.
	ReasonMessage string
	// InvokerName, InvokerUID and InvokerID name who kicked or banned the
	// client; they are empty otherwise.
	InvokerName string
	InvokerUID  teamspeak.UID
	Reason      teamspeak.Reason
	ID          teamspeak.ClientID
	InvokerID   teamspeak.ClientID
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

// VoiceData is voice or whisper audio received from another client.
type VoiceData struct {
	Data     []byte
	ClientID teamspeak.ClientID
	Codec    teamspeak.Codec
}
