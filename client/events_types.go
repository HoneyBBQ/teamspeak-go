package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// TextMessage is an incoming notifytextmessage payload.
type TextMessage struct {
	InvokerName   string
	InvokerUID    string
	Message       string
	InvokerGroups []uint64
	TargetMode    int
	TargetID      uint64
	InvokerID     uint16
}

// ClientMovedEvent is emitted when a client changes channel (notifyclientmoved).
type ClientMovedEvent struct {
	InvokerName     string
	InvokerUID      string
	TargetChannelID uint64
	Reason          teamspeak.Reason
	ID              uint16
	InvokerID       uint16
}

// PokeEvent is emitted when this client is poked (notifyclientpoke).
type PokeEvent struct {
	InvokerName string
	InvokerUID  string
	Message     string
	InvokerID   uint16
}

// ClientLeftViewEvent is emitted when a client leaves view (notifyclientleftview).
type ClientLeftViewEvent struct {
	// ReasonMessage is the reason given for a kick or a ban, or the client's
	// own parting message.
	ReasonMessage string
	// InvokerName, InvokerUID and InvokerID name who kicked or banned the
	// client; they are empty otherwise.
	InvokerName string
	InvokerUID  string
	Reason      teamspeak.Reason
	ID          uint16
	InvokerID   uint16
}

// KickedEvent is this client being kicked from its channel or the server.
type KickedEvent struct {
	// Message is the reason the invoker gave.
	Message     string
	InvokerName string
	InvokerUID  string
	// Reason is teamspeak.ReasonKickChannel, ReasonKickServer or
	// ReasonKickServerBan.
	Reason    teamspeak.Reason
	InvokerID uint16
}

// VoiceData is voice or whisper audio received from another client.
type VoiceData struct {
	Data     []byte
	ClientID uint16
	Codec    byte
}
