package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// Event is teamspeak.Event: what event middleware receives. The root package defines it so
// that other clients share it.
type Event = teamspeak.Event

// ConnectedEvent is what OnConnected handlers receive: the handshake completed.
type ConnectedEvent struct {
	// Reconnected is true when the connection came from the reconnect loop
	// that WithReconnect turns on, and false for the one a Connect call made.
	Reconnected bool
}

// DisconnectedEvent is what OnDisconnected handlers receive: a connection, or
// an attempt to make one, ended.
type DisconnectedEvent struct {
	// Err is the cause: a failed handshake, ErrConnectionTimeout for a server
	// that stopped answering, or a *RemovedError for a kick, a ban or a server
	// stopping. It is nil after Disconnect.
	Err error
	// WillReconnect is true when the reconnect loop will try again: reconnection
	// is on, Disconnect has not been called, the attempts are not used up, and
	// the policy's ShouldRetry accepts Err. It is false after Disconnect and
	// for a failed Connect, which is never retried.
	WillReconnect bool
}

// ClientEnterEvent is teamspeak.ClientEnterEvent.
type ClientEnterEvent = teamspeak.ClientEnterEvent

// NotificationEvent is teamspeak.NotificationEvent.
type NotificationEvent = teamspeak.NotificationEvent

// TextMessageEvent is teamspeak.TextMessageEvent.
type TextMessageEvent = teamspeak.TextMessageEvent

// ClientMovedEvent is teamspeak.ClientMovedEvent.
type ClientMovedEvent = teamspeak.ClientMovedEvent

// PokeEvent is teamspeak.PokeEvent.
type PokeEvent = teamspeak.PokeEvent

// ClientLeaveEvent is teamspeak.ClientLeaveEvent.
type ClientLeaveEvent = teamspeak.ClientLeaveEvent

// KickedEvent is teamspeak.KickedEvent.
type KickedEvent = teamspeak.KickedEvent

// VoiceDataEvent is teamspeak.VoiceDataEvent.
type VoiceDataEvent = teamspeak.VoiceDataEvent
