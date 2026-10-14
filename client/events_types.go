package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// Event is teamspeak.Event: what event middleware receives. The root package defines it so
// that other clients share it.
type Event = teamspeak.Event

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
