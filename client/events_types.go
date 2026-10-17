package client

import teamspeak "github.com/honeybbq/teamspeak-go"

// The event types, the status and the connection's own errors live in the root
// package, so a future ServerQuery client shares them; this package re-exports
// them under the names it has always used.

// Event is teamspeak.Event: what event middleware receives.
type Event = teamspeak.Event

// ConnectedEvent is teamspeak.ConnectedEvent: the handshake completed.
type ConnectedEvent = teamspeak.ConnectedEvent

// DisconnectedEvent is teamspeak.DisconnectedEvent: a connection, or an
// attempt to make one, ended.
type DisconnectedEvent = teamspeak.DisconnectedEvent

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

// ClientUpdatedEvent is teamspeak.ClientUpdatedEvent.
type ClientUpdatedEvent = teamspeak.ClientUpdatedEvent

// ClientServerGroupChange is teamspeak.ClientServerGroupChange.
type ClientServerGroupChange = teamspeak.ClientServerGroupChange

// ClientServerGroupAddedEvent is teamspeak.ClientServerGroupAddedEvent.
type ClientServerGroupAddedEvent = teamspeak.ClientServerGroupAddedEvent

// ClientServerGroupRemovedEvent is teamspeak.ClientServerGroupRemovedEvent.
type ClientServerGroupRemovedEvent = teamspeak.ClientServerGroupRemovedEvent

// ClientChannelGroupChangedEvent is teamspeak.ClientChannelGroupChangedEvent.
type ClientChannelGroupChangedEvent = teamspeak.ClientChannelGroupChangedEvent

// ChannelCreatedEvent is teamspeak.ChannelCreatedEvent.
type ChannelCreatedEvent = teamspeak.ChannelCreatedEvent

// ChannelEditedEvent is teamspeak.ChannelEditedEvent.
type ChannelEditedEvent = teamspeak.ChannelEditedEvent

// ChannelMovedEvent is teamspeak.ChannelMovedEvent.
type ChannelMovedEvent = teamspeak.ChannelMovedEvent

// ChannelDeletedEvent is teamspeak.ChannelDeletedEvent.
type ChannelDeletedEvent = teamspeak.ChannelDeletedEvent

// ChannelDescriptionChangedEvent is teamspeak.ChannelDescriptionChangedEvent.
type ChannelDescriptionChangedEvent = teamspeak.ChannelDescriptionChangedEvent

// ChannelPasswordChangedEvent is teamspeak.ChannelPasswordChangedEvent.
type ChannelPasswordChangedEvent = teamspeak.ChannelPasswordChangedEvent

// ServerEditedEvent is teamspeak.ServerEditedEvent.
type ServerEditedEvent = teamspeak.ServerEditedEvent

// ChannelSubscribedEvent is teamspeak.ChannelSubscribedEvent.
type ChannelSubscribedEvent = teamspeak.ChannelSubscribedEvent

// ChannelUnsubscribedEvent is teamspeak.ChannelUnsubscribedEvent.
type ChannelUnsubscribedEvent = teamspeak.ChannelUnsubscribedEvent

// PluginCommandEvent is teamspeak.PluginCommandEvent.
type PluginCommandEvent = teamspeak.PluginCommandEvent

// ClientChatComposingEvent is teamspeak.ClientChatComposingEvent.
type ClientChatComposingEvent = teamspeak.ClientChatComposingEvent

// Status is teamspeak.Status: the state of a client's connection.
type Status = teamspeak.Status

// The connection states.
const (
	// StatusDisconnected is a client with no connection.
	StatusDisconnected = teamspeak.StatusDisconnected
	// StatusConnecting is a client between Connect and the end of the
	// handshake.
	StatusConnecting = teamspeak.StatusConnecting
	// StatusConnected is a client whose handshake has completed.
	StatusConnected = teamspeak.StatusConnected
)

// ServerFamily is teamspeak.ServerFamily: the server generation a version
// string belongs to.
type ServerFamily = teamspeak.ServerFamily

// The server generations.
const (
	// ServerFamilyUnknown means the server has not identified itself yet. It is
	// the zero value.
	ServerFamilyUnknown = teamspeak.ServerFamilyUnknown
	// ServerFamilyTS3 is TeamSpeak 3, which hashes client uids with SHA-1.
	ServerFamilyTS3 = teamspeak.ServerFamilyTS3
	// ServerFamilyTS6 is TeamSpeak 6, which hashes client uids with SHA-256.
	ServerFamilyTS6 = teamspeak.ServerFamilyTS6
)
