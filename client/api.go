package client

import (
	"context"
	"errors"
	"fmt"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// VoiceOptions are SendVoice's optional parameters. It has no fields yet: it is
// reserved for later.
type VoiceOptions struct{}

// SendVoice sends one encoded audio frame, normally teamspeak.CodecOpusVoice
// or CodecOpusMusic. Without an open connection it returns
// teamspeak.ErrNotConnected.
func (c *Client) SendVoice(data []byte, codec teamspeak.Codec, _ VoiceOptions) error {
	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}

	return notConnected(h.SendVoicePacket(data, byte(codec)))
}

// notConnected reports a send the transport refused for having no open
// connection as teamspeak.ErrNotConnected.
func notConnected(err error) error {
	if errors.Is(err, transport.ErrNotOpen) {
		return fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, err)
	}

	return err
}

// ErrNoWhisperTargets reports a whisper with no one to receive it.
var ErrNoWhisperTargets = transport.ErrNoWhisperTargets

// ErrTooManyWhisperTargets reports more whisper targets than one packet can
// address: more than 32 clients.
var ErrTooManyWhisperTargets = transport.ErrTooManyWhisperTargets

// ErrTooManyWhisperChannels reports a whisper naming more than 255 channels.
var ErrTooManyWhisperChannels = transport.ErrTooManyWhisperChannels

// ErrInvalidWhisperTarget reports a GroupWhisperTarget that is not one of the
// constructors' results, or was built with a scope the packet has no name for.
var ErrInvalidWhisperTarget = errors.New("invalid group whisper target")

// WhisperTargets are who SendWhisper reaches: clients, channels, or both. The
// packet's direct form carries the two lists together. Fields are added as the
// framing learns them, so build one with keyed fields.
type WhisperTargets struct {
	// Clients are the clients to whisper to, at most 32.
	Clients []teamspeak.ClientID
	// Channels are the channels to whisper to, at most 255.
	Channels []teamspeak.ChannelID
}

// SendWhisper sends Opus voice directly to the clients and channels in
// targets, regardless of which channel the clients are in. At least one target
// in total is required: with none it returns ErrNoWhisperTargets, with more
// than 32 clients ErrTooManyWhisperTargets, and with more than 255 channels
// ErrTooManyWhisperChannels. Whether a target hears it is the server's
// decision, from the bot's i_client_whisper_power against the target's
// i_client_needed_whisper_power. Without an open connection it returns
// teamspeak.ErrNotConnected.
func (c *Client) SendWhisper(data []byte, targets WhisperTargets, codec teamspeak.Codec) error {
	clients := make([]uint16, len(targets.Clients))
	for i, id := range targets.Clients {
		clients[i] = uint16(id)
	}
	channels := make([]uint64, len(targets.Channels))
	for i, id := range targets.Channels {
		channels[i] = uint64(id)
	}

	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}

	return notConnected(h.SendWhisperPacket(data, clients, channels, byte(codec)))
}

// GroupWhisperType is which clients a group whisper reaches: the packet's
// GroupWhisperType. Server group, channel group and all clients were measured
// on TeamSpeak 3 and 6; channel commander was not.
type GroupWhisperType uint8

// The group whisper types.
const (
	// GroupWhisperServerGroup reaches the members of one server group.
	GroupWhisperServerGroup GroupWhisperType = 0
	// GroupWhisperChannelGroup reaches the holders of one channel group.
	GroupWhisperChannelGroup GroupWhisperType = 1
	// GroupWhisperChannelCommander reaches the clients that are channel
	// commanders. Unmeasured: a test client was not one.
	GroupWhisperChannelCommander GroupWhisperType = 2
	// GroupWhisperAllClients reaches every client.
	GroupWhisperAllClients GroupWhisperType = 3
)

// GroupWhisperScope is which channels a group whisper reaches: the packet's
// GroupWhisperTarget. All channels and the current channel were measured on
// TeamSpeak 3 and 6; the others carry the packet's names and were not.
type GroupWhisperScope uint8

// The group whisper scopes.
const (
	// GroupWhisperAllChannels reaches every channel.
	GroupWhisperAllChannels GroupWhisperScope = 0
	// GroupWhisperCurrentChannel reaches the channel the sender is in.
	GroupWhisperCurrentChannel GroupWhisperScope = 1
	// GroupWhisperParentChannel reaches the parent of the sender's channel.
	// Unmeasured.
	GroupWhisperParentChannel GroupWhisperScope = 2
	// GroupWhisperAllParentChannels reaches every ancestor of the sender's
	// channel. Unmeasured.
	GroupWhisperAllParentChannels GroupWhisperScope = 3
	// GroupWhisperChannelFamily reaches the sender's channel and its
	// subchannels. Unmeasured.
	GroupWhisperChannelFamily GroupWhisperScope = 4
	// GroupWhisperCompleteChannelFamily reaches the sender's ancestors, its
	// channel and its subchannels. Unmeasured.
	GroupWhisperCompleteChannelFamily GroupWhisperScope = 5
	// GroupWhisperSubchannels reaches the subchannels of the sender's channel.
	// Unmeasured.
	GroupWhisperSubchannels GroupWhisperScope = 6
)

// GroupWhisperTarget is who SendGroupWhisper sends to: one of the packet's
// group targets, within the channels a scope picks. Build one with
// WhisperToServerGroup, WhisperToChannelGroup, WhisperToChannelCommanders or
// WhisperToAllClients. Its fields are unexported so that the id can only be
// the kind the type takes: a server group cannot be given a channel group's
// id, and a type that takes no id cannot be given one. The zero value is not a
// target; sending it fails with ErrInvalidWhisperTarget.
type GroupWhisperTarget struct {
	id    uint64
	kind  GroupWhisperType
	scope GroupWhisperScope
	valid bool
}

// WhisperToServerGroup targets the members of server group id, within scope.
func WhisperToServerGroup(scope GroupWhisperScope, id teamspeak.ServerGroupID) GroupWhisperTarget {
	return newGroupWhisperTarget(GroupWhisperServerGroup, scope, uint64(id))
}

// WhisperToChannelGroup targets the holders of channel group id, within scope.
func WhisperToChannelGroup(scope GroupWhisperScope, id teamspeak.ChannelGroupID) GroupWhisperTarget {
	return newGroupWhisperTarget(GroupWhisperChannelGroup, scope, uint64(id))
}

// WhisperToChannelCommanders targets the channel commanders, within scope.
func WhisperToChannelCommanders(scope GroupWhisperScope) GroupWhisperTarget {
	return newGroupWhisperTarget(GroupWhisperChannelCommander, scope, 0)
}

// WhisperToAllClients targets every client, within scope.
func WhisperToAllClients(scope GroupWhisperScope) GroupWhisperTarget {
	return newGroupWhisperTarget(GroupWhisperAllClients, scope, 0)
}

func newGroupWhisperTarget(kind GroupWhisperType, scope GroupWhisperScope, id uint64) GroupWhisperTarget {
	return GroupWhisperTarget{kind: kind, scope: scope, id: id, valid: scope <= GroupWhisperSubchannels}
}

// Type is which clients the target reaches.
func (t GroupWhisperTarget) Type() GroupWhisperType { return t.kind }

// Scope is which channels the target reaches.
func (t GroupWhisperTarget) Scope() GroupWhisperScope { return t.scope }

// SendGroupWhisper sends Opus voice to a group of clients: a server group, a
// channel group, the channel commanders or everyone, within the channels the
// target's scope picks. It is the packet's group form; SendWhisper is the
// direct one. A target that is not one of the constructors' results returns
// ErrInvalidWhisperTarget. Whether a client hears it is the server's decision,
// as for SendWhisper. Without an open connection it returns
// teamspeak.ErrNotConnected.
func (c *Client) SendGroupWhisper(data []byte, target GroupWhisperTarget, codec teamspeak.Codec) error {
	if !target.valid {
		return ErrInvalidWhisperTarget
	}

	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}

	return notConnected(h.SendGroupWhisperPacket(data, byte(target.kind), byte(target.scope), target.id, byte(codec)))
}

// ServerCapabilities reports what the connected server is: version, generation,
// and the uid hash it uses. Populated from initserver; before connecting the
// family reads as unknown. The record is a copy: changing its Extensions
// changes nothing in the client.
func (c *Client) ServerCapabilities() ServerCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.capabilities.clone()
}

// UID returns our own client_unique_identifier, hashed with the
// algorithm the connected server uses.
//
// TS3 uses SHA-1 and TS6 SHA-256, so this reads the algorithm learned during
// initserver rather than assuming one: comparing a hard-coded SHA-1 UID to a
// TS6 server silently never matches.
func (c *Client) UID() teamspeak.UID {
	c.mu.Lock()
	defer c.mu.Unlock()

	return identity.UID(c.identity.PublicKey(), c.uidAlgorithm)
}

// ClientID returns the id the server assigned this session, or 0 before it
// has. A reconnect gets a new one.
func (c *Client) ClientID() teamspeak.ClientID {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.clid
}

// Status reports the current connection state.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.status
}

// waitConnected waits for the current connection attempt to complete,
// returning its cause if it fails.
func (c *Client) waitConnected(ctx context.Context) error {
	c.mu.Lock()
	attempt := c.attempt
	c.mu.Unlock()

	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
