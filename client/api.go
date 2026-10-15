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
// address.
var ErrTooManyWhisperTargets = transport.ErrTooManyWhisperTargets

// WhisperTargets are who SendWhisper reaches. Only clients can be addressed
// today: the packet SendWhisper builds carries no channel targets. Fields are
// added as the framing learns them, so build one with keyed fields.
type WhisperTargets struct {
	// Clients are the clients to whisper to, at least one and at most 32.
	Clients []teamspeak.ClientID
}

// SendWhisper sends Opus voice directly to the clients in targets, regardless
// of which channel they are in. The bot's server group needs
// i_client_whisper_power. Without an open connection it returns
// teamspeak.ErrNotConnected.
func (c *Client) SendWhisper(data []byte, targets WhisperTargets, codec teamspeak.Codec) error {
	clients := make([]uint16, len(targets.Clients))
	for i, id := range targets.Clients {
		clients[i] = uint16(id)
	}

	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}

	return notConnected(h.SendWhisperPacket(data, clients, byte(codec)))
}

// ServerCapabilities reports what the connected server is: version, generation,
// and the uid hash it uses. Populated from initserver; before connecting the
// family reads as unknown.
func (c *Client) ServerCapabilities() ServerCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.capabilities
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
