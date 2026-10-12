package client

import (
	"context"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// SendVoice sends one encoded audio frame, normally teamspeak.CodecOpusVoice
// or CodecOpusMusic.
func (c *Client) SendVoice(data []byte, codec teamspeak.Codec) error {
	return c.currentHandler().SendVoicePacket(data, byte(codec))
}

// ErrNoWhisperTargets reports a whisper with no one to receive it.
var ErrNoWhisperTargets = transport.ErrNoWhisperTargets

// ErrTooManyWhisperTargets reports more whisper targets than one packet can
// address.
var ErrTooManyWhisperTargets = transport.ErrTooManyWhisperTargets

// SendWhisper sends Opus voice directly to up to 32 clients, regardless of which
// channel they are in. The bot's server group needs i_client_whisper_power.
func (c *Client) SendWhisper(data []byte, targetClientIDs []teamspeak.ClientID, codec teamspeak.Codec) error {
	targets := make([]uint16, len(targetClientIDs))
	for i, id := range targetClientIDs {
		targets[i] = uint16(id)
	}

	return c.currentHandler().SendWhisperPacket(data, targets, byte(codec))
}

// ServerCapabilities reports what the connected server is: version, generation,
// and the uid hash it uses. Populated from initserver; before connecting the
// family reads as unknown.
func (c *Client) ServerCapabilities() ServerCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.capabilities
}

// UniqueIdentifier returns our own client_unique_identifier, hashed with the
// algorithm the connected server uses.
//
// TS3 uses SHA-1 and TS6 SHA-256, so this reads the algorithm learned during
// initserver rather than assuming one: comparing a hard-coded SHA-1 UID to a
// TS6 server silently never matches.
func (c *Client) UniqueIdentifier() teamspeak.UID {
	c.mu.Lock()
	defer c.mu.Unlock()

	return teamspeak.UID(identity.UID(c.crypt.Identity.PublicKey(), c.uidAlgorithm))
}

// ClientID returns the id the server assigned this session, or 0 before it
// has. A reconnect gets a new one.
func (c *Client) ClientID() teamspeak.ClientID {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.clid
}

// Status reports the current connection state.
func (c *Client) Status() ClientStatus {
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
