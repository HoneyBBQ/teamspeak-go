package teamspeak

import (
	"context"
	"errors"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

var errNoDataReturned = errors.New("no data returned")

// SendVoice sends a raw Opus frame. Codec values: 4 = Opus voice, 5 = Opus music.
func (c *Client) SendVoice(data []byte, codec byte) error {
	return c.handler.SendVoicePacket(data, codec)
}

// ErrNoWhisperTargets reports a whisper with no one to receive it.
var ErrNoWhisperTargets = transport.ErrNoWhisperTargets

// ErrTooManyWhisperTargets reports more whisper targets than one packet can
// address.
var ErrTooManyWhisperTargets = transport.ErrTooManyWhisperTargets

// SendWhisper sends Opus voice directly to up to 32 clients, regardless of which
// channel they are in. The bot's server group needs i_client_whisper_power.
func (c *Client) SendWhisper(data []byte, targetClientIDs []uint16, codec byte) error {
	return c.handler.SendWhisperPacket(data, targetClientIDs, codec)
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
func (c *Client) UniqueIdentifier() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return identity.UID(c.crypt.Identity.PublicKey(), c.uidAlgorithm)
}

// ClientID returns the client's own ID assigned by the server.
func (c *Client) ClientID() uint16 {
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

// WaitConnected waits for the connection handshake to be completed.
//
// It returns nil once the handshake completes. If the attempt fails, it returns
// the cause, such as the server's error for a rejected password, rather than
// waiting for ctx to expire. It may be called before or after Connect.
func (c *Client) WaitConnected(ctx context.Context) error {
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
