package client

import (
	"net"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ParseServerCapabilities is parseServerCapabilities, for the external tests.
var ParseServerCapabilities = parseServerCapabilities

// DropConnectionForTest closes the transport out from under the client, which
// is what a network failure does. Exported to the test binary only, so the
// integration test can exercise reconnection without a real outage.
func (c *Client) DropConnectionForTest() error {
	c.mu.Lock()
	handler := c.handler
	c.mu.Unlock()

	if handler == nil {
		return nil
	}

	return handler.Close()
}

// SetPacketConnForTest installs a transport for the next Connect, so a test can
// supply a caller-owned socket.
func (c *Client) SetPacketConnForTest(pc net.PacketConn) {
	c.mu.Lock()
	c.packetConn = pc
	c.mu.Unlock()
}

// ReconnectingForTest reports whether a retry loop is running.
func (c *Client) ReconnectingForTest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.reconnecting
}

var _ = transport.PacketTypeCommand
var _ = time.Second

// KnownClientForTest returns what the client currently remembers of a client in
// view, for tests that check the list is kept fresh.
func (c *Client) KnownClientForTest(id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.clients[id]

	return e, ok
}

// SendVoiceEncryptedForTest sends a voice frame encrypted instead of in the
// clear, to measure how the server treats it.
func (c *Client) SendVoiceEncryptedForTest(data []byte, codec teamspeak.Codec) error {
	h := c.connectedHandler()
	if h == nil {
		return teamspeak.ErrNotConnected
	}

	return h.SendVoicePacketEncrypted(data, byte(codec))
}

// SeedVoiceCounterForTest sets the next outer id of the Voice or VoiceWhisper
// packets sent, so a test can reach the 16-bit wrap quickly.
func (c *Client) SeedVoiceCounterForTest(whisper bool, id uint16, gen uint32) {
	t := transport.PacketTypeVoice
	if whisper {
		t = transport.PacketTypeVoiceWhisper
	}
	c.connectedHandler().SeedPacketCounter(t, id, gen)
}
