package client

import (
	"net"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

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
