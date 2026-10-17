//go:build integration

package client_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"

	"github.com/honeybbq/teamspeak-go/identity"
)

// WithPacketConn exists so an application can supply its own transport. It has
// to work as well as the built-in dialling path, not merely compile: this runs
// a full handshake over a socket the caller created and owns.
func TestIntegration_CustomPacketConn(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	opts := append(integrationClientOptions(nil), client.WithPacketConn(pc))
	c := newClient(t, id, addr, "custom-packetconn", opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	requireNoErr(t, paceConnect(ctx))
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect over a caller-supplied PacketConn: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	if c.ClientID() == 0 {
		t.Error("expected the server to assign a client id over the custom transport")
	}
	t.Logf("connected over caller-supplied PacketConn, clid=%d", c.ClientID())

	reconnectOnSamePacketConn(t, c)
}

// reconnectOnSamePacketConn disconnects c and connects it again on the same
// PacketConn. The first connection's reader must have stopped, or it would
// take the second's datagrams and the handshake would stall.
func reconnectOnSamePacketConn(t *testing.T, c *client.Client) {
	t.Helper()
	err := c.Disconnect(t.Context())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	// Both servers ignore a new handshake from the address of a session that
	// ended a moment ago — measured at three to four seconds — so a second
	// connection from the same port has to wait that out.
	time.Sleep(5 * time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	requireNoErr(t, paceConnect(ctx))
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("second Connect on the same PacketConn: %v", err)
	}
	_, err = c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("command on the second connection: %v", err)
	}
}
