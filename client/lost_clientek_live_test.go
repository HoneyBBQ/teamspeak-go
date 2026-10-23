//go:build integration

package client_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// commandTypeByte is where the packet type sits in a client datagram: after
// the tag, the packet id and the client id.
const commandTypeByte = 12

// dropFirstCommandConn loses the first Command datagram the client sends,
// which is clientek.
type dropFirstCommandConn struct {
	net.PacketConn

	dropped atomic.Int32
}

func (c *dropFirstCommandConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > commandTypeByte && b[commandTypeByte]&0x0f == 2 && c.dropped.CompareAndSwap(0, 1) {
		return len(b), nil
	}

	return c.PacketConn.WriteTo(b, addr)
}

// clientek goes out under the dummy key and crypto init completes right after
// it, so when its first datagram is lost the resend must still use the dummy
// key: the server cannot decrypt it under any other, and the handshake would
// die on its timeout.
func TestIntegration_ConnectsWhenTheFirstClientEkIsLost(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	lossy := &dropFirstCommandConn{PacketConn: pc}

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	opts := append(integrationClientOptions(nil), client.WithPacketConn(lossy))
	c := newClient(t, id, addr, "lost-clientek", opts...)
	requireNoErr(t, paceConnect(t.Context()))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect with the first clientek lost: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	if lossy.dropped.Load() != 1 {
		t.Errorf("dropped %d datagrams, want the first clientek", lossy.dropped.Load())
	}
	if c.ClientID() == 0 {
		t.Error("no client id assigned")
	}
}
