package client

import (
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func TestRoundTrip_FalseBeforeConnect(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.status = StatusDisconnected
	c.mu.Unlock()

	if got, ok := c.RoundTrip(); ok || got != (RoundTripEstimate{}) {
		t.Errorf("RoundTrip = %+v, %v, want false", got, ok)
	}
}

func TestRoundTrip_FalseUntilThePongThenTheHandlersEstimate(t *testing.T) {
	c, server := newTestClientWithPipe(t)
	completeCryptoInit(t, c.handler)
	c.mu.Lock()
	c.status = StatusConnected
	c.mu.Unlock()
	_ = readFromPipe(t, server) // the Init1 from Start

	if got, ok := c.RoundTrip(); ok {
		t.Fatalf("connected, no pong yet: RoundTrip = %+v, true", got)
	}

	// The first ping goes out after transport.PingInterval; answer it.
	var ping []byte
	deadline := time.After(transport.PingInterval + 3*time.Second)
	for ping == nil {
		select {
		case <-deadline:
			t.Fatal("no ping within the ping interval")
		default:
		}
		if raw := readFromPipe(t, server); len(raw) >= 13 && raw[12]&0x0f == byte(transport.PacketTypePing) {
			ping = raw
		}
	}
	time.Sleep(20 * time.Millisecond)

	sig := c.handler.TsCrypt.FakeSignature()
	pong := make([]byte, 8+3+2)
	copy(pong, sig[:])
	pong[10] = byte(transport.PacketTypePong) | byte(transport.PacketFlagUnencrypted)
	copy(pong[11:], ping[8:10]) // the pong carries the ping's id
	if _, err := server.Write(pong); err != nil {
		t.Fatal(err)
	}

	var got RoundTripEstimate
	var ok bool
	for range 100 {
		if got, ok = c.RoundTrip(); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	want, _ := c.handler.RoundTrip()
	if !ok || got.Mean < 20*time.Millisecond || got.Mean != want.Mean || got.Deviation != want.Deviation {
		t.Errorf("RoundTrip = %+v, %v, the handler's is %+v", got, ok, want)
	}

	c.mu.Lock()
	c.status = StatusDisconnected
	c.mu.Unlock()
	if got, ok := c.RoundTrip(); ok {
		t.Errorf("after disconnect: RoundTrip = %+v, true", got)
	}
}
