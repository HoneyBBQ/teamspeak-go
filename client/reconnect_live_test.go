//go:build integration

package client_test

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
)

func TestIntegration_ReconnectsAfterADrop(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	// The client dials its own socket here rather than taking a caller-owned
	// PacketConn: the adapter deliberately does not close what it was given, so
	// a PacketConn-based drop cannot be undone and the reconnect would have
	// nothing to connect through.
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	opts := append(integrationClientOptions(nil),
		client.WithReconnect(client.ReconnectOptions{
			Enabled: true,
			Backoff: client.BackoffPolicy{
				InitialDelay: 500 * time.Millisecond,
				MaxDelay:     4 * time.Second,
				Factor:       2,
			},
		}),
	)

	c := newClient(t, id, addr, "go-reconnect", opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	firstID := c.ClientID()
	if firstID == 0 {
		t.Fatal("expected a client id")
	}
	t.Logf("connected, clid=%d", firstID)

	// Drop the session the way the network would: the handler's idle timeout
	// fires when nothing arrives, and closing the socket from underneath is the
	// same path. TestReconnectLoopRetries below covers the retry behaviour
	// without needing a real drop.
	dropErr := c.DropConnectionForTest()
	if dropErr != nil {
		t.Fatalf("drop connection: %v", dropErr)
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if c.Status() == client.StatusConnected && c.ClientID() != firstID && c.ClientID() != 0 {
			t.Logf("recovered, clid=%d (was %d)", c.ClientID(), firstID)

			_, listErr := c.ListChannels(t.Context())
			if listErr != nil {
				t.Errorf("reconnected session is not usable: %v", listErr)
			}

			return
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("did not reconnect within the deadline (status=%v clid=%d)", c.Status(), c.ClientID())
}

func TestIntegration_NoReconnectAfterExplicitDisconnect(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	opts := append(integrationClientOptions(nil),
		client.WithReconnect(client.ReconnectOptions{
			Enabled: true,
			Backoff: client.BackoffPolicy{InitialDelay: 200 * time.Millisecond},
		}),
	)

	c := newClient(t, id, addr, "go-noreconnect", opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	err = c.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	// Well past the first retry delay: a deliberate disconnect must stay down.
	time.Sleep(3 * time.Second)

	if c.Status() != client.StatusDisconnected {
		t.Errorf("status = %v, want disconnected", c.Status())
	}
}

func TestDefaultShouldRetry_TransientIsRetried(t *testing.T) {
	// 521 is the server holding the dropped session, which clears itself.
	if !client.DefaultShouldRetry(&teamspeak.ServerError{Code: errcode.ClientTooManyClonesConnected}, 1) {
		t.Error("521 should be retried: it clears once the server reaps the zombie")
	}
	// A ban does not clear.
	if client.DefaultShouldRetry(&teamspeak.ServerError{Code: errcode.ConnectFailedBanned}, 1) {
		t.Error("3329 should not be retried")
	}
	// A plain transport failure is worth another attempt.
	if !client.DefaultShouldRetry(syscall.ECONNREFUSED, 1) {
		t.Error("a transport failure should be retried")
	}
}
