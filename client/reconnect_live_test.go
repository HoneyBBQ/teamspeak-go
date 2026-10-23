//go:build integration

package client_test

import (
	"context"
	"regexp"
	"strings"
	"sync"
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
			Backoff: client.BackoffPolicy{
				InitialDelay: 500 * time.Millisecond,
				MaxDelay:     4 * time.Second,
				Factor:       2,
			},
		}),
	)

	c := newClient(t, id, addr, "go-reconnect", opts...)
	err = connectWithRetries(t.Context(), t, c)
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
	// Commands keep arriving from other goroutines while the connection
	// drops and comes back; see sendCommandsUntilStopped.
	defer sendCommandsUntilStopped(t, c)()

	// The reconnection the drop causes is a connection like any other.
	requireNoErr(t, paceConnect(t.Context()))
	dropErr := c.DropConnectionForTest()
	if dropErr != nil {
		t.Fatalf("drop connection: %v", dropErr)
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if c.Status() == client.StatusConnected && c.ClientID() != firstID && c.ClientID() != 0 {
			t.Logf("recovered, clid=%d (was %d)", c.ClientID(), firstID)

			_, listErr := c.ListChannels(t.Context(), teamspeak.ChannelListOptions{})
			if listErr != nil {
				t.Errorf("reconnected session is not usable: %v", listErr)
			}

			return
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("did not reconnect within the deadline (status=%v clid=%d)", c.Status(), c.ClientID())
}

// A client that asked for a taken name is renamed by the server ("name" becomes
// "name1"). After a drop it must ask for "name" again: asking for "name1" while
// the old session still holds it would give "name12", and so on at every drop.
//
//nolint:funlen // one scenario, step by step
func TestIntegration_ReconnectAsksForTheRequestedNickname(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	const requested = "go-nick-taken"

	holderID, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	holder := newClient(t, holderID, addr, requested, integrationClientOptions(nil)...)
	requireNoErr(t, connectWithRetries(t.Context(), t, holder))
	t.Cleanup(func() { _ = holder.Disconnect(context.Background()) })

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	opts := append(integrationClientOptions(nil),
		client.WithReconnect(client.ReconnectOptions{
			Backoff: client.BackoffPolicy{InitialDelay: 500 * time.Millisecond, MaxDelay: 4 * time.Second, Factor: 2},
		}),
	)
	c := newClient(t, id, addr, requested, opts...)
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	nameOf := func() string {
		rows, listErr := c.ListClients(t.Context(), teamspeak.ClientListOptions{})
		if listErr != nil {
			t.Fatalf("ListClients: %v", listErr)
		}
		for _, row := range rows {
			if row.ID == c.ClientID() {
				return row.Nickname
			}
		}

		return ""
	}
	first := nameOf()
	if first == requested || !strings.HasPrefix(first, requested) {
		t.Fatalf("nickname = %q, want %q with a suffix", first, requested)
	}
	firstID := c.ClientID()

	requireNoErr(t, paceConnect(t.Context()))
	requireNoErr(t, c.DropConnectionForTest())

	deadline := time.Now().Add(90 * time.Second)
	for c.Status() != client.StatusConnected || c.ClientID() == firstID || c.ClientID() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("did not reconnect within the deadline (status=%v)", c.Status())
		}
		time.Sleep(250 * time.Millisecond)
	}

	// One digit more would mean it asked for the name it was given.
	if got := nameOf(); !regexp.MustCompile("^" + requested + `\d$`).MatchString(got) {
		t.Errorf("nickname after the reconnect = %q, want %q and one digit", got, requested)
	}
}

func TestIntegration_NoReconnectAfterExplicitDisconnect(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	opts := append(integrationClientOptions(nil),
		client.WithReconnect(client.ReconnectOptions{
			Backoff: client.BackoffPolicy{InitialDelay: 200 * time.Millisecond},
		}),
	)

	c := newClient(t, id, addr, "go-noreconnect", opts...)
	err = connectWithRetries(t.Context(), t, c)
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

// sendCommandsUntilStopped sends commands, raw lines and voice from three
// goroutines, as a bot would, until the returned function is called. Run under
// -race across a reconnect it checks that none of them reads the handler or
// its crypto state while the reconnect replaces it; failing with
// ErrNotConnected meanwhile is fine.
func sendCommandsUntilStopped(t *testing.T, c *client.Client) func() {
	t.Helper()
	stop := make(chan struct{})
	var senders sync.WaitGroup
	for range 3 {
		senders.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				_, _ = c.WhoAmI(ctx)
				_ = c.ExecNoWait(ctx, "clientupdate client_away=0")
				_ = c.SendVoice([]byte{0}, teamspeak.CodecOpusVoice, client.VoiceOptions{})
				cancel()
				time.Sleep(100 * time.Millisecond)
			}
		})
	}

	return func() {
		close(stop)
		senders.Wait()
	}
}
