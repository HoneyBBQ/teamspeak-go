//go:build integration

package teamspeak_test

// Integration tests against a live TeamSpeak 3 server (build tag: integration).
//
// Run locally:
//
//	docker compose -f docker-compose.integration.yml up -d --wait
//	TEAMSPEAK_ADDR=127.0.0.1:9987 go test -tags integration ./... -v -timeout 120s
//	docker compose -f docker-compose.integration.yml down
//
// In CI the server is provided by the workflow's service container and
// TEAMSPEAK_ADDR is set automatically.
//
// # Notes
//
//   - A single shared client is reused across tests to avoid TS3 anti-flood
//     protection, which bans IPs that establish too many connections quickly.
//   - Some commands (clientlist, channellist) require elevated server group
//     permissions that the default "Guest" group does not have.  Those tests
//     skip automatically instead of failing hard.

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

// sharedClient is one connection for the whole integration test binary.

var (
	sharedClient *teamspeak.Client
	sharedOnce   sync.Once
	sharedErr    error
)

// requireTeamSpeakAddr skips unless TEAMSPEAK_ADDR is set (opt-in integration runs).
func requireTeamSpeakAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set — skip integration test (set TEAMSPEAK_ADDR=host:port to enable)")
	}
	return addr
}

// requireSharedClient returns a connected client, establishing the connection
// exactly once for the entire test binary. If the connection fails the calling
// test is Fatal'd.
func requireSharedClient(t *testing.T) *teamspeak.Client {
	t.Helper()
	addr := requireTeamSpeakAddr(t)

	sharedOnce.Do(func() {
		id, err := crypto.GenerateIdentity(8)
		if err != nil {
			sharedErr = err
			return
		}
		c := teamspeak.NewClient(id, addr, "teamspeak-go-integ")
		if err = c.Connect(); err != nil {
			sharedErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err = c.WaitConnected(ctx); err != nil {
			sharedErr = err
			return
		}
		sharedClient = c
	})

	if sharedErr != nil {
		t.Fatalf("shared client setup failed: %v", sharedErr)
	}
	return sharedClient
}

// skipOnPermErr skips on TS3 "insufficient permissions"
// error (id=2568). These occur on servers where the Guest group is restricted
// to the vanilla defaults.
func skipOnPermErr(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "insufficient") {
		t.Skipf("skipping — server returned permission error: %v", err)
	}
}

// TestIntegration_Connect verifies the full handshake succeeds and the client
// receives a valid server-assigned client ID.
func TestIntegration_Connect(t *testing.T) {
	c := requireSharedClient(t)

	clid := c.ClientID()
	if clid == 0 {
		t.Error("expected non-zero client ID after connect")
	}
	t.Logf("connected: clid=%d", clid)
}

// TestIntegration_ListClients verifies the clientlist command.
// Skipped automatically if the server denies permission.
func TestIntegration_ListClients(t *testing.T) {
	c := requireSharedClient(t)

	clients, err := c.ListClients()
	skipOnPermErr(t, err)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) == 0 {
		t.Fatal("expected at least one client (ourselves)")
	}

	ownID := c.ClientID()
	found := false
	for _, cl := range clients {
		if cl.ID == ownID {
			found = true
			t.Logf("self: clid=%d nick=%q cid=%d", cl.ID, cl.Nickname, cl.ChannelID)
			break
		}
	}
	if !found {
		t.Errorf("own clid=%d not found in clientlist", ownID)
	}
}

// TestIntegration_ListChannels verifies the channellist command.
// Skipped automatically if the server denies permission.
func TestIntegration_ListChannels(t *testing.T) {
	c := requireSharedClient(t)

	channels, err := c.ListChannels()
	skipOnPermErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) == 0 {
		t.Fatal("expected at least one channel (default channel)")
	}
	t.Logf("channels: %d found, first=%q", len(channels), channels[0].Name)
}

// TestIntegration_GetClientInfo verifies that fetching our own client info
// returns a non-empty response. Some fields may be absent due to server
// permission restrictions.
func TestIntegration_GetClientInfo(t *testing.T) {
	c := requireSharedClient(t)

	info, err := c.GetClientInfo(c.ClientID())
	skipOnPermErr(t, err)
	if err != nil {
		t.Fatalf("GetClientInfo: %v", err)
	}
	if len(info) == 0 {
		t.Fatal("expected non-empty client info map")
	}
	// client_nickname is always present (it is the client's own info).
	if info["client_nickname"] == "" {
		t.Errorf("expected client_nickname in clientinfo response; got keys: %v", mapKeys(info))
	}
	t.Logf("clientinfo keys: %v", mapKeys(info))
}

// TestIntegration_Disconnect verifies that OnDisconnected fires after an
// explicit Disconnect() call. Uses a separate dedicated client.
func TestIntegration_Disconnect(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	id, err := crypto.GenerateIdentity(8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c := teamspeak.NewClient(id, addr, "teamspeak-go-integ-disc")

	if err = c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = c.WaitConnected(ctx); err != nil {
		t.Fatalf("WaitConnected: %v", err)
	}

	disconnected := make(chan error, 1)
	c.OnDisconnected(func(e error) { disconnected <- e })

	if err = c.Disconnect(); err != nil {
		t.Logf("Disconnect returned (non-fatal): %v", err)
	}

	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Error("OnDisconnected not fired after Disconnect()")
	}
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
