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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var (
	sharedClient      *teamspeak.Client
	sharedClientEnter chan teamspeak.ClientInfo
	sharedOnce        sync.Once
	errSharedClient   error
)

var (
	integrationServerPassword         = os.Getenv("TEAMSPEAK_SERVER_PASSWORD")
	integrationDefaultChannel         = os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL")
	integrationDefaultChannelPassword = os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")
)

func integrationClientOptions(logger *slog.Logger) []teamspeak.ClientOption {
	opts := make([]teamspeak.ClientOption, 0, 4)
	if logger != nil {
		opts = append(opts, teamspeak.WithLogger(logger))
	}
	if integrationServerPassword != "" {
		opts = append(opts, teamspeak.WithServerPassword(integrationServerPassword))
	}
	if integrationDefaultChannel != "" {
		opts = append(opts, teamspeak.WithDefaultChannel(integrationDefaultChannel))
	}
	if integrationDefaultChannelPassword != "" {
		opts = append(opts, teamspeak.WithDefaultChannelPassword(integrationDefaultChannelPassword))
	}

	return opts
}

func requireTeamSpeakAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set — skip integration test (set TEAMSPEAK_ADDR=host:port to enable)")
	}

	return addr
}

func requireSharedClient(t *testing.T) *teamspeak.Client {
	t.Helper()
	addr := requireTeamSpeakAddr(t)

	sharedOnce.Do(func() {
		id, err := crypto.GenerateIdentity(8)
		if err != nil {
			errSharedClient = err

			return
		}
		c := teamspeak.NewClient(id, addr, "teamspeak-go-integ", integrationClientOptions(nil)...)
		sharedClientEnter = make(chan teamspeak.ClientInfo, 1)
		c.OnClientEnter(func(info teamspeak.ClientInfo) {
			// Compare via the client rather than a precomputed UID: the hash
			// depends on the server version (TS3 SHA-1, TS6 SHA-256), which is
			// only known once the handshake has read initserver.
			if info.UID != "" && info.UID == c.UniqueIdentifier() {
				select {
				case sharedClientEnter <- info:
				default:
				}
			}
		})
		err = c.Connect()
		if err != nil {
			errSharedClient = err

			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = c.WaitConnected(ctx)
		if err != nil {
			errSharedClient = err

			return
		}
		sharedClient = c
	})

	if errSharedClient != nil {
		t.Fatalf("shared client setup failed: %v", errSharedClient)
	}

	return sharedClient
}

func skipOnPermErr(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "insufficient") {
		t.Skipf("skipping — server returned permission error: %v", err)
	}
}

// Tests share one peer in addition to the primary client and the short-lived
// disconnect-test client: at most three rapid connections from the same IP.
var (
	peerOnce   sync.Once
	peerClient *teamspeak.Client
	errPeer    error
	peerLogs   lockedBuffer
)

type lockedBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func requireIntegrationPeer(t *testing.T, addr string) *teamspeak.Client {
	t.Helper()
	peerOnce.Do(func() {
		id, err := crypto.GenerateIdentity(8)
		if err != nil {
			errPeer = err

			return
		}
		logger := slog.New(slog.NewJSONHandler(&peerLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		peerClient = teamspeak.NewClient(id, addr, "teamspeak-go-peer", integrationClientOptions(logger)...)
		errPeer = peerClient.Connect()
		if errPeer != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		errPeer = peerClient.WaitConnected(ctx)
	})
	if errPeer != nil {
		t.Fatalf("peer connection: %v", errPeer)
	}

	return peerClient
}

func TestMain(m *testing.M) {
	code := m.Run()
	if peerClient != nil {
		_ = peerClient.Disconnect()
	}
	if sharedClient != nil {
		_ = sharedClient.Disconnect()
	}
	os.Exit(code)
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func extractJSONField(s string, needle string) string {
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(s[start:], "\"")
	if end < 0 {
		return ""
	}

	return s[start : start+end]
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

func TestIntegration_Connect(t *testing.T) {
	c := requireSharedClient(t)

	clid := c.ClientID()
	if clid == 0 {
		t.Error("expected non-zero client ID after connect")
	}
	t.Logf("connected: clid=%d", clid)
}

func TestIntegration_ConnectWithOptionalHandshakeAuth(t *testing.T) {
	c := requireSharedClient(t)

	t.Logf(
		"connect auth enabled: serverPassword=%t defaultChannel=%t defaultChannelPassword=%t",
		integrationServerPassword != "",
		integrationDefaultChannel != "",
		integrationDefaultChannelPassword != "",
	)
	if c.ClientID() == 0 {
		t.Error("expected non-zero client ID after connect")
	}
}

func TestIntegration_ClientEnterChannelID(t *testing.T) {
	requireSharedClient(t)

	// The welcome-sequence clientEnter may already have been consumed by an
	// earlier test, so fall back to the channel the client reports now rather
	// than depending on test order.
	select {
	case info := <-sharedClientEnter:
		t.Logf("clientEnter: clid=%d cid=%d", info.ID, info.ChannelID)
		if info.ChannelID == 0 {
			t.Error("expected clientEnter to report a non-zero channel ID")
		}
	case <-time.After(2 * time.Second):
		c := requireSharedClient(t)
		t.Logf("clientEnter already consumed; ChannelID()=%d", c.ChannelID())
		if c.ChannelID() == 0 {
			t.Error("expected a non-zero channel ID once connected")
		}
	}
}

func TestIntegration_Disconnect(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	id, err := crypto.GenerateIdentity(8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c := teamspeak.NewClient(id, addr, "teamspeak-go-integ-disc", integrationClientOptions(nil)...)

	err = c.Connect()
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = c.WaitConnected(ctx)
	if err != nil {
		t.Fatalf("WaitConnected: %v", err)
	}

	disconnected := make(chan error, 1)
	c.OnDisconnected(func(e error) { disconnected <- e })

	err = c.Disconnect()
	if err != nil {
		t.Logf("Disconnect returned (non-fatal): %v", err)
	}

	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Error("OnDisconnected not fired after Disconnect()")
	}
}

// ---------------------------------------------------------------------------
// Server queries
// ---------------------------------------------------------------------------

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

func TestIntegration_JoinsConfiguredDefaultChannel(t *testing.T) {
	if integrationDefaultChannel == "" {
		t.Skip("TEAMSPEAK_DEFAULT_CHANNEL not set")
	}

	c := requireSharedClient(t)

	channels, err := c.ListChannels()
	skipOnPermErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	clients, err := c.ListClients()
	skipOnPermErr(t, err)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}

	var self *teamspeak.ClientInfo
	for i := range clients {
		if clients[i].ID == c.ClientID() {
			self = &clients[i]

			break
		}
	}
	if self == nil {
		t.Fatal("expected to find ourselves in client list")
	}

	var currentChannel *teamspeak.ChannelInfo
	for i := range channels {
		if channels[i].ID == self.ChannelID {
			currentChannel = &channels[i]

			break
		}
	}
	if currentChannel == nil {
		t.Fatalf("expected to resolve current channel for cid=%d", self.ChannelID)
	}
	if currentChannel.Name != integrationDefaultChannel {
		t.Fatalf("expected current channel %q, got %q", integrationDefaultChannel, currentChannel.Name)
	}
}

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
	if info["client_nickname"] == "" {
		t.Errorf("expected client_nickname in clientinfo response; got keys: %v", mapKeys(info))
	}
	t.Logf("clientinfo keys: %v", mapKeys(info))
}

// ---------------------------------------------------------------------------
// Text messages
// ---------------------------------------------------------------------------

func TestIntegration_TextPrivateNotifyFields(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	receiver := requireIntegrationPeer(t, addr)

	// Reuse the shared connection as sender to stay within TS3's anti-flood
	// connection budget. The receiver still gets a separate session so the
	// notification crosses the wire between two clients.
	sender := requireSharedClient(t)
	senderInfo, err := sender.GetClientInfo(sender.ClientID())
	if err != nil {
		t.Fatalf("sender GetClientInfo: %v", err)
	}
	senderUID := strings.TrimSpace(senderInfo["client_unique_identifier"])
	t.Logf("sender clientinfo keys: %v", mapKeys(senderInfo))

	received := make(chan teamspeak.TextMessage, 1)
	receiver.OnTextMessage(func(msg teamspeak.TextMessage) {
		select {
		case received <- msg:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	probeText := fmt.Sprintf("cursor-probe-%d", time.Now().UTC().UnixNano())
	err = sender.SendTextMessage(1, uint64(receiver.ClientID()), probeText)
	if err != nil {
		t.Fatalf("sender SendTextMessage private: %v", err)
	}

	var msg teamspeak.TextMessage
	select {
	case msg = <-received:
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for private text notification; logs=%s", peerLogs.String())
	}

	if msg.Message != probeText {
		t.Fatalf("unexpected message text: got %q want %q", msg.Message, probeText)
	}

	logs := peerLogs.String()
	t.Logf("receiver logs: %s", logs)

	if !strings.Contains(logs, "\"name\":\"notifytextmessage\"") {
		t.Fatalf("expected notifytextmessage in logs, got: %s", logs)
	}

	targetNeedle := fmt.Sprintf("\"target\":\"%d\"", receiver.ClientID())
	if !strings.Contains(logs, targetNeedle) {
		t.Fatalf("expected raw notify target %s in logs, got: %s", targetNeedle, logs)
	}

	rawInvokerUID := extractJSONField(logs, "\"invokeruid\":\"")
	if rawInvokerUID == "" {
		t.Fatalf("expected raw notify invokeruid in logs, got: %s", logs)
	}

	if msg.TargetMode != 1 {
		t.Fatalf("unexpected target mode: got %d want 1", msg.TargetMode)
	}

	if msg.TargetID != uint64(receiver.ClientID()) {
		t.Fatalf("parsed TargetID mismatch: got %d want %d", msg.TargetID, receiver.ClientID())
	}

	expectedInvokerUID := rawInvokerUID
	if senderUID != "" {
		expectedInvokerUID = senderUID
	}
	if strings.TrimSpace(msg.InvokerUID) != expectedInvokerUID {
		t.Fatalf("parsed InvokerUID mismatch: got %q want %q", msg.InvokerUID, expectedInvokerUID)
	}
}

// ---------------------------------------------------------------------------
// Poke
// ---------------------------------------------------------------------------

func TestIntegration_PokeSendAndReceive(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	sender := requireSharedClient(t)
	receiver := requireIntegrationPeer(t, addr)

	pokeMsg := fmt.Sprintf("poke-test-%d", time.Now().UTC().UnixNano())

	poked := make(chan teamspeak.PokeEvent, 1)
	receiver.OnPoked(func(e teamspeak.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	err := sender.Poke(receiver.ClientID(), pokeMsg)
	if err != nil {
		t.Fatalf("Poke: %v", err)
	}
	t.Logf("sent poke from clid=%d to clid=%d msg=%q", sender.ClientID(), receiver.ClientID(), pokeMsg)

	select {
	case evt := <-poked:
		t.Logf("poke received: invoker=%q uid=%q msg=%q", evt.InvokerName, evt.InvokerUID, evt.Message)
		if evt.InvokerID != sender.ClientID() {
			t.Errorf("InvokerID mismatch: got %d want %d", evt.InvokerID, sender.ClientID())
		}
		if evt.Message != pokeMsg {
			t.Errorf("Message mismatch: got %q want %q", evt.Message, pokeMsg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for poke notification")
	}
}

func TestIntegration_PokeEmptyMessage(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	sender := requireSharedClient(t)
	receiver := requireIntegrationPeer(t, addr)

	poked := make(chan teamspeak.PokeEvent, 1)
	receiver.OnPoked(func(e teamspeak.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	err := sender.Poke(receiver.ClientID(), "")
	if err != nil {
		t.Fatalf("Poke (empty): %v", err)
	}
	t.Logf("sent empty poke from clid=%d to clid=%d", sender.ClientID(), receiver.ClientID())

	select {
	case evt := <-poked:
		t.Logf("empty poke received: invoker=%q msg=%q", evt.InvokerName, evt.Message)
		if evt.Message != "" {
			t.Errorf("expected empty message, got %q", evt.Message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for empty poke notification")
	}
}
