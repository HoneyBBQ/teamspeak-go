//go:build integration

package client_test

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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var (
	sharedClient      *client.Client
	sharedClientEnter chan teamspeak.ClientInfo
	sharedOnce        sync.Once
	errSharedClient   error
)

var (
	integrationServerPassword         = os.Getenv("TEAMSPEAK_SERVER_PASSWORD")
	integrationDefaultChannel         = os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL")
	integrationDefaultChannelPassword = os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")
)

func integrationClientOptions(logger *slog.Logger) []client.Option {
	opts := make([]client.Option, 0, 4)
	if logger != nil {
		opts = append(opts, client.WithLogger(logger))
	}
	if integrationServerPassword != "" {
		opts = append(opts, client.WithServerPassword(integrationServerPassword))
	}
	if integrationDefaultChannel != "" {
		opts = append(opts, client.WithDefaultChannel(integrationDefaultChannel))
	}
	if integrationDefaultChannelPassword != "" {
		opts = append(opts, client.WithDefaultChannelPassword(integrationDefaultChannelPassword))
	}

	return opts
}

// newClient builds a client, failing the test if the configuration is rejected.
func newClient(t *testing.T, id *identity.Identity, addr, nickname string, opts ...client.Option) *client.Client {
	t.Helper()
	c, err := client.New(id, addr, nickname, opts...)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	return c
}

func requireTeamSpeakAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set — skip integration test (set TEAMSPEAK_ADDR=host:port to enable)")
	}

	return addr
}

func requireSharedClient(t *testing.T) *client.Client {
	t.Helper()
	addr := requireTeamSpeakAddr(t)

	sharedOnce.Do(func() {
		id, err := identity.Generate(context.Background(), 8)
		if err != nil {
			errSharedClient = err

			return
		}
		c := newClient(t, id, addr, "teamspeak-go-integ", integrationClientOptions(nil)...)
		sharedClientEnter = make(chan teamspeak.ClientInfo, 1)
		c.OnClientEnter(func(enter client.ClientEnterEvent) {
			info := enter.ClientInfo
			// Compare via the client rather than a precomputed UID: the hash
			// depends on the server version (TS3 SHA-1, TS6 SHA-256), which is
			// only known once the handshake has read initserver.
			if info.UID != "" && info.UID == c.UID() {
				select {
				case sharedClientEnter <- info:
				default:
				}
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = c.Connect(ctx)
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

// requireNoErr fails the test on any error.
//
// It used to skip on a permission error instead. The fixture grants what the
// suite needs, so a refusal is a failure; skipping is how a suite passes while
// testing nothing.
func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Tests share one peer in addition to the primary client and the short-lived
// disconnect-test client: at most three rapid connections from the same IP.
var (
	peerOnce   sync.Once
	peerClient *client.Client
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

func requireIntegrationPeer(t *testing.T, addr string) *client.Client {
	t.Helper()
	peerOnce.Do(func() {
		id, err := identity.Generate(context.Background(), 8)
		if err != nil {
			errPeer = err

			return
		}
		logger := slog.New(slog.NewJSONHandler(&peerLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		peerClient = newClient(t, id, addr, "teamspeak-go-peer", integrationClientOptions(logger)...)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		errPeer = peerClient.Connect(ctx)
	})
	if errPeer != nil {
		t.Fatalf("peer connection: %v", errPeer)
	}

	return peerClient
}

func TestMain(m *testing.M) {
	code := m.Run()
	if peerClient != nil {
		_ = peerClient.Disconnect(context.Background())
	}
	if sharedClient != nil {
		_ = sharedClient.Disconnect(context.Background())
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

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c := newClient(t, id, addr, "teamspeak-go-integ-disc", integrationClientOptions(nil)...)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	disconnected := make(chan error, 1)
	c.OnDisconnected(func(e error) { disconnected <- e })

	err = c.Disconnect(context.Background())
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

	clients, err := c.ListClients(t.Context(), teamspeak.ClientListOptions{})
	requireNoErr(t, err)
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

// The times are unix seconds and client_idle_time milliseconds; reading the
// latter as seconds made a bot idle for two seconds look idle for half an hour.
func TestIntegration_ListClientsTimes(t *testing.T) {
	c := requireSharedClient(t)

	clients, err := c.ListClients(t.Context(), teamspeak.ClientListOptions{Times: true})
	requireNoErr(t, err)
	idx := slices.IndexFunc(clients, func(cl teamspeak.ClientInfo) bool { return cl.ID == c.ClientID() })
	if idx < 0 {
		t.Fatal("own client not in clientlist")
	}
	self := clients[idx]
	t.Logf("self: created=%v lastconnected=%v idle=%v", self.Created, self.LastConnected, self.IdleTime)
	if self.Created.IsZero() || time.Since(self.Created) < 0 {
		t.Errorf("Created = %v, want a time in the past", self.Created)
	}
	if self.IdleTime < 0 || self.IdleTime > 10*time.Minute {
		t.Errorf("IdleTime = %v, want under the suite's own run time", self.IdleTime)
	}
}

func TestIntegration_ListChannels(t *testing.T) {
	c := requireSharedClient(t)

	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
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

	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	clients, err := c.ListClients(t.Context(), teamspeak.ClientListOptions{})
	requireNoErr(t, err)
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

	var currentChannel *teamspeak.Channel
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

	info, err := c.GetClientInfo(t.Context(), c.ClientID())
	requireNoErr(t, err)
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

// The typed TextMessageEvent has to carry what the raw notification did: the
// target, which channel and server messages lack, and the sender's uid. The
// raw notification arrives through OnNotification, which this also checks
// live.
func TestIntegration_TextPrivateNotifyFields(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	receiver := requireIntegrationPeer(t, addr)

	// Reuse the shared connection as sender to stay within TS3's anti-flood
	// connection budget. The receiver still gets a separate session so the
	// notification crosses the wire between two clients.
	sender := requireSharedClient(t)
	senderInfo, err := sender.GetClientInfo(t.Context(), sender.ClientID())
	requireNoErr(t, err)
	senderUID := teamspeak.UID(strings.TrimSpace(senderInfo["client_unique_identifier"]))

	probeText := fmt.Sprintf("cursor-probe-%d", time.Now().UTC().UnixNano())
	received := make(chan client.TextMessageEvent, 1)
	defer receiver.OnTextMessage(func(msg client.TextMessageEvent) {
		if msg.Message == probeText {
			received <- msg
		}
	})()
	raw := make(chan client.NotificationEvent, 1)
	defer receiver.OnNotification(func(n client.NotificationEvent) {
		if n.Name == "notifytextmessage" && n.Params["msg"] == probeText {
			raw <- n
		}
	})()

	time.Sleep(500 * time.Millisecond)
	requireNoErr(t, sender.SendPrivateMessage(t.Context(), receiver.ClientID(), probeText))

	msg := awaitLive(t, received, "the private text message")
	notification := awaitLive(t, raw, "the raw notifytextmessage")

	if want := strconv.FormatUint(uint64(receiver.ClientID()), 10); notification.Params["target"] != want {
		t.Errorf("raw target = %q, want %s", notification.Params["target"], want)
	}
	if msg.TargetMode != teamspeak.TextMessageTargetClient {
		t.Errorf("target mode = %v, want %v", msg.TargetMode, teamspeak.TextMessageTargetClient)
	}
	if msg.TargetID != receiver.ClientID() {
		t.Errorf("TargetID = %d, want %d", msg.TargetID, receiver.ClientID())
	}
	expectedInvokerUID := teamspeak.UID(notification.Params["invokeruid"])
	if senderUID != "" {
		expectedInvokerUID = senderUID
	}
	if msg.InvokerUID == "" || msg.InvokerUID != expectedInvokerUID {
		t.Errorf("InvokerUID = %q, want %q", msg.InvokerUID, expectedInvokerUID)
	}
}

// awaitLive waits for one value from ch, failing the test after ten seconds.
func awaitLive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s; receiver logs: %s", what, peerLogs.String())

		var zero T

		return zero
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

	poked := make(chan client.PokeEvent, 1)
	receiver.OnPoked(func(e client.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	err := sender.PokeClient(t.Context(), receiver.ClientID(), pokeMsg)
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

	poked := make(chan client.PokeEvent, 1)
	receiver.OnPoked(func(e client.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	err := sender.PokeClient(t.Context(), receiver.ClientID(), "")
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
