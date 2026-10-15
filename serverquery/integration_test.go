//go:build integration

package serverquery_test

// Integration tests against live TeamSpeak servers (build tag: integration).
//
// The fixture provisions the server and writes the query credentials for the
// transport it provisioned over:
//
//	TS3_QUERY_HOST=127.0.0.1 ./scripts/ts3-fixture.sh
//	TS3_QUERY_HTTP=127.0.0.1:10080 ./scripts/ts3-fixture.sh
//	set -a; . "${TS3_FIXTURE_ENV:-${TMPDIR:-/tmp}/ts3-fixture.env}"; set +a
//	go test -count=1 -race -tags integration -timeout 300s ./serverquery/
//
// It writes TEAMSPEAK_QUERY_KIND and the host, port and login for the transport
// it used, and the SSH ones too when the server was started with SSH enabled.
// Each test skips when its own transport's variables are unset, so the suite
// runs against whichever endpoints are actually there.
//
// One connection at a time: a server's flood protection bans an IP that
// connects too fast, so the tests that only read share one client.

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/serverquery"
	"github.com/honeybbq/teamspeak-go/versions"
)

// The environment the fixture writes for the query suite.
const (
	envHost     = "TEAMSPEAK_QUERY_HOST"
	envPort     = "TEAMSPEAK_QUERY_PORT"
	envLogin    = "TEAMSPEAK_QUERY_LOGIN_NAME"
	envPassword = "TEAMSPEAK_QUERY_LOGIN_PASSWORD"
	envWebURL   = "TEAMSPEAK_QUERY_URL"
	envAPIKey   = "TEAMSPEAK_QUERY_API_KEY"
	envSSHHost  = "TEAMSPEAK_QUERY_SSH_HOST"
	envSSHPort  = "TEAMSPEAK_QUERY_SSH_PORT"
	envSSHUser  = "TEAMSPEAK_QUERY_SSH_USER"
	envSSHPass  = "TEAMSPEAK_QUERY_SSH_PASSWORD"
)

// waitForOtherSuites stands aside before connecting: the voice suite's live
// client and this one against the same server, or a rerun straight after a
// failure, is what gets an IP flood-banned.
func waitForOtherSuites() {
	if os.Getenv("QUERY_NO_WAIT") != "" {
		return
	}
	time.Sleep(100 * time.Millisecond)
}

// tcpVars are what a raw-protocol test needs, skipping when the fixture ran
// over WebQuery instead.
func tcpVars(t *testing.T) (addr, login, password string) {
	t.Helper()
	host := os.Getenv(envHost)
	port := os.Getenv(envPort)
	login = os.Getenv(envLogin)
	password = os.Getenv(envPassword)
	if host == "" || port == "" || login == "" || password == "" {
		t.Skipf("%s, %s, %s and %s not set — skipping the raw ServerQuery test",
			envHost, envPort, envLogin, envPassword)
	}

	return host + ":" + port, login, password
}

// webVars are what a WebQuery test needs.
func webVars(t *testing.T) (base, apiKey string) {
	t.Helper()
	base = os.Getenv(envWebURL)
	apiKey = os.Getenv(envAPIKey)
	if base == "" || apiKey == "" {
		t.Skipf("%s and %s not set — skipping the WebQuery test", envWebURL, envAPIKey)
	}

	return base, apiKey
}

// sshVars are what an SSH test needs. The fixture writes them only when the
// server was started with SSH enabled, which TS6 does not do by default.
func sshVars(t *testing.T) (addr, user, password string) {
	t.Helper()
	host := os.Getenv(envSSHHost)
	port := os.Getenv(envSSHPort)
	user = os.Getenv(envSSHUser)
	password = os.Getenv(envSSHPass)
	if host == "" || port == "" || user == "" || password == "" {
		t.Skipf("%s, %s, %s and %s not set — skipping the SSH test",
			envSSHHost, envSSHPort, envSSHUser, envSSHPass)
	}

	return host + ":" + port, user, password
}

// assertCoreCommands runs the commands every transport serves, against the
// server the caller opened: the test is about the transport and the session,
// not about the server's contents.
func assertCoreCommands(t *testing.T, c *serverquery.Client, family teamspeak.ServerFamily) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version, err := c.GetVersion(ctx)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version.Version == "" {
		t.Error("GetVersion returned no version string")
	}
	if got := c.ServerFamily(); got != family {
		t.Errorf("ServerFamily = %v, want %v", got, family)
	}

	who, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if who.ClientID == 0 && who.Nickname == "" {
		t.Errorf("WhoAmI described no connection: %+v", who)
	}

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) == 0 {
		t.Error("ListChannels returned no channels; the fixture creates at least one")
	}

	// Stats is what a metrics exporter reads, so it has to describe the live
	// connection.
	stats := c.Stats()
	if stats.Transport == "" || stats.ConnectedAt.IsZero() {
		t.Errorf("Stats = %+v, want the connection's identity", stats)
	}
	if stats.BytesSent == 0 {
		t.Error("Stats reports nothing sent, but commands have been answered")
	}
}

// open connects c and registers a Disconnect for the end of the test.
func open(t *testing.T, c *serverquery.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		// Its own context: the test's may already be done.
		disconnectCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := c.Disconnect(disconnectCtx); err != nil {
			t.Errorf("Disconnect: %v", err)
		}
	})
}

// TeamSpeak 3 over raw ServerQuery: the commands, and a text message from a
// voice client arriving as an event.
func TestQuery_TS3OverTCP(t *testing.T) {
	addr, login, password := tcpVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.TCP(addr),
		serverquery.WithLogin(login, password),
		serverquery.WithServer(1),
		// A logger, so a failure says what the client was doing.
		serverquery.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	if got := c.Status(); got != teamspeak.StatusConnected {
		t.Fatalf("Status = %v, want connected", got)
	}
	assertCoreCommands(t, c, teamspeak.ServerFamilyTS3)

	// This account is serveradmin and the voice client connects as a guest,
	// which the default group does not let send a server message. The fixture
	// grants the permissions the voice suite exercises; this one is the query
	// suite's, so it is granted here.
	grantGuestPermission(t, c, perm.ClientServerTextMessageSend)

	channel := os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL")
	if channel == "" {
		channel = "Alpha"
	}
	heard := make(chan teamspeak.TextMessageEvent, 8)
	c.OnTextMessage(func(e teamspeak.TextMessageEvent) {
		select {
		case heard <- e:
		default:
		}
	})

	sendMessageFromVoiceClient(t, channel)

	select {
	case e := <-heard:
		if e.Message == "" {
			t.Error("the message arrived with no body")
		}
		if e.InvokerName == "" {
			t.Error("the message arrived with no sender")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the text message a voice client sent never arrived")
	}
}

// TeamSpeak 6 over WebQuery: the commands, over the one transport TS6 serves
// by default. No events: the transport reports that it delivers none, so the
// On… methods for server events are inert rather than failing the connect.
func TestQuery_TS6OverWebQuery(t *testing.T) {
	base, apiKey := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.Web(base, apiKey),
		// WebQuery addresses a virtual server in the request path, so one has
		// to be named: without it the server-scoped commands answer 1024,
		// "invalid serverID", the instance having no channels or clients.
		serverquery.WithServer(1),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	assertCoreCommands(t, c, teamspeak.ServerFamilyTS6)

	fired := make(chan struct{}, 1)
	remove := c.OnTextMessage(func(teamspeak.TextMessageEvent) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})
	remove()

	select {
	case <-fired:
		t.Error("a server event arrived over a transport that has none")
	case <-time.After(200 * time.Millisecond):
	}
}

// TeamSpeak 6 over SSH, where the server was started with it: the SSH login
// replaced the query login, so no `login` command is sent and the session is
// the query account as soon as it opens.
func TestQuery_TS6OverSSH(t *testing.T) {
	addr, user, password := sshVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.SSH(addr, user, password),
		serverquery.WithServer(1),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	assertCoreCommands(t, c, teamspeak.ServerFamilyTS6)
}

// grantGuestPermission gives the server's default group a permission, so a
// guest voice client can do what a test needs. It is additive and idempotent;
// the fixture does the same for the permissions the voice suite uses.
func grantGuestPermission(t *testing.T, c *serverquery.Client, permission string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	info, err := c.GetServerInfo(ctx)
	if err != nil {
		t.Fatalf("GetServerInfo: %v", err)
	}
	groupID, err := strconv.ParseUint(info["virtualserver_default_server_group"], 10, 64)
	if err != nil {
		t.Fatalf("the server reported no default server group: %v", err)
	}
	err = c.AddServerGroupPermission(ctx, teamspeak.ServerGroupID(groupID),
		teamspeak.PermissionByName(permission), 1, teamspeak.ServerGroupPermissionOptions{})
	if err != nil {
		t.Fatalf("adding %s to the default group: %v", permission, err)
	}
}

// sendMessageFromVoiceClient connects as a voice client, sends a server-wide
// message, and leaves. It has to be a voice client: a query connection's own
// message does not come back to it as a notification.
func sendMessageFromVoiceClient(t *testing.T, channel string) {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_ADDR not set, so no voice client can send the message")
	}
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	options := []client.Option{client.WithVersion(versions.Windows_3_6_2_1695203293)}
	if password := os.Getenv("TEAMSPEAK_SERVER_PASSWORD"); password != "" {
		options = append(options, client.WithServerPassword(password))
	}
	if channel != "" {
		options = append(options, client.WithDefaultChannel(channel))
	}
	voice, err := client.New(id, addr, "query-itest", options...)
	if err != nil {
		t.Fatalf("voice client New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := voice.Connect(ctx); err != nil {
		t.Fatalf("voice client Connect: %v", err)
	}
	defer func() { _ = voice.Disconnect(context.Background()) }()

	if err := voice.SendServerMessage(ctx, "query integration test"); err != nil {
		t.Fatalf("SendServerMessage: %v", err)
	}
}

// A shared query client for the test that writes, so the server sees one
// connection rather than one per test.
var (
	sharedOnce   sync.Once
	sharedClient *serverquery.Client
	sharedErr    error
)

func sharedQueryClient(t *testing.T) *serverquery.Client {
	t.Helper()
	sharedOnce.Do(func() {
		host := os.Getenv(envHost)
		port := os.Getenv(envPort)
		login := os.Getenv(envLogin)
		password := os.Getenv(envPassword)
		if host == "" || port == "" || login == "" || password == "" {
			return
		}
		sharedClient, sharedErr = serverquery.New(serverquery.TCP(host+":"+port),
			serverquery.WithLogin(login, password),
			serverquery.WithServer(1),
		)
		if sharedErr != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		sharedErr = sharedClient.Connect(ctx)
	})
	if sharedErr != nil {
		t.Fatalf("shared query client: %v", sharedErr)
	}
	if sharedClient == nil {
		t.Skipf("%s, %s, %s and %s not set", envHost, envPort, envLogin, envPassword)
	}

	return sharedClient
}

// A typed command that writes, to prove the session is usable for more than
// reading: the client creates a channel under a fresh name, finds it in the
// list, and removes it again.
func TestQuery_TypedCommandRoundTrip(t *testing.T) {
	c := sharedQueryClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := "query-itest-" + strings.ReplaceAll(time.Now().Format("150405.000"), ".", "")
	cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: name})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	if cid == 0 {
		t.Fatal("CreateChannel returned no channel id")
	}
	defer func() {
		// Force: creating a channel moves this query connection into it, so the
		// channel is never empty and the server refuses a plain delete with
		// 772, "channel not empty".
		delCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := c.DeleteChannel(delCtx, cid, teamspeak.ChannelDeleteOptions{Force: true}); err != nil {
			t.Errorf("DeleteChannel: %v", err)
		}
	}()

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	found := false
	for _, ch := range channels {
		if ch.ID == cid {
			found = true
		}
	}
	if !found {
		t.Errorf("the channel %d the client created is not in the list", cid)
	}
}
