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
// connects too fast, so the tests wait for each other and keep the number of
// connections down.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/livetest"
	"github.com/honeybbq/teamspeak-go/internal/sshalgo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

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
	envFamily   = "TEAMSPEAK_QUERY_FAMILY"
)

// serverFamily is the generation the fixture read from the server's version:
// what the client's own detection is checked against. TS6 where the fixture
// wrote none, as the suite once only met TS6 over WebQuery and SSH.
func serverFamily() teamspeak.ServerFamily {
	if os.Getenv(envFamily) == "ts3" {
		return teamspeak.ServerFamilyTS3
	}

	return teamspeak.ServerFamilyTS6
}

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
func tcpVars(t *testing.T) (string, string, string) {
	t.Helper()
	host := os.Getenv(envHost)
	port := os.Getenv(envPort)
	login := os.Getenv(envLogin)
	password := os.Getenv(envPassword)
	if host == "" || port == "" || login == "" || password == "" {
		t.Skipf("%s, %s, %s and %s not set — skipping the raw ServerQuery test",
			envHost, envPort, envLogin, envPassword)
	}

	return host + ":" + port, login, password
}

// webVars are what a WebQuery test needs.
func webVars(t *testing.T) (string, string) {
	t.Helper()
	base := os.Getenv(envWebURL)
	apiKey := os.Getenv(envAPIKey)
	if base == "" || apiKey == "" {
		t.Skipf("%s and %s not set — skipping the WebQuery test", envWebURL, envAPIKey)
	}

	return base, apiKey
}

// sshVars are what an SSH test needs. The fixture writes them only when the
// server was started with SSH enabled, which TS6 does not do by default.
func sshVars(t *testing.T) (string, string, string) {
	t.Helper()
	host := os.Getenv(envSSHHost)
	port := os.Getenv(envSSHPort)
	user := os.Getenv(envSSHUser)
	password := os.Getenv(envSSHPass)
	if host == "" || port == "" || user == "" || password == "" {
		t.Skipf("%s, %s, %s and %s not set — skipping the SSH test",
			envSSHHost, envSSHPort, envSSHUser, envSSHPass)
	}

	// Registered before the test opens its session, so it runs after the
	// session is closed.
	t.Cleanup(sshTeardown)

	return host + ":" + port, user, password
}

// sshTeardownTime is how long a TeamSpeak 3 server needs to finish closing an
// SSH query session.
const sshTeardownTime = 50 * time.Millisecond

// sshTeardown waits out the end of an SSH session. A TeamSpeak 3 server that is
// still closing one accepts the next connection, whatever its transport, and
// closes it at once with nothing read, which a client reports as EOF before any
// response (measured on 3.13.8: 4 to 14 requests in 100 sent straight after an
// SSH close, none from 3 ms on). The server logs "Bad file descriptor" for them.
// TeamSpeak 6 and a raw session's end do not do it. The server drops the
// connection, so the suite waits rather than retrying: a retry cannot know the
// command was not run. The SDK does nothing for it. See the "Server behaviour
// the SDK works around" section of the serverquery package documentation.
func sshTeardown() { time.Sleep(sshTeardownTime) }

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
	if got := c.ServerVersion(); got != version.Version {
		t.Errorf("ServerVersion = %q, want the version command's %q", got, version.Version)
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
	err := c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		// Its own context: the test's may already be done.
		disconnectCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		disconnectErr := c.Disconnect(disconnectCtx)
		if disconnectErr != nil {
			t.Errorf("Disconnect: %v", disconnectErr)
		}
	})
}

// TeamSpeak 3 over raw ServerQuery: the commands, and the events the
// connection delivers.
func TestQuery_TS3OverTCP(t *testing.T) {
	addr, login, password := tcpVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.TCPLogin(addr, login, password),
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

	t.Run("text message", func(t *testing.T) { assertTextMessageEvent(t, c) })
	t.Run("own channel kick", func(t *testing.T) { assertOwnChannelKick(t, c) })
}

// With no server selected the server refuses servernotifyregister and
// clientlist (1024) and answers the instance-level commands, so a client with
// no WithServer connects, and registers its events at the first Use.
func TestQuery_TCPWithNoServerSelectsOneLater(t *testing.T) {
	addr, login, password := tcpVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.TCPLogin(addr, login, password))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	servers, err := c.ListServers(ctx, teamspeak.ServerListOptions{})
	if err != nil || len(servers) == 0 {
		t.Fatalf("ListServers with no server selected: %d servers, %v", len(servers), err)
	}
	err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	rows, err := c.Exec(ctx, "whoami")
	if err != nil || len(rows) != 1 || rows[0]["client_id"] == "" {
		t.Fatalf("whoami after Use: %v, %v", rows, err)
	}
}

// WebQuery, which TeamSpeak 3 (3.12 and later) and TeamSpeak 6 both serve, and
// the one transport TS6 has on by default: the commands. No events: the
// transport reports that it delivers none, so the On… methods for server events
// are inert rather than failing the connect.
func TestQuery_OverWebQuery(t *testing.T) {
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

	assertCoreCommands(t, c, serverFamily())

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

// SSH, on a TeamSpeak 3 (3.3 and later) or TeamSpeak 6 server started with it:
// the SSH login replaced the query login, so no `login` command is sent and the
// session is the query account as soon as it opens. SSH is also the one
// transport on TS6 that delivers events, so they are checked here, on the same
// connection.
//
// No nickname is set on purpose: a client that found its own id by matching
// its nickname would lose its own kick when it had none.
func TestQuery_OverSSH(t *testing.T) {
	addr, user, password := sshVars(t)
	waitForOtherSuites()

	// The host key is verified, never accepted blindly: against the caller's
	// known_hosts file when there is one, and otherwise against the key this
	// server presents.
	check, err := serverquery.KnownHosts(livetest.KnownHostsFor(t, addr))
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	c, err := serverquery.New(serverquery.SSHWith(addr, user, password,
		serverquery.SSHOptions{HostKeyCheck: check}),
		serverquery.WithServer(1),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)

	assertCoreCommands(t, c, serverFamily())

	t.Run("text message", func(t *testing.T) { assertTextMessageEvent(t, c) })
	t.Run("own channel kick", func(t *testing.T) { assertOwnChannelKick(t, c) })
}

// rawShell opens a plain SSH shell on the query server, past the package's own
// transport, so a test can write what it likes and see every line that comes
// back. It returns the writer and the lines, with blanks dropped.
func rawShell(t *testing.T) (func(string), <-chan string) {
	t.Helper()
	addr, user, password := sshVars(t)
	waitForOtherSuites()

	callback, err := knownhosts.New(livetest.KnownHostsFor(t, addr))
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback:   callback,
		HostKeyAlgorithms: sshalgo.HostKeyAlgorithms(),
		Timeout:           10 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	err = session.Shell()
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}

	lines := scanLines(stdout)
	write := func(s string) {
		_, err := io.WriteString(stdin, s)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	return write, lines
}

// scanLines delivers the non-blank lines of r, and closes the channel at its end.
func scanLines(r io.Reader) <-chan string {
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				lines <- line
			}
		}
	}()

	return lines
}

// untilError reads lines up to and including the next error line.
func untilError(t *testing.T, lines <-chan string) []string {
	t.Helper()
	var got []string
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("connection ended; saw %q", got)
			}
			got = append(got, line)
			if strings.HasPrefix(line, "error ") {
				return got
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no error line; saw %q", got)
		}
	}
}

// The SSH transport writes an empty line to release a reply the server holds
// back. That rests on the server taking an empty line and sending nothing for
// it, which this pins on a raw SSH shell: no reply line arrives for it, and
// the next command is answered as usual.
func TestQuery_SSHEmptyLineGetsNoReply(t *testing.T) {
	write, lines := rawShell(t)

	// A command first, to be sure the session is up.
	write("use 1\n")
	untilError(t, lines)

	write("\n")
	select {
	case line := <-lines:
		t.Fatalf("an empty line was answered with %q", line)
	case <-time.After(time.Second):
	}

	write("version\n")
	got := untilError(t, lines)
	t.Logf("lines after the next command: %q", got)
	if len(got) != 2 || !strings.HasPrefix(got[0], "version=") ||
		!strings.HasPrefix(got[1], "error id=0 msg=ok") {
		t.Fatalf("version answered %q", got)
	}
}

// A server that is not the one recorded is refused before the login goes
// anywhere, so the password is never offered to it and the refusal does not
// read as bad credentials. The two ways of not being the recorded server are
// told apart by the ssh library's own error, which the package wraps.
func TestQuery_SSHRefusesUnrecordedHostKey(t *testing.T) {
	addr, _, _ := sshVars(t)

	t.Run("key changed", func(t *testing.T) {
		// A key generated here, recorded for the server's own address: what a
		// server answering in place of the real one looks like.
		stranger, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		public, err := ssh.NewPublicKey(stranger)
		if err != nil {
			t.Fatalf("ssh.NewPublicKey: %v", err)
		}

		keyErr := refusedHostKey(t, livetest.WriteKnownHosts(t, addr, public))
		if len(keyErr.Want) == 0 {
			t.Error("a changed key was reported as an unknown host: Want is empty")
		}
	})

	t.Run("host not recorded", func(t *testing.T) {
		// The right key, recorded for another port: what a mistyped port looks
		// like.
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("SSH address %q: %v", addr, err)
		}
		number, err := strconv.Atoi(port)
		if err != nil {
			t.Fatalf("SSH port %q: %v", port, err)
		}
		elsewhere := net.JoinHostPort(host, strconv.Itoa(number+1))
		path := livetest.WriteKnownHosts(t, elsewhere, livetest.PresentedHostKey(t, addr))

		keyErr := refusedHostKey(t, path)
		if len(keyErr.Want) != 0 {
			t.Errorf("an unknown host was reported as a changed key: Want = %v", keyErr.Want)
		}
	})
}

// refusedHostKey connects to the SSH server checking its key against the
// known_hosts file at path, and asserts the connect is refused for the key and
// for nothing else. It returns the ssh library's error for the caller to tell
// an unknown host from a changed key.
func refusedHostKey(t *testing.T, path string) *knownhosts.KeyError {
	t.Helper()
	addr, user, password := sshVars(t)
	waitForOtherSuites()

	check, err := serverquery.KnownHosts(path)
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	c, err := serverquery.New(serverquery.SSHWith(addr, user, password,
		serverquery.SSHOptions{HostKeyCheck: check}),
		serverquery.WithServer(1),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err == nil {
		_ = c.Disconnect(context.Background())
		t.Fatal("Connect accepted a host key that was not the recorded one")
	}
	if !errors.Is(err, serverquery.ErrHostKey) {
		t.Errorf("Connect error = %v, want it to wrap ErrHostKey", err)
	}
	if errors.Is(err, serverquery.ErrAuth) {
		t.Errorf("a refused host key was reported as bad credentials: %v", err)
	}
	if got := c.Status(); got == teamspeak.StatusConnected {
		t.Errorf("Status = %v after a refused connect", got)
	}
	t.Logf("refused: %v", err)

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("the refusal does not carry the ssh library's KeyError: %v", err)
	}

	return keyErr
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

// assertTextMessageEvent has a voice client send a message and expects the
// query client to hear it.
func assertTextMessageEvent(t *testing.T, c *serverquery.Client) {
	t.Helper()
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
	remove := c.OnTextMessage(func(e teamspeak.TextMessageEvent) {
		select {
		case heard <- e:
		default:
		}
	})
	defer remove()

	// The voice client leaves straight after sending. Waiting for that
	// departure checks that OnClientLeave is delivered over this transport
	// too, and means the next subtest starts after the announcement rather
	// than with it arriving in the middle of a command.
	left := make(chan struct{}, 8)
	removeLeave := c.OnClientLeave(func(teamspeak.ClientLeaveEvent) {
		select {
		case left <- struct{}{}:
		default:
		}
	})
	defer removeLeave()

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
	select {
	case <-left:
	case <-time.After(10 * time.Second):
		t.Error("the voice client left, but its departure was never announced")
	}
}

// channelIDByName finds a channel the fixture created.
func channelIDByName(t *testing.T, c *serverquery.Client, name string) teamspeak.ChannelID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	for _, ch := range channels {
		if ch.Name == name {
			return ch.ID
		}
	}
	t.Fatalf("the fixture's channel %q is not on the server", name)

	return 0
}

// assertOwnChannelKick kicks the query client from its channel and expects
// OnKicked to report it. A query client is never kicked from the server (the
// server answers 516), but a channel kick is accepted and reaches it as a move
// of its own, so the client has to know which client id is its own to see it.
func assertOwnChannelKick(t *testing.T, c *serverquery.Client) {
	t.Helper()
	name := os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL")
	password := os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD")
	if name == "" {
		t.Skip("TEAMSPEAK_PASSWORD_CHANNEL not set, so there is no channel to be kicked out of")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	who, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	target := channelIDByName(t, c, name)

	// A kick moves the client out of its channel, so it has to be in one it
	// can be moved out of: the default channel answers 770.
	err = c.MoveClient(ctx, who.ClientID, target, teamspeak.ClientMoveOptions{Password: password})
	if err != nil {
		t.Fatalf("MoveClient into %q: %v", name, err)
	}

	kicked := make(chan teamspeak.KickedEvent, 1)
	remove := c.OnKicked(func(e teamspeak.KickedEvent) {
		select {
		case kicked <- e:
		default:
		}
	})
	defer remove()

	reason := "out-of-" + strconv.Itoa(int(who.ClientID))
	err = c.KickClient(ctx, who.ClientID, teamspeak.ReasonKickChannel,
		teamspeak.ClientKickOptions{ReasonMessage: reason})
	if err != nil {
		t.Fatalf("KickClient: %v", err)
	}

	select {
	case e := <-kicked:
		if e.Reason != teamspeak.ReasonKickChannel {
			t.Errorf("kick Reason = %v, want a channel kick", e.Reason)
		}
		if e.ReasonMessage != reason {
			t.Errorf("kick ReasonMessage = %q, want %q", e.ReasonMessage, reason)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the client's own channel kick was never reported")
	}

	// A channel kick moves the client; it does not remove it from the server.
	if got := c.Status(); got != teamspeak.StatusConnected {
		t.Errorf("Status = %v after a channel kick, want connected", got)
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
	err = voice.Connect(ctx)
	if err != nil {
		t.Fatalf("voice client Connect: %v", err)
	}
	defer func() { _ = voice.Disconnect(context.Background()) }()

	err = voice.SendServerMessage(ctx, "query integration test")
	if err != nil {
		t.Fatalf("SendServerMessage: %v", err)
	}
}

// A typed command that writes, to prove the session is usable for more than
// reading: the client creates a channel under a fresh name, finds it in the
// list, and removes it again.
//
// It runs over each command transport the job has, as subtests, so a transport
// the server does not serve shows as skipped by name. Each opens its own
// connection and closes it: a connection shared between tests would need a
// TestMain to close it, and this is the only test that writes.
func TestQuery_TypedCommandRoundTrip(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		addr, login, password := tcpVars(t)
		waitForOtherSuites()
		c, err := serverquery.New(serverquery.TCPLogin(addr, login, password),
			serverquery.WithServer(1),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		open(t, c)
		assertChannelRoundTrip(t, c)
	})

	t.Run("ssh", func(t *testing.T) {
		addr, user, password := sshVars(t)
		waitForOtherSuites()
		check, err := serverquery.KnownHosts(livetest.KnownHostsFor(t, addr))
		if err != nil {
			t.Fatalf("KnownHosts: %v", err)
		}
		c, err := serverquery.New(serverquery.SSHWith(addr, user, password,
			serverquery.SSHOptions{HostKeyCheck: check}),
			serverquery.WithServer(1),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		open(t, c)
		assertChannelRoundTrip(t, c)
	})

	t.Run("web", func(t *testing.T) {
		base, apiKey := webVars(t)
		waitForOtherSuites()
		c, err := serverquery.New(serverquery.Web(base, apiKey), serverquery.WithServer(1))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		open(t, c)
		assertChannelRoundTrip(t, c)
	})
}

// assertChannelRoundTrip creates a channel on c, finds it, and removes it.
func assertChannelRoundTrip(t *testing.T, c *serverquery.Client) {
	t.Helper()
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
		deleteErr := c.DeleteChannel(delCtx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		if deleteErr != nil {
			t.Errorf("DeleteChannel: %v", deleteErr)
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
