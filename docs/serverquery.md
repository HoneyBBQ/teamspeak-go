# ServerQuery

The `serverquery` package is a second client: the same typed commands as the
voice client — `ListChannels`, `MoveClient` and the rest — over TeamSpeak's
administrative interface rather than the voice protocol, plus the server's
notifications as the same events.

**It is experimental.** It may change in a minor release, unlike the rest of
the module, which follows semantic versioning from v1.0.0. Pin a version and
read the changelog before depending on it.

```go
import "github.com/honeybbq/teamspeak-go/serverquery"

c, err := serverquery.New(
	serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", password),
	serverquery.WithServer(1),
	serverquery.WithNickname("bot"),
)
if err != nil {
	return err
}
if err := c.Connect(ctx); err != nil {
	return err
}
defer c.Disconnect(context.WithoutCancel(ctx))

channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
```

## Transports

The three transports do not offer the same things, and the difference decides
which one a program can use:

| Transport | Where | Server | Login | Events |
|---|---|---|---|---|
| `TCPLogin(addr, name, password)` (`TCP(addr)` for none) | 10011 | TeamSpeak 3 only | the `login` command | yes |
| `SSHWith(addr, user, password, SSHOptions{...})` | 10022 | TeamSpeak 3 (3.3 and later) and 6, off by default | the SSH login | yes |
| `Web(baseURL, apiKey)` | 10080 (HTTP), 10443 (HTTPS) | TeamSpeak 3 (3.12 and later) and 6 | the api key | **none** |

TeamSpeak 6 dropped raw ServerQuery, so a TS6 server has no 10011 to connect
to. TeamSpeak 3 serves SSH and WebQuery as well, but only the raw port is on
until `query_protocols` lists the others; the official Docker image takes
`TS3SERVER_QUERY_PROTOCOLS=raw,ssh,http`, and `TS3SERVER_SERVERADMIN_PASSWORD`
for the SSH login. TS3 has no guest access and no key in its log: create the
api key over raw TCP with `apikeyadd`. `ServerFamily()` reports which
generation the connected server is.

WebQuery has no session for the server to push to, so it delivers no events at
all, and it refuses every file transfer command. A program that needs either
needs SSH.

## Events

Nothing is registered unless you ask: `WithEvents` names the categories, and
the client registers exactly those on connecting and reads the client list the
events draw their fields from. Raw TCP and SSH accept `server`, `channel`,
`textserver`, `textchannel` and `textprivate`; `bans` is opt-in, because TS3
refuses it, and so is `tokenused`, which reports a client redeeming a privilege
key as a `NotificationEvent`, since the key is a credential. WebQuery accepts
none, so `WithEvents` over it is refused with `ErrInvalidConfig`, as is
`WithEvents()` with no category:

```go
c, err := serverquery.New(dialer,
	serverquery.WithEvents(serverquery.CategoryTextServer, serverquery.CategoryTextChannel))
// handle err
c.OnTextMessage(func(m teamspeak.TextMessageEvent) {
	fmt.Println(m.InvokerName, "said", m.Message)
})
```

`OnConnected` and `OnDisconnected` report the connection itself and work over
every transport. The `On…` methods for server events are inert over a
transport that cannot deliver them: they return a function that removes
nothing, and the client logs one warning per method rather than failing the
connect.

## Guest access

TeamSpeak 6 beta13 and later let a connection in without an account, with the
access of the Guest ServerQuery group: `SSHGuestWith(addr, SSHOptions{...})`
over SSH (the user `guest`, no password, and the host key policy below, which
`SSHGuest(addr)` alone lacks) and `WebGuest(baseURL)` over WebQuery (no api
key). TeamSpeak 3 has no guest access, and `Connect` then returns an error
wrapping `ErrNoGuestAccess`. A guest is only ever a deliberate choice: `SSH`
and `Web` refuse an empty password, an empty api key and the user name `guest`
with `ErrInvalidConfig`, so a missing credential is not turned into a quiet
downgrade.

## Pacing and idle sessions

The query client sends each command as it is called, one at a time, and does
not resend a command the server refuses for flooding or keep an idle session
open. `WithLineMiddleware` is where a program does either; a middleware that
waits holds every later command. [Flood control](flood-control.md) has the
limits and the recipes, a keepalive among them.

## Host keys

The SSH transport needs a host key policy. Without one it refuses to dial
rather than trusting whatever answers the port, because the query account it
logs in as is normally `serveradmin`:

```go
check, err := serverquery.KnownHosts(filepath.Join(home, ".ssh", "known_hosts"))
c, err := serverquery.New(serverquery.SSHWith(addr, "serveradmin", password,
	serverquery.SSHOptions{HostKeyCheck: check}))
```

`KnownHosts` verifies against an OpenSSH known_hosts file, which it reads when
it is called and only from the path given: it is never read from `~/.ssh`
behind your back. `InsecureIgnoreHostKey()` accepts anything, and is named so
that the call site says out loud what it is giving up. A refusal wraps
`ErrHostKey`, and tells an unknown host apart from a key that has changed.

## Reconnection

`WithReconnect(teamspeak.ReconnectOptions{})` reconnects after a dropped
connection, sharing the voice client's backoff policy. The default retry
decision, `serverquery.DefaultShouldRetry`, never retries a refused login or a
refused `use`, except for the query flood limit, which clears by itself: those
are the server saying the credentials or the server id are wrong, and repeating
them only risks the flood ban that TeamSpeak applies to an IP that connects too
often. It does not retry an SSH host key that was not accepted either.

## Errors

The query client's errors are listed in [Design](design.md#errors).
