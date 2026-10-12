# Changelog

All notable changes to this module. It follows [Semantic Versioning](https://semver.org);
from v1.0.0 on, a breaking change needs a new major version and import path.

## v1.0.0-beta.1 (unreleased)

The API settled for 1.0. Almost every signature changed; the
[migration guide](#migrating-from-v02-and-v03) below walks through each one.
ServerQuery is not in this beta: its executor exists as
`internal/serverquery` and is published as `serverquery` once implemented,
before v1.0.0.

### Layout

- The module root, package `teamspeak`, holds what every TeamSpeak connection
  shares: the typed commands (`*teamspeak.Commands`), ids, errors and result
  types. The voice client is `github.com/honeybbq/teamspeak-go/client`.
  Identities are `github.com/honeybbq/teamspeak-go/identity`, server error
  codes `github.com/honeybbq/teamspeak-go/errcode`.
- Protocol internals — `crypto`, `handshake`, `transport`, `discovery` — are
  under `internal/` and no longer importable. They were never stable API.
- The typed commands run on any `teamspeak.Executor`, so the same methods will
  run over ServerQuery. A client embeds them.

### Correctness

- About 35 queries answer with a notification rather than data rows
  (`servergrouplist` with `notifyservergrouplist`, and so on); they returned
  nothing. Each command now declares where its answer arrives, measured on
  TeamSpeak 3 and 6 (`docs/voice-protocol-responses.md` in teamspeak-js).
- `ftinitupload` and `ftinitdownload` are answered after their `error`, matched
  by `clientftfid`; they returned no key. A failure the server reports in
  `notifystatusfiletransfer` is a `*ServerError`.
- Two commands in flight could take each other's rows.
- `CreateChannel` returned channel id 0; group creation and copy returned the
  first group in the list rather than the new one.
- A value that really contained `\s` was unescaped twice and came back with a
  space in it.
- A message containing `return_code=` suppressed the real one and timed out.
- `SendTextMessage` did not wait for the server's answer, so a permission
  refusal was lost.
- A command with no connection to send it on waited out its timeout, or
  panicked; it now fails with `ErrNotConnected` at once, and a lost
  connection fails every command in flight.
- The reconnect policy's "permanent refusals" named the wrong codes, so a
  wrong server password (1028) was retried until the attempts ran out.
- A kick, a ban or the server stopping left the client "connected" for a
  minute, then reported the end with a nil error. The session now ends at once
  with a `*client.RemovedError`. Channel kicks were never reported.
- An empty list (`banlist` on a server with no bans) failed with error 1281; it
  returns no rows.
- `AddTempPassword` always created an empty password; `ViewLog` returned no
  lines; TeamSpeak 6 file times were read in the wrong unit; transfer speeds
  and negative icon ids read as 0.
- Event handlers ran on a goroutine each, so events could arrive out of order
  and handlers raced. They now run one at a time, in order. The integration
  suite runs under `-race` on both server generations with no races reported.

### Go idioms

- Every operation that waits takes a `context.Context` first: `Connect`,
  `Disconnect`, every typed command, `Exec`, file transfers, identity
  generation. A command without a deadline gives up after ten seconds.
- `client.New` returns an error for an invalid configuration; options are an
  opaque `client.Option`.
- Errors are matched with `errors.Is`: `teamspeak.ErrServer`, an
  `errcode.Code`, `teamspeak.ErrNotConnected`, `client.ErrAlreadyConnected`,
  `client.ErrTimedOut`, `context.DeadlineExceeded`; `errors.As` for
  `*teamspeak.ServerError` and `*client.RemovedError`.
- Ids are named types, times are `time.Time`, durations `time.Duration`,
  enums have `String` methods.
- `On…` methods return a function that removes the handler.
- Logging is silent by default and never includes a command's parameters,
  which carry password hashes and privilege keys. `identity.Identity`'s
  `String` and `LogValue` never include its private key.

### Added

- `errcode`: every server error code by name.
- `client.OnNotification`: every notification as it arrived, for the ones the
  SDK does not model.
- `client.ServerCapabilities` reports the server's name, icon, host banner and
  welcome message from the handshake.
- `(*Commands).ClientDatabase`: an iterator over the whole client database.
- `teamspeak.Permission`, `teamspeak.Reason`, `teamspeak.GroupType` and the
  other enumerations.
- Runnable examples on pkg.go.dev.

The server info and raw notifications follow the
[EchoSixHIYA fork](https://github.com/EchoSixHIYA/teamspeak-js), by illusia.

## Migrating from v0.2 and v0.3

### Imports

| v0.x | v1 |
| --- | --- |
| `teamspeak.NewClient`, `teamspeak.With…` | `client.New`, `client.With…` |
| `crypto.GenerateIdentity`, `crypto.IdentityFromString` | `identity.Generate(ctx, level)`, `identity.Parse` |
| `crypto.GetUidFromPublicKey` | `identity.UID(publicKey, identity.UIDSHA1)` |
| `transport`, `handshake`, `crypto`, `discovery` | internal; no replacement |

### Connecting

```go
// v0.x
c := teamspeak.NewClient(id, "ts.example.com", "bot")
if err := c.Connect(); err != nil { … }
if err := c.WaitConnected(ctx); err != nil { … }
defer c.Disconnect()

// v1
c, err := client.New(id, "ts.example.com", "bot")
if err != nil { … }
if err := c.Connect(ctx); err != nil { … } // returns once the handshake completes
defer c.Disconnect(context.WithoutCancel(ctx))
```

`Connect` replaces `Connect` plus `WaitConnected`: it returns the handshake's
failure, such as the server's error for a wrong password, and abandons the
attempt when `ctx` is done.

### Commands

Every typed command takes `ctx` first and named ids:

```go
// v0.x
channels, err := c.ListChannels()
err = c.ClientMove(clid, 5, "")

// v1
channels, err := c.ListChannels(ctx)
err = c.MoveClient(ctx, clid, teamspeak.ChannelID(5), "")
```

Raw commands:

| v0.x | v1 |
| --- | --- |
| `ExecCommandWithResponse(line, timeout)` | `Exec(ctx, line)` |
| `ExecCommand(line, timeout)` | `Exec(ctx, line)`, ignoring the rows |
| `SendCommandNoWait(line)` | `ExecNoWait(ctx, line)` |

Optional parameters are pointer fields, set with Go's `new`: `ChannelCreateOptions{ChannelName: "Room", ChannelTopic: new("hello")}`. A
permission is `teamspeak.PermissionByName("i_client_talk_power")` or
`PermissionByID(id)`, in place of the `permID`, `permSID` pair. Text messages
are `SendPrivateMessage`, `SendChannelMessage` and `SendServerMessage`. A
missing pointer field still means "not sent"; an empty string is sent empty.

### Errors

In v0.x a server error was an unexported error whose text held the code
(`TeamSpeak server error: … (id=2568)`), so telling refusals apart meant
parsing the message. In v1 it is a `*teamspeak.ServerError` with a typed code:

```go
if errors.Is(err, errcode.PermissionsClientInsufficient) { … }

var se *teamspeak.ServerError
if errors.As(err, &se) {
	log.Print(se.Code, se.Message, se.FailedPermID)
}
```

### Events

```go
// v0.x
c.OnTextMessage(func(m teamspeak.TextMessage) { … })
c.OnKicked(func(reason string) { … })

// v1
stop := c.OnTextMessage(func(m client.TextMessage) { … })
defer stop()
c.OnKicked(func(e client.KickedEvent) { … }) // e.Message, e.Reason, e.InvokerName
```

`OnClientEnter` receives a `client.ClientEnterEvent`, which embeds
`teamspeak.ClientInfo`. `ReasonID` fields are `Reason teamspeak.Reason`.
`OnDisconnected` receives nil only after `Disconnect`; otherwise the cause.

Middleware is set when the client is built, with `client.WithCommandMiddleware`
and `client.WithEventMiddleware`; `UseCommandMiddleware` and
`UseEventMiddleware` are gone, since changing a chain while commands run raced.
Event middleware receives a `client.Event`.

### Reconnecting

`client.DefaultBackoffPolicy` is a function, and `BackoffDelay(policy,
attempt, random)` is `policy.Delay(attempt)`. A zero `Jitter` now means the
default; a negative one turns jitter off.

### File transfers

```go
// v0.x
info, err := c.FileTransferInitUpload(cid, "/a.txt", "", size, true) // password, then size
err = teamspeak.UploadFileData(host, info, r)

// v1
info, err := c.InitFileUpload(ctx, cid, "/a.txt", size, "", true)
err = teamspeak.UploadFileData(ctx, host, info, r, nil)
```

The last argument is a `teamspeak.FileTransferDialer` — any `DialContext`,
such as a `*net.Dialer` or a proxy — or nil for a direct dial.
