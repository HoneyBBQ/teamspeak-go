# Design

The conventions below hold across the whole module. Each is stated once here.

## Errors

An error is one of two kinds:

- **A refusal the server reports.** It is a `*teamspeak.ServerError` carrying
  the server's `Code`, `Message`, `ExtraMessage` and, for a refused permission
  check, `FailedPermID` or, over WebQuery, `FailedPermission` (the name).
- **A condition the SDK detects itself**: not connected, no data, a timeout,
  invalid input or configuration, a failed handshake, a failed file transfer.
  Each is a sentinel (`ErrNotConnected`, `ErrNoData`, ...) or, where the caller
  needs fields, a typed error such as `*client.RemovedError`.

Match with `errors.Is` for a sentinel or a code, and `errors.As` for the fields:

```go
err := c.MoveClient(ctx, c.ClientID(), cid, teamspeak.ClientMoveOptions{Password: "wrong"})
switch {
case errors.Is(err, errcode.ChannelInvalidPassword):
	// ask for the password again
case errors.Is(err, teamspeak.ErrNotConnected):
	// the connection is gone
case errors.Is(err, teamspeak.ErrServer):
	// any other refusal
}

var refusal *teamspeak.ServerError
if errors.As(err, &refusal) {
	fmt.Println(refusal.Code, refusal.Message, refusal.ExtraMessage, refusal.FailedPermID)
}
```

A `*ServerError` unwraps to both `teamspeak.ErrServer` and its `errcode.Code`,
so `errors.Is` matches the class or one specific refusal. The `errcode` package
names the server's codes as constants; `errcode.Code` is itself an error. The
same table, with the same numbers, is `ErrorCode` in the JavaScript SDK. A code
the package does not name still matches by number: `errcode.Code(5000)`.

Errors live with the code that produces them, so a package exports only the
errors its own functions return:

| Package | Errors |
| --- | --- |
| `teamspeak` (shared by every client) | `ErrServer` and `*ServerError`; `ErrNotConnected`, `ErrAlreadyConnected`, `ErrNoData`, `ErrFileTransfer`, `ErrInvalidCommand`, `ErrInvalidUID`, `ErrMissingDependency` |
| `client` (voice only) | `ErrConnectionTimeout`, `ErrHandshake`, `ErrPuzzleTooHard`, `ErrInvalidAddress`, `ErrInvalidConfig`, the whisper target errors, `*RemovedError` (kick, ban or server stop) |
| `serverquery` (query only) | `ErrInvalidConfig`, `ErrDial`, `ErrAuth`, `ErrNoGuestAccess`, `ErrHostKey`, `*WebQueryHTTPError` |
| `stream` | `ErrClosed`, `ErrNotPending`, `ErrAlreadyWatching`, `ErrInvalidOptions`, `*UnsupportedError`, `*JoinDeniedError`, `*PayloadTooLargeError`, `*EndedError` (which also matches the server's 5635) |
| `identity` | `ErrInvalidFormat`, `ErrInvalidLevel`, `ErrNotSerializable` |

`client.ErrInvalidConfig` and `serverquery.ErrInvalidConfig` are different
sentinels, one for each constructor. `*WebQueryHTTPError` carries the HTTP
`Status` and, when the body held the server's status (`HasCode`), the same code:
it then also matches `errcode` values and `*ServerError`, as a refusal over any
other transport does. Reach any typed error the same way:

```go
var httpErr *serverquery.WebQueryHTTPError
if errors.As(err, &httpErr) {
	fmt.Println("HTTP", httpErr.Status)
}
```

**Cancellation.** A cancelled or expired context is the caller's own error, not
an SDK error. Every call that takes a context returns an error for which
`errors.Is(err, ctx.Err())` holds: `context.Canceled` or
`context.DeadlineExceeded`, possibly wrapped with the command or the step it
was waiting for. This covers `Connect` and the typed commands, and file
transfers, whose error matches `ErrFileTransfer` as well. A command whose
context has no deadline gets one of ten seconds, so a silent server surfaces
as `context.DeadlineExceeded` too. A cancelled `Connect` does not retry and
leaves the client disconnected; a command that was given up on may still have
taken effect on the server. A failed connection over SSH can match `ErrDial`
and the context's error together, so test the context first.

**No data.** `ErrNoData` means the command succeeded but its answer lacked the
data it exists to return, such as the id of a channel just created. Treat the
command as having taken effect and do not retry it blindly, or it creates a
second object or fails as a duplicate. `CreateChannel` and the group commands
look the new object up themselves and return `ErrNoData` only when nothing
matches. A list that comes back empty is not this error.

## Ids

Every kind of id is its own named integer type: `ClientID`, `ChannelID`,
`ClientDBID`, `ServerGroupID`, `ChannelGroupID`, `PermissionID`, `IconID`,
`ServerID`, `BanID` and the rest, with `UID` and `ChannelUID` as strings. They
share a width, so as plain integers one could stand in for another. Passing the
wrong kind is a compile error; convert deliberately when a number comes from
elsewhere:

```go
cid := teamspeak.ChannelID(5)
err := c.MoveClient(ctx, c.ClientID(), cid, teamspeak.ClientMoveOptions{})
// c.MoveClient(ctx, cid, c.ClientID(), ...) does not compile.
```

## Options and absent values

**Options.** Required arguments are positional. Everything optional is one
options struct, the last argument. A field that is not set is not sent: a nil
pointer leaves the setting alone, and a pointer to the zero value clears it. A
few fields are plain values whose zero value is the default, and say so in their
documentation (`BanClientOptions.Duration`, where 0 is permanent). Build
pointers with `new`:

```go
topic := ""
err := c.EditChannel(ctx, cid, teamspeak.ChannelEditOptions{
	Name:  new("Lounge"),
	Topic: &topic, // sent empty: clears the topic
	// Password is nil: not sent, so the password stays as it is.
})
```

**Records.** In a record the server's answer fills in, an optional field is a
pointer, and nil means the server did not send it. That is not the same as
zero or false: `TotalClients` is nil in a `GetChannelInfo` result, which does
not carry it, and 0 in a `ListChannels` result of an empty channel.

```go
info, err := c.GetChannelInfo(ctx, cid)
if err != nil {
	return err
}
if info.TotalClients != nil {
	fmt.Println(*info.TotalClients, "clients")
}
```

**Durations and times** are `time.Duration` and `time.Time`. A duration is
rounded to the unit the server uses for that field. A `time.Time` that is the
zero time stands for "never". The JavaScript SDK uses `...Ms` numbers and `Date`.

## Events

Each server event has a typed `On...` method (`OnTextMessage`, `OnClientEnter`,
...), and `OnNotification` receives every notification as the server sent it,
including those no typed event models. The notification arrives after the typed
event it produced. Both return a function that removes the handler.

```go
off := c.OnTextMessage(func(e client.TextMessageEvent) {
	fmt.Println(e.InvokerName, e.Message)
})
defer off()

c.OnNotification(func(n client.NotificationEvent) {
	fmt.Println(n.Name, n.Params)
})
```

- **Order.** Handlers run one at a time, in the order the events arrived, on a
  goroutine of the client's own, so a handler may call the client and wait for
  an answer. A handler that blocks holds up the events behind it.
- **State.** The client updates its state, such as `View()`, before it queues the
  event that reports the change, so a handler sees state at least as new as its
  event.
- **A panic** in a handler is recovered and logged at Error with the event type.
  The other handlers and later events are still delivered. The JavaScript SDK
  rethrows a throwing listener as an uncaught exception instead.
- **Middleware.** `client.WithEventMiddleware` sees each server event before the
  handlers and may pass it on, replace it or drop it; connected, disconnected
  and kicked bypass it. `client.WithCommandMiddleware` wraps the typed commands.
  Both are described above.

## Stability

From v1.0.0 the module follows semantic versioning, as described under
[Compatibility](compatibility.md). The exported API is recorded in `api/*.txt`,
and CI fails when the code and the record disagree, so a change to it shows up
in review. The enumerations and event types may gain members in a minor
release; give a `switch` over them a default case.

An API that may still change in a minor release says `Experimental:` in its doc
comment, which `go doc` and pkg.go.dev show. Today that is the whole
`serverquery` package, the server view (`Client.View`, `ServerView`,
`ViewStatus` and the view events), `ChannelTree`, the `Previous` field of the
client-leave and channel-deleted events, and `Client.GetServerVariables`.

## Server behaviour the SDK works around

The servers answer some commands in ways that differ between TeamSpeak 3 and 6
and between transports, and the SDK evens those out. The measured tables are in
[voice-protocol-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/voice-protocol-responses.md)
and [serverquery-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/serverquery-responses.md).
