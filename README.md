<div align="center">

# teamspeak-go

**A clean-room TeamSpeak client protocol library written in pure Go.**

Works with TeamSpeak 3 and TeamSpeak 6 servers. No proprietary SDK, no copied code.

[![CI](https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml/badge.svg)](https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/honeybbq/teamspeak-go/branch/main/graph/badge.svg)](https://codecov.io/gh/honeybbq/teamspeak-go)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/HoneyBBQ/teamspeak-go/badge)](https://scorecard.dev/viewer/?uri=github.com/HoneyBBQ/teamspeak-go)
[![Release](https://img.shields.io/github/v/release/honeybbq/teamspeak-go?include_prereleases&sort=semver)](https://github.com/honeybbq/teamspeak-go/releases)

[![Go Reference](https://pkg.go.dev/badge/github.com/honeybbq/teamspeak-go.svg)](https://pkg.go.dev/github.com/honeybbq/teamspeak-go)
[![Go Version](https://img.shields.io/github/go-mod/go-version/honeybbq/teamspeak-go)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## Features

- **Full protocol handshake** — ECDH key exchange, RSA puzzle, EAX-encrypted transport
- **Command & notification system** — Send commands, receive server events
- **Event-driven API** — Register handlers for text messages, client enter/leave, channel moves, kicks, etc.
- **Voice data** — Send Opus voice packets (codec 4 & 5)
- **File transfers** — Upload, download, and delete files on the server
- **Address resolution** — SRV records, TSDNS, and direct address support
- **Middleware** — Pluggable command and event middleware chains
- **Built-in rate limiter** — Token-bucket throttling to prevent server-side flood kicks
- **Identity management** — Generate, import/export, and upgrade security level of identities
- **Full command set** — 109 typed methods covering every command the voice protocol answers
- **Typed ids and times** — a channel id cannot be passed where a client id belongs; timestamps are `time.Time`, durations `time.Duration`
- **Reconnection** — Opt-in retry with backoff, tuned for TeamSpeak's antiflood ban
- **Server capabilities** — Reports the server version and the uid hash it uses (SHA-1 on TS3, SHA-256 on TS6), and the server's name, icon, banner and welcome message
- **Custom transports** — Supply your own net.PacketConn and file transfer dialer
- **ServerQuery** — The same typed commands over raw TCP, SSH or WebQuery, with the server's notifications as events
- **Zero CGO** — Pure Go, cross-compile anywhere

## Installation

1.0 is in beta. `go get` on its own still picks v0.2, because Go skips
pre-releases unless you ask for one, so name the version:

```bash
go get github.com/honeybbq/teamspeak-go@v1.0.0-beta.6
```

Everything in this README is the 1.0 API. You need Go 1.26 or newer.

Coming from v0.x? Almost every signature changed. [CHANGELOG.md](CHANGELOG.md)
has the full list and a migration table.

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

func main() {
	// Generate a new identity (or load an existing one)
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}

	// Create the client
	c, err := client.New(
		id,
		"localhost",
		"GoBot",
		client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
		client.WithDefaultChannel("Lobby"),
		client.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Register event handlers
	c.OnConnected(func(e client.ConnectedEvent) {
		fmt.Println("Connected to server! Reconnected:", e.Reconnected)
	})

	c.OnTextMessage(func(msg client.TextMessageEvent) {
		fmt.Printf("[%s]: %s\n", msg.InvokerName, msg.Message)
	})

	c.OnDisconnected(func(e client.DisconnectedEvent) {
		fmt.Println("Disconnected:", e.Err, "will reconnect:", e.WillReconnect)
	})

	// Connect returns once the handshake completes.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(channels), "channels")

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	_ = c.Disconnect(context.Background())
}
```

## API Overview

### Client Lifecycle

| Method | Description |
|---|---|
| `client.New(identity, addr, nickname, ...opts)` | Create a new client |
| `Connect(ctx)` | Connect, returning once the handshake completes |
| `Disconnect(ctx)` | Leave the server, close the connection and cancel a pending reconnect |
| `Status() client.Status` | `StatusDisconnected`, `StatusConnecting` or `StatusConnected` |
| `ClientID() teamspeak.ClientID` | Our clid, assigned by the server |
| `ChannelID() teamspeak.ChannelID` | The channel we are in |
| `ServerCapabilities()` | What the server said about itself in the handshake: version, family, uid hash, name, icon, banner and welcome message |
| `UID() teamspeak.UID` | Our own uid, hashed as the server does |

### Events

The event types are defined in the root `teamspeak` package and `client`
re-exports them as aliases, so a future ServerQuery client shares them.

| Method | Description |
|---|---|
| `OnConnected(func(ConnectedEvent))` | Fires when fully connected; `Reconnected` is true when the reconnect loop made the connection |
| `OnDisconnected(func(DisconnectedEvent))` | Fires on disconnect; `Err` is nil after `Disconnect`, and `WillReconnect` says whether the reconnect loop will try again |
| `OnTextMessage(func(TextMessageEvent))` | Fires on text messages |
| `OnClientEnter(func(ClientEnterEvent))` | Fires when a client comes into view; the event embeds its `teamspeak.ClientEntry` |
| `OnClientLeave(func(ClientLeaveEvent))` | Fires when a client leaves |
| `OnClientMoved(func(ClientMovedEvent))` | Fires when a client moves channels |
| `OnPoked(func(PokeEvent))` | Fires when the bot is poked |
| `OnVoiceData(func(VoiceDataEvent))` | Fires for each audio frame another client sends; dropped, with a warning, while more than 256 deliveries are waiting |
| `OnNotification(func(NotificationEvent))` | Fires for every notification, as the server sent it |
| `OnKicked(func(KickedEvent))` | Fires when the bot is kicked from its channel or the server |

Each `On` method returns a function that removes the handler. Handlers run one
at a time, in the order their events arrived, on a goroutine of the client's
own, so a handler may call the client and wait for an answer; a handler that
blocks holds up the events behind it. A handler that panics is recovered and
logged at Error with the event type; the other handlers and later events are
still delivered.

`OnNotification` is the escape hatch for a notification the SDK has no typed
event for. Every notification arrives there — name and unescaped parameters —
after the typed event it produced, one per row for a batched one. Each handler
gets its own copy of the parameters.

```go
c.OnNotification(func(n client.NotificationEvent) {
	if n.Name == notify.ChannelEdited {
		fmt.Println("channel", n.Params["cid"], "edited")
	}
})
```

#### Event middleware

Event middleware sees every server event before its handlers do — the events
above except connected, disconnected and kicked, which report the connection
itself and bypass it. It receives a `client.Event`, which is one of
`TextMessageEvent`, `ClientEnterEvent`, `ClientLeaveEvent`, `ClientMovedEvent`,
`PokeEvent`, `VoiceDataEvent` or `NotificationEvent`; it may pass the event on,
replace it, or drop it by not calling `next`.

```go
ignoreCommands := func(next func(client.Event)) func(client.Event) {
	return func(evt client.Event) {
		if msg, ok := evt.(client.TextMessageEvent); ok && strings.HasPrefix(msg.Message, "!") {
			return // dropped: no handler sees it
		}
		next(evt)
	}
}
c, err := client.New(id, addr, "Bot", client.WithEventMiddleware(ignoreCommands))
```

#### Server info

`ServerCapabilities()` is read from `initserver`, so it costs no round trip and
is filled in by the time `Connect` returns:

```go
caps := c.ServerCapabilities()
fmt.Println(caps.Name, caps.Family, caps.Version)
// caps.IconID is the icon's CRC32 (0 for none), unsigned even when the server
// sends it signed; caps.HostBannerImageURL and caps.WelcomeMessage are as set
// on the server.
```

### Commands

Every command is a typed method taking a context, defined once in the root
`teamspeak` package and embedded into the client. Options structs use a nil
pointer field to omit a parameter entirely — which the protocol distinguishes from an empty value:
clearing a password takes `channel_password=`, leaving it alone sends nothing.
Build the pointers with `new`: `new("the quiet one")`, `new(true)`.

Ids are typed — `ChannelID`, `ClientID`, `ClientDBID`, `ServerGroupID`,
`ChannelGroupID`, `PermissionID`, `IconID`, `ServerID`, `UID` — so a channel id
cannot be passed where a client id belongs. Timestamps are `time.Time` (the
zero time for "never") and durations `time.Duration`, rounded to the unit the
server uses for that field.

```go
// A field the answer may leave out is a pointer, nil when absent:
// GetChannelInfo has no TotalClients, ListChannels does.
channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})

cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
	Name:        "Lounge",
	Topic:       new("the quiet one"),
	IsPermanent: new(true),
})

// Required arguments are positional; everything optional is one options
// struct, the last argument.
err = c.MoveClient(ctx, c.ClientID(), cid, teamspeak.ClientMoveOptions{Password: "channel-password"})
err = c.SendChannelMessage(ctx, "hello")

// A permission is named by id or by name; the zero Permission is refused.
// The perm package has a constant for every name the servers list.
err = c.AddChannelPermission(ctx, cid, teamspeak.PermissionByName(perm.ChannelNeededJoinPower), 50)

// 0 bans permanently; anything else is sent in whole seconds. The server bans
// the client's uid and IP (and MyTeamSpeak id); over the voice protocol it
// reports none of their ids, so banIDs is empty and ListBans finds them.
banIDs, err := c.BanClient(ctx, troll, teamspeak.BanClientOptions{Duration: 10 * time.Minute, Reason: "cool off"})

// AddBan is the same for one ban: the bool is false when the server reported
// no id, so 0 is never mistaken for one. ServerQuery answers banadd with a
// banid; the voice protocol answers nothing, and ListBans finds the ban.
banID, reported, err := c.AddBan(ctx, teamspeak.BanOptions{IP: "203.0.113.5", Reason: "spam"})
if reported {
	fmt.Println("ban", banID)
}

// The client database is paged; the iterator fetches page after page.
for entry, err := range c.IterateClientDatabase(ctx, teamspeak.PagingOptions{}) {
	if err != nil {
		return err
	}
	fmt.Println(entry.Nickname, entry.LastConnected)
}
```

| File            | Covers                                                          |
| --------------- | --------------------------------------------------------------- |
| `api_channels.go`  | Create, edit, move, delete, subscribe, channel permissions    |
| `api_clients.go`   | List, move, kick, poke, edit, the client database, permissions |
| `api_server.go`    | Server and instance settings, groups, temp passwords, bindings |
| `api_groups.go`    | Channel groups, the permission catalogue, tokens               |
| `api_moderation.go`| Bans, complaints, offline messages, text messages, the log     |
| `api_files.go`     | List, delete, rename, create directories, transfer negotiation |

Many of these commands are answered over the voice protocol with a
notification rather than data rows — `servergrouplist` with
`notifyservergrouplist`, `ftinitupload` with `notifystartupload` after the
command has already succeeded. The client pairs each answer with its command,
so this is invisible to callers; the measured table is in
[voice-protocol-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/voice-protocol-responses.md).
A refusal is always returned as an error, never as an empty result.

For anything outside the typed set, `Exec(ctx, line)` sends a raw command
line and returns the rows that answer it.

### File Transfers

| Method | Description |
|---|---|
| `ListFiles(cid, path, FileOptions)` | Directory listing; `cid` is a `teamspeak.ChannelID` |
| `GetFileInfo(cid, path, FileOptions)` | Size and timestamp of one file |
| `DeleteFile(cid, paths, FileOptions)` | Delete one or more files in one command |
| `CreateDirectory(cid, dir, FileOptions)` | Create a directory |
| `RenameFile(cid, old, new, FileRenameOptions)` | Rename or move a file |
| `StopFileTransfer(id, FileTransferStopOptions)` | Cancel a running transfer |
| `ListActiveTransfers()` | Transfers in progress |
| `InitFileUpload(cid, path, size, FileUploadOptions)` / `InitFileDownload(cid, path, FileDownloadOptions)` | Negotiate a transfer; pass the result to `UploadFileData` / `DownloadFileData` |
| `teamspeak.UploadFileData(ctx, host, info, reader, FileTransferOptions)` | Transfer file data to the server |
| `teamspeak.DownloadFileData(ctx, host, info, writer, FileTransferOptions)` | Receive file data from the server |
| `teamspeak.DialFileTransfer(ctx, host, port, key, FileTransferOptions)` | Open the transfer connection yourself |

The data travels over its own TCP connection to the file transfer port. `ctx`
bounds the whole transfer: when it is done the connection is closed and the
call returns an error wrapping `ctx.Err()`, so `errors.Is(err, context.Canceled)`
holds. Every error of these calls also matches `teamspeak.ErrFileTransfer`.
`FileTransferOptions.IdleTimeout` is the longest a transfer may go without
moving a byte (default 30 seconds, negative disables it); beyond it the call
fails with an error wrapping `ErrFileTransfer` and `os.ErrDeadlineExceeded`.
A download that sends more bytes than the size the server announced fails
after that size, and one that ends short of it fails with
`io.ErrUnexpectedEOF`.
`FileTransferOptions.Dialer` is a `teamspeak.FileTransferDialer` — anything
with `DialContext(ctx, network, addr)`, such as a `*net.Dialer` or a
`golang.org/x/net/proxy` `ContextDialer`; the zero options dial directly, with
a 10 second connect timeout.

```go
upload, err := c.InitFileUpload(ctx, cid, "/notes.txt", uint64(len(data)),
	teamspeak.FileUploadOptions{Overwrite: true})
if err != nil {
	return err
}
err = teamspeak.UploadFileData(ctx, host, upload, bytes.NewReader(data), teamspeak.FileTransferOptions{})
```

### Identity

```go
// Generate a new identity with security level 8
id, err := identity.Generate(ctx, 8)

// Export for storage — this includes the private key, so store it like a
// password. The key is not otherwise reachable: String, %v, slog never
// print it, and json.Marshal refuses an identity.
exported := id.Export()

// Read a previously exported identity
id, err = identity.Parse(exported)

// Raise the security level (CPU-intensive; ctx bounds it). Identities are
// immutable: this returns a new one. Levels go up to 160.
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
id, err = id.UpgradeToLevel(ctx, 10)
```

### Options

```go
c, err := client.New(id, "ts.example.com", "Bot",
	client.WithLogger(slog.Default()), // silent without it
	client.WithResolver(customResolver),
	client.WithCommandMiddleware(timeCommands),
	client.WithEventMiddleware(filterMiddleware),
	client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
	client.WithDefaultChannel("Lobby"),
	client.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
)
```

Command middleware wraps the typed commands. It sees each request and the
caller's context, and returns the rows or an error, so it can time, retry or
answer a command itself. Raw `Exec` and `ExecNoWait` lines, and the commands
the client sends on its own during the handshake, do not pass through it.

```go
timeCommands := func(next teamspeak.Executor) teamspeak.Executor {
	return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
				rows, err := next.Send(ctx, req)
		slog.Debug("command", "name", req.Command(), "took", time.Since(start), "err", err)

		return rows, err
	})
}
```

`WithNicknameLookup()` resolves a dot-less address as a MyTeamSpeak nickname
at named.myteamspeak.com first. It is off by default, since the lookup tells
MyTeamSpeak which server you are connecting to; without it a dot-less address
is resolved like any host.

`WithPacketConn(pc)` runs the session over your own `net.PacketConn`. The
client never closes it: ending a connection sets its read deadline to stop the
reader, and the next `Connect` clears it. Datagrams from any address but the
server's are dropped.

Connection auth options:

- `WithServerPassword(password)` accepts the plain-text server password, keeps only the TeamSpeak protocol hash, and sends it during `clientinit`
- `WithDefaultChannel(channel)` requests a default channel during `clientinit`
- `WithDefaultChannelPassword(password)` accepts the plain-text channel password and sends the TeamSpeak protocol hash for the configured default channel

### Client version

`clientinit` sends a recent Windows version unless `WithVersion` says
otherwise. The `versions` package has one variable for each version that is
known to work, named `<Platform>_<version>_<build>`; the first letter of a
platform that starts in lower case is capitalised, so macOS is `MacOS` and iOS
is `IOS`:

```go
import "github.com/honeybbq/teamspeak-go/versions"

c, err := client.New(id, "ts.example.com", "Bot",
	client.WithVersion(versions.Windows_3_6_2_1695203293),
)
```

A `versions.ClientVersion` is a platform, a version string and a signature, and
only the ones in the package carry a signature a server accepts. Do not modify
the variables. A server refuses a build below its configured minimum, so an old
version fails to connect on a server that has raised it. `New` returns
`ErrInvalidConfig` when a field is empty or the signature is not the base64 of
64 bytes.

### Tracing

`WithTrace` reports the milestones of a client's connection attempts and its
session, and `FileTransferOptions.Trace` those of one file transfer. Every hook
is optional.

```go
c, err := client.New(id, "ts.example.com", "Bot",
	client.WithTrace(&client.Trace{
		ResolveDone: func(i client.ResolveDoneInfo) {
			slog.Info("resolved", "target", i.Target, "took", i.Duration)
		},
		HandshakeDone: func(i client.HandshakeDoneInfo) {
			slog.Info("handshake", "took", i.Duration, "puzzle", i.PuzzleLevel, "resends", i.Resends)
		},
		SessionStart: func(i client.SessionStartInfo) {
			slog.Info("connected", "clid", i.ClientID, "nickname", i.Nickname, "took", i.Duration)
		},
		WelcomeDone: func(i client.WelcomeDoneInfo) {
			slog.Info("welcome done", "channel", i.ChannelID, "channels", i.Channels, "clients", i.Clients)
		},
		AttemptFailed: func(i client.AttemptFailedInfo) {
			slog.Warn("attempt failed", "phase", i.Phase, "target", i.Target, "err", i.Err)
		},
		SessionEnd: func(i client.SessionEndInfo) {
			slog.Info("session ended", "after", i.Duration, "cause", i.Cause)
		},
		ReconnectScheduled: func(i client.ReconnectScheduledInfo) {
			slog.Info("reconnecting", "attempt", i.Attempt, "in", i.Delay, "cause", i.Cause)
		},
		ReconnectStopped: func(i client.ReconnectStoppedInfo) {
			slog.Warn("gave up reconnecting", "attempts", i.Attempts, "cause", i.Cause)
		},
	}),
)
```

An attempt that succeeds calls `ResolveStart`, `ResolveDone`, `ConnectStart`,
`ConnectDone`, `HandshakeDone`, `SessionStart` and `WelcomeDone`, in that order.
One that does not reach `SessionStart` ends with `AttemptFailed` instead, saying
in which phase (`open`, `handshake` or `join`) it failed. Every session ends
with one `SessionEnd`, before the disconnected event; `Disconnect` also calls
`DisconnectStart` and `DisconnectDone` (which says whether the server
acknowledged the goodbye). After a drop, `ReconnectScheduled` precedes each
retry, and `ReconnectStopped` says when the loop gives up.

The rules for a hook:

- It is called synchronously, at the milestone, and its return value is
  ignored: it cannot change or stop the connection.
- It must be quick. Do slow work on your own goroutine.
- It may be called from different goroutines (yours for `Connect` and
  `Disconnect`, the receive goroutine for the handshake and a drop, the
  reconnect goroutine for a retry), so it must be safe for that. No client lock
  is held, so it can read `Status` or `ClientID`.
- It must not call `Connect` or `Disconnect`. To abandon an attempt, cancel the
  context you gave `Connect`; to leave once connected, call `Disconnect` from an
  `OnConnected` handler.
- A hook that panics is recovered and logged at Error; the connection goes on.

The client copies the `Trace` in `New`, so changing it afterwards has no effect.

A file transfer reports `DialStart`, `DialDone`, `Progress` (at most once per
64 KiB, and once more at the end with the final count) and then `Done` or
`Failed`, which says whether it failed while dialling or while transferring. The
transfer key is never in any of them. These hooks run on the goroutine that
called `UploadFileData` or `DownloadFileData`, and a panic in one is not
recovered: it reaches your code, after the connection is closed.

```go
err := teamspeak.UploadFileData(ctx, host, upload, file, teamspeak.FileTransferOptions{
	Trace: &teamspeak.FileTransferTrace{
		Progress: func(i teamspeak.FileTransferProgressInfo) { bar.Set(i.Bytes) },
		Failed:   func(i teamspeak.FileTransferFailedInfo) { slog.Warn("upload", "stage", i.Stage, "err", i.Err) },
	},
})
```

## Design

The conventions below hold across the whole module. Each is stated once here.

### Errors

An error is one of two kinds:

- **A refusal the server reports.** It is a `*teamspeak.ServerError` carrying
  the server's `Code`, `Message`, `ExtraMessage` and, for a refused permission
  check, `FailedPermID`.
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

### Ids

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

### Options and absent values

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

### Events

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

### Stability

From v1.0.0 the module follows semantic versioning, as described under
[Compatibility](#compatibility). The exported API is recorded in `api/*.txt`,
and CI fails when the code and the record disagree, so a change to it shows up
in review. The enumerations and event types may gain members in a minor
release; give a `switch` over them a default case.

An API that may still change in a minor release says `Experimental:` in its doc
comment, which `go doc` and pkg.go.dev show. Today that is the whole
`serverquery` package, the server view (`Client.View`, `ServerView`,
`ViewStatus` and the view events), `ChannelTree`, the `Previous` field of the
client-leave and channel-deleted events, and `Client.GetServerVariables`.

### Server behaviour the SDK works around

The servers answer some commands in ways that differ between TeamSpeak 3 and 6
and between transports, and the SDK evens those out. The measured tables are in
[voice-protocol-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/voice-protocol-responses.md)
and [serverquery-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/serverquery-responses.md).

## ServerQuery

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

### Transports

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

### Events

Registration is automatic: on connecting, the client asks for the five
notification categories both TCP and SSH accept — `server`, `channel`,
`textserver`, `textchannel` and `textprivate`. `WithEvents` narrows the set,
and `WithoutEvents` turns registration off. `bans` is opt-in, because TS3
refuses it:

```go
c.OnTextMessage(func(m teamspeak.TextMessageEvent) {
	fmt.Println(m.InvokerName, "said", m.Message)
})
```

`OnConnected` and `OnDisconnected` report the connection itself and work over
every transport. The `On…` methods for server events are inert over a
transport that cannot deliver them: they return a function that removes
nothing, and the client logs one warning per method rather than failing the
connect.

### Host keys

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

### Reconnection

`WithReconnect(teamspeak.ReconnectOptions{})` reconnects after a dropped
connection, sharing the voice client's backoff policy. The default retry
decision, `serverquery.DefaultShouldRetry`, never retries a refused login or a
refused `use`: those are the server saying the credentials or the server id are
wrong, and repeating them only risks the flood ban that TeamSpeak applies to an
IP that connects too often.

### Errors

The query client's errors are listed in [Design](#errors).

## Compatibility

From v1.0.0 the module follows semantic versioning. Minor releases may add
members to `Status`, `ServerFamily`, `identity.UIDAlgorithm`, the set of
`client.Event` types and the enumerations (`GroupType`, `Codec`, `Reason` and
the rest), and the server may send values this module does not name, so a
`switch` over any of them should have a default case.

### Supported Go versions

The module supports the two newest Go major releases, as Go itself does; CI
tests both, 1.26 and 1.27. The `go` line in `go.mod` is the oldest of them.
When that release leaves support, a minor release may raise the line; that is
not a breaking change.

### Differences from teamspeak-js

The two SDKs make the same decisions and use the same names, except where the
languages differ:

- **Backoff zero values.** Go cannot tell an unset field from 0, so a zero
  `BackoffPolicy` field takes the default, and a negative `Jitter` turns
  jitter off. JavaScript takes `undefined` as the default and 0 as 0.
- **A handler that panics or throws.** Go recovers the panic, logs it at
  Error, and keeps delivering. JavaScript rethrows it through
  `queueMicrotask`, as an uncaught exception from an EventEmitter listener
  would be, and keeps delivering to the other listeners.
- **Durations** are `time.Duration` in Go and milliseconds, with an `Ms`
  suffix, in JavaScript. Go's `ClientListOptions.OmitUID` is JavaScript's
  `uid` flag, because a Go bool's zero value must be the default.
- **When disconnect returns.** JavaScript's `disconnect()` resolves after
  its `disconnected` has been delivered, which is safe there: a listener that
  awaits `disconnect()` yields to the delivery loop. Go's `Disconnect`
  returns once the event is queued and guarantees order instead — the old
  session's `disconnected` before the new session's `connected` and any
  other event of it — since a Go handler blocking on its own delivery would
  deadlock. A Go handler may call `Connect` and `Disconnect` freely.
- **connected.** Both deliver it once `Connect` has succeeded, on the event
  queue. JavaScript's single thread lets a listener added right after
  `connect()` resolves still hear it; Go's event goroutine may run first, so
  register `OnConnected` before `Connect` to be sure to.

## Architecture

```
teamspeak-go/
├── *.go               # package teamspeak — what the clients share: the
│                      #   typed commands (Commands, on any Executor), their
│                      #   results, events, errors, and file transfer data
├── client/            # package client — the voice client: session, events,
│                      #   voice, reconnection, voice-only commands
├── identity/          # creating, storing and inspecting identities
├── errcode/           # the server's error codes, as constants
├── perm/              # the permission names, as constants
├── notify/            # the notification names, as constants
├── prop/              # the property keys of serverinfo, clientinfo and the like
├── commands/          # the command language: command names and escaping
├── serverquery/       # package serverquery — the ServerQuery client: the
│                      #   three transports, the query session, events
└── internal/          # crypto, handshake, transport, discovery; wire and
                       #   servererr, the line format both protocols share;
                       #   eventbus and servernotify, what the clients share
```

## Acknowledgments

Protocol knowledge was primarily informed by the [TSLib](https://github.com/Splamy/TS3AudioBot) implementation in [TS3AudioBot](https://github.com/Splamy/TS3AudioBot) by Splamy. Huge thanks to the TS3AudioBot project and its contributors.

## Disclaimer

TeamSpeak is a registered trademark of [TeamSpeak Systems GmbH](https://teamspeak.com/). This project is not affiliated with, endorsed by, or associated with TeamSpeak Systems GmbH in any way.

This library is a **clean-room implementation** developed from publicly available documentation, protocol analysis of network traffic, and independent research. No proprietary TeamSpeak SDK code, headers, or libraries were used in its creation.

## License

[MIT](LICENSE)
