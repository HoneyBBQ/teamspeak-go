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
- **Zero CGO** — Pure Go, cross-compile anywhere

## Installation

1.0 is in beta. `go get` on its own still picks v0.2, because Go skips
pre-releases unless you ask for one, so name the version:

```bash
go get github.com/honeybbq/teamspeak-go@v1.0.0-beta.5
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
	c.OnConnected(func() {
		fmt.Println("Connected to server!")
	})

	c.OnTextMessage(func(msg client.TextMessageEvent) {
		fmt.Printf("[%s]: %s\n", msg.InvokerName, msg.Message)
	})

	c.OnDisconnected(func(err error) {
		fmt.Println("Disconnected:", err)
	})

	// Connect returns once the handshake completes.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	channels, err := c.ListChannels(ctx)
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
| `OnConnected(func())` | Fires when fully connected |
| `OnDisconnected(func(error))` | Fires on disconnect |
| `OnTextMessage(func(TextMessageEvent))` | Fires on text messages |
| `OnClientEnter(func(ClientEnterEvent))` | Fires when a client comes into view; the event embeds its `teamspeak.ClientInfo` |
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
channels, err := c.ListChannels(ctx)

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

// The client database is paged; the iterator fetches page after page.
for entry, err := range c.ClientDatabase(ctx) {
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

### Errors

A refusal from the server is a `*teamspeak.ServerError`. It matches its code
from the `errcode` package and `teamspeak.ErrServer` with `errors.Is`:

```go
err := c.MoveClient(ctx, c.ClientID(), cid, teamspeak.ClientMoveOptions{Password: "wrong"})
switch {
case errors.Is(err, errcode.ChannelInvalidPassword):
	// ask for the password again
case errors.Is(err, teamspeak.ErrNotConnected):
	// the connection is gone
}
```

## Compatibility

From v1.0.0 the module follows semantic versioning. Minor releases may add
members to `Status`, `ServerFamily`, `identity.UIDAlgorithm`, the set of
`client.Event` types and the enumerations (`GroupType`, `Codec`, `Reason` and
the rest), and the server may send values this module does not name, so a
`switch` over any of them should have a default case.

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
└── internal/          # crypto, handshake, transport, discovery; wire and
                       #   servererr, the line format both protocols share;
                       #   serverquery, an unpublished ServerQuery client
```

## Acknowledgments

Protocol knowledge was primarily informed by the [TSLib](https://github.com/Splamy/TS3AudioBot) implementation in [TS3AudioBot](https://github.com/Splamy/TS3AudioBot) by Splamy. Huge thanks to the TS3AudioBot project and its contributors.

## Disclaimer

TeamSpeak is a registered trademark of [TeamSpeak Systems GmbH](https://teamspeak.com/). This project is not affiliated with, endorsed by, or associated with TeamSpeak Systems GmbH in any way.

This library is a **clean-room implementation** developed from publicly available documentation, protocol analysis of network traffic, and independent research. No proprietary TeamSpeak SDK code, headers, or libraries were used in its creation.

## License

[MIT](LICENSE)
