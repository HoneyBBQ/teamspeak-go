<div align="center">

# teamspeak-go

**A clean-room TeamSpeak client protocol library written in pure Go.**

Compatible with TeamSpeak 3, 5 & 6. No proprietary SDK. No copy-pasted code.

[![CI](https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml/badge.svg)](https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/honeybbq/teamspeak-go/branch/main/graph/badge.svg)](https://codecov.io/gh/honeybbq/teamspeak-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/honeybbq/teamspeak-go)](https://goreportcard.com/report/github.com/honeybbq/teamspeak-go)

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
- **Full command set** — 107 typed methods covering every command the voice protocol answers
- **Reconnection** — Opt-in retry with backoff, tuned for TeamSpeak's antiflood ban
- **Server capabilities** — Reports the server version and the uid hash it uses (SHA-1 on TS3, SHA-256 on TS6)
- **Custom transports** — Supply your own net.PacketConn and file transfer dialer
- **Zero CGO** — Pure Go, cross-compile anywhere

## Installation

```bash
go get github.com/honeybbq/teamspeak-go
```

Requires **Go 1.26** or later.

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

	c.OnTextMessage(func(msg client.TextMessage) {
		fmt.Printf("[%s]: %s\n", msg.InvokerName, msg.Message)
	})

	c.OnDisconnected(func(err error) {
		fmt.Println("Disconnected:", err)
	})

	// Connect returns once the handshake completes.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
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
| `NewClient(identity, addr, nickname, ...opts)` | Create a new client |
| `Connect(ctx)` | Connect, returning once the handshake completes |
| `Disconnect(ctx)` | Leave the server and close the connection |
| `ClientID()` | Our clid, assigned by the server |
| `ChannelID()` | The channel we are in |
| `ServerCapabilities()` | Server version, family and uid hash |
| `UniqueIdentifier()` | Our own uid, hashed as the server does |

### Events

| Method | Description |
|---|---|
| `OnConnected(func())` | Fires when fully connected |
| `OnDisconnected(func(error))` | Fires on disconnect |
| `OnTextMessage(func(TextMessage))` | Fires on text messages |
| `OnClientEnter(func(ClientInfo))` | Fires when a client joins |
| `OnClientLeave(func(ClientLeftViewEvent))` | Fires when a client leaves |
| `OnClientMoved(func(ClientMovedEvent))` | Fires when a client moves channels |
| `OnKicked(func(KickedEvent))` | Fires when the bot is kicked from its channel or the server |

Each `On` method returns a function that removes the handler. Handlers run one
at a time, in the order their events arrived, on a goroutine of the client's
own, so a handler may call the client and wait for an answer; a handler that
blocks holds up the events behind it.

### Commands

Every command is a typed method taking a context, defined once in the root
`teamspeak` package and embedded into the client. Options structs use a nil
pointer field to omit a parameter entirely — which the protocol distinguishes from an empty value:
clearing a password takes `channel_password=`, leaving it alone sends nothing.

```go
channels, err := c.ListChannels(ctx)

cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{
	ChannelName:          "Lounge",
	ChannelTopic:         teamspeak.String("the quiet one"),
	ChannelFlagPermanent: teamspeak.BoolOf(true),
})

err = c.MoveClient(ctx, c.ClientID(), cid, "channel-password")
err = c.SendTextMessage(ctx, teamspeak.TextMessageTargetChannel, cid, "hello")
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
| `ListFiles(cid, path, pw)` | Directory listing |
| `GetFileInfo(cid, path, pw)` | Size and timestamp of one file |
| `DeleteFile(cid, paths, pw)` | Delete one or more files |
| `CreateDirectory(cid, dir, pw)` | Create a directory |
| `RenameFile(cid, old, new, opts)` | Rename or move a file |
| `StopFileTransfer(id, delete)` | Cancel a running transfer |
| `ListActiveTransfers()` | Transfers in progress |
| `InitFileUpload(...)` / `InitFileDownload(...)` | Negotiate a transfer; pass the result to `UploadFileData` / `DownloadFileData` |
| `UploadFileData(host, info, reader, dialer)` | Transfer file data to the server |
| `DownloadFileData(host, info, writer, dialer)` | Receive file data from the server |

### Identity

```go
// Generate a new identity with security level 8
id, err := identity.Generate(ctx, 8)

// Export for storage — this includes the private key, so store it like a
// password. String() and slog never print the key.
exported := id.Export()

// Read a previously exported identity
id, err = identity.Parse(exported)

// Raise the security level (CPU-intensive; ctx bounds it)
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
err = id.UpgradeToLevel(ctx, 10)
```

### Options

```go
c, err := client.New(id, "ts.example.com", "Bot",
	client.WithLogger(slog.Default()), // silent without it
	client.WithResolver(customResolver),
	client.WithCommandMiddleware(loggingMiddleware),
	client.WithEventMiddleware(filterMiddleware),
	client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
	client.WithDefaultChannel("Lobby"),
	client.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
)
```

Connection auth options:

- `WithServerPassword(password)` accepts the plain-text server password and sends the TeamSpeak protocol hash during `clientinit`
- `WithDefaultChannel(channel)` requests a default channel during `clientinit`
- `WithDefaultChannelPassword(password)` accepts the plain-text channel password and sends the TeamSpeak protocol hash for the configured default channel

## Architecture

```
teamspeak-go/
├── *.go               # package teamspeak — what the clients share: the
│                      #   typed commands (Commands, on any Executor), their
│                      #   results, errors, and file transfer data
├── client/            # package client — the voice client: session, events,
│                      #   voice, reconnection, voice-only commands
├── identity/          # creating, storing and inspecting identities
├── commands/          # the command language: escaping, parsing, building
└── internal/          # crypto, handshake, transport, discovery
```

## Acknowledgments

Protocol knowledge was primarily informed by the [TSLib](https://github.com/Splamy/TS3AudioBot) implementation in [TS3AudioBot](https://github.com/Splamy/TS3AudioBot) by Splamy. Huge thanks to the TS3AudioBot project and its contributors.

## Disclaimer

TeamSpeak is a registered trademark of [TeamSpeak Systems GmbH](https://teamspeak.com/). This project is not affiliated with, endorsed by, or associated with TeamSpeak Systems GmbH in any way.

This library is a **clean-room implementation** developed from publicly available documentation, protocol analysis of network traffic, and independent research. No proprietary TeamSpeak SDK code, headers, or libraries were used in its creation.

## License

[MIT](LICENSE)
