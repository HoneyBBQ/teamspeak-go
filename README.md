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

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

func main() {
	// Generate a new identity (or load an existing one)
	identity, err := crypto.GenerateIdentity(8)
	if err != nil {
		log.Fatal(err)
	}

	// Create the client
	client := teamspeak.NewClient(
		identity,
		"localhost",
		"GoBot",
		teamspeak.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
		teamspeak.WithDefaultChannel("Lobby"),
		teamspeak.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
	)

	// Register event handlers
	client.OnConnected(func() {
		fmt.Println("Connected to server!")
	})

	client.OnTextMessage(func(msg teamspeak.TextMessage) {
		fmt.Printf("[%s]: %s\n", msg.InvokerName, msg.Message)
	})

	client.OnDisconnected(func(err error) {
		fmt.Println("Disconnected:", err)
	})

	// Connect
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}

	// Wait until connected
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.WaitConnected(ctx); err != nil {
		log.Fatal(err)
	}

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	client.Disconnect()
}
```

## API Overview

### Client Lifecycle

| Method | Description |
|---|---|
| `NewClient(identity, addr, nickname, ...opts)` | Create a new client |
| `Connect()` | Initiate connection to the server |
| `WaitConnected(ctx)` | Block until the handshake completes |
| `Disconnect()` | Gracefully disconnect |
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
| `OnKicked(func(string))` | Fires when the bot is kicked |

### Commands

Every command the voice protocol answers is a typed method, grouped by area in
`api_*.go`. Each takes an options struct, and a nil pointer field omits the
parameter entirely — which the protocol distinguishes from an empty value:
clearing a password takes `channel_password=`, leaving it alone sends nothing.

```go
channels, err := c.ListChannels()

cid, err := c.CreateChannel(teamspeak.ChannelCreateOptions{
	ChannelName:          "Lounge",
	ChannelTopic:         teamspeak.String("the quiet one"),
	ChannelFlagPermanent: teamspeak.BoolOf(true),
})

err = c.MoveClient(c.ClientID(), cid, "channel-password")
err = c.SendTextMessage(teamspeak.TextMessageTargetChannel, cid, "hello")
```

| File            | Covers                                                          |
| --------------- | --------------------------------------------------------------- |
| `api_channels.go`  | Create, edit, move, delete, subscribe, channel permissions    |
| `api_clients.go`   | List, move, kick, poke, edit, the client database, permissions |
| `api_server.go`    | Server and instance settings, groups, temp passwords, bindings |
| `api_groups.go`    | Channel groups, the permission catalogue, tokens               |
| `api_moderation.go`| Bans, complaints, offline messages, text messages, the log     |
| `api_files.go`     | List, delete, rename, create directories, transfer negotiation |

> **The voice protocol answers `ok` with no data row for a set of commands that
> ServerQuery answers normally** — `servergrouplist`, `permissionlist`, the
> group permission lists, several client lookups, and the file transfer
> negotiation. Verified with Server Admin, so this is server behaviour rather
> than permissions. An empty slice does not mean "nothing there"; see
> [voice-protocol-empty-responses.md](https://github.com/honeybbq/teamspeak-js/blob/main/docs/voice-protocol-empty-responses.md).

For anything outside the typed set, `ExecCommand` and `ExecCommandWithResponse`
take a raw command.

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
| `InitFileUpload(...)` / `InitFileDownload(...)` | Negotiate a transfer (see the note above: empty over the voice protocol) |
| `UploadFileData(host, info, reader, dialer)` | Transfer file data to the server |
| `DownloadFileData(host, info, writer, dialer)` | Receive file data from the server |

### Identity

```go
// Generate a new identity with security level 8
identity, err := crypto.GenerateIdentity(8)

// Export to string for persistent storage
exported := identity.String()

// Import from a previously exported string
identity, err = crypto.IdentityFromString(exported)

// Upgrade security level (CPU-intensive)
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
err = identity.UpgradeToLevel(10, ctx)
```

### Options

```go
client := teamspeak.NewClient(identity, "ts.example.com", "Bot",
	teamspeak.WithLogger(slog.Default()),
	teamspeak.WithResolver(customResolver),
	teamspeak.WithCommandMiddleware(loggingMiddleware),
	teamspeak.WithEventMiddleware(filterMiddleware),
	teamspeak.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
	teamspeak.WithDefaultChannel("Lobby"),
	teamspeak.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
)
```

Connection auth options:

- `WithServerPassword(password)` accepts the plain-text server password and sends the TeamSpeak protocol hash during `clientinit`
- `WithDefaultChannel(channel)` requests a default channel during `clientinit`
- `WithDefaultChannelPassword(password)` accepts the plain-text channel password and sends the TeamSpeak protocol hash for the configured default channel

## Architecture

```
teamspeak-go/
├── client.go          # Client lifecycle, connection management
├── api.go             # High-level API (messages, channels, clients)
├── commands.go        # Command sending and response tracking
├── events.go          # Event handler registration and middleware
├── notifications.go   # Server notification parsing and dispatch
├── handshake.go       # Protocol handshake orchestration
├── transfer.go        # File transfer operations
├── crypto/            # ECDH, EAX encryption, identity management
├── handshake/         # Crypto handshake and license verification
├── transport/         # UDP packet framing, ACK, compression
├── commands/          # Command builder and parser
└── discovery/         # SRV / TSDNS / direct address resolution
```

## Acknowledgments

Protocol knowledge was primarily informed by the [TSLib](https://github.com/Splamy/TS3AudioBot) implementation in [TS3AudioBot](https://github.com/Splamy/TS3AudioBot) by Splamy. Huge thanks to the TS3AudioBot project and its contributors.

## Disclaimer

TeamSpeak is a registered trademark of [TeamSpeak Systems GmbH](https://teamspeak.com/). This project is not affiliated with, endorsed by, or associated with TeamSpeak Systems GmbH in any way.

This library is a **clean-room implementation** developed from publicly available documentation, protocol analysis of network traffic, and independent research. No proprietary TeamSpeak SDK code, headers, or libraries were used in its creation.

## License

[MIT](LICENSE)
