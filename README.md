<p align="center">
  <a href="https://pkg.go.dev/github.com/honeybbq/teamspeak-go">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/HoneyBBQ/teamspeak-go/main/docs/assets/banner-dark.svg">
      <img alt="teamspeak-go" src="https://raw.githubusercontent.com/HoneyBBQ/teamspeak-go/main/docs/assets/banner-light.svg" width="460">
    </picture>
  </a>
</p>

<p align="center">
  <strong>An independent TeamSpeak client protocol library written in pure Go.</strong><br>
  Works with TeamSpeak 3 and TeamSpeak 6 servers. No proprietary SDK or code.
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/honeybbq/teamspeak-go"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/honeybbq/teamspeak-go.svg"></a>
  <a href="https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/honeybbq/teamspeak-go/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://codecov.io/gh/honeybbq/teamspeak-go"><img alt="codecov" src="https://codecov.io/gh/honeybbq/teamspeak-go/branch/main/graph/badge.svg"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/HoneyBBQ/teamspeak-go"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/HoneyBBQ/teamspeak-go/badge"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/honeybbq/teamspeak-go"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/honeybbq/teamspeak-go">Docs</a> ·
  <a href="docs/guide.md">Guide</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CHANGELOG.md#migrating-from-v02-and-v03">Migrating from v0.x</a>
</p>

## Why this library

- **The voice protocol, end to end.** ECDH key exchange, the RSA puzzle, EAX-encrypted transport, and Opus voice (codecs 4 and 5), in pure Go with no CGO.
- **ServerQuery too.** The same typed commands run over raw TCP, SSH (with host-key verification) or WebQuery, with the server's notifications as events.
- **Typed commands and events.** Every command the voice protocol answers is a typed method, ids are distinct types, times are `time.Time`, and events arrive on handlers with pluggable middleware.
- **File transfers.** Upload, download and delete files on the server, with avatars and icons covered.
- **TeamSpeak 6 screen-share signalling.** Find, publish and watch streams in the `stream` package, with SDP and ICE as strings for any WebRTC stack.
- **Built for long-running bots.** Opt-in reconnection tuned for TeamSpeak's antiflood ban, and a token-bucket rate limiter that keeps you clear of flood kicks.
- **Identities and server facts.** Generate, import, export and upgrade identities; read the server version, its uid hash (SHA-1 on TS3, SHA-256 on TS6) and its name, icon and banner.
- **TeamSpeak 3 and 6, pure Go.** Zero CGO, cross-compiles anywhere, with a custom `net.PacketConn` and transfer dialer for proxies and tests.

## Install

```bash
go get github.com/honeybbq/teamspeak-go@v1.0.0-beta.14
```

1.0 is in beta: `go get` without a version still picks v0.2, because Go skips pre-releases unless you name one. Go 1.26 or newer is required. Coming from v0.x? [CHANGELOG.md](CHANGELOG.md) has the full list of changes and a migration table.

## Quick start

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
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "localhost", "GoBot",
		client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
		client.WithDefaultChannel("Lobby"))
	if err != nil {
		log.Fatal(err)
	}
	c.OnTextMessage(func(m client.TextMessageEvent) { fmt.Printf("[%s]: %s\n", m.InvokerName, m.Message) })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer c.Disconnect(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
```

## Packages

| Import                                          | What it is                                                                 | Docs                                        |
| ----------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------- |
| `github.com/honeybbq/teamspeak-go`              | What every client shares: typed commands, results, events, errors, ids     | [Design](docs/design.md)                    |
| `github.com/honeybbq/teamspeak-go/client`       | The voice client: session, events, voice, reconnection, file transfers     | [Guide](docs/guide.md)                      |
| `github.com/honeybbq/teamspeak-go/serverquery`  | The ServerQuery client over raw TCP, SSH or WebQuery                       | [ServerQuery](docs/serverquery.md)          |
| `github.com/honeybbq/teamspeak-go/stream`       | TeamSpeak 6 screen-share signalling; no WebRTC code                        | [Streams](docs/streams.md)                  |
| `github.com/honeybbq/teamspeak-go/identity`     | Creating, storing and inspecting identities                                | [Identity](docs/guide.md#identity)          |
| `github.com/honeybbq/teamspeak-go/versions`     | Client versions a server accepts, for `client.WithVersion`                 | [Configuration](docs/configuration.md)      |

The `errcode`, `perm`, `notify`, `prop` and `commands` packages hold the server's constants and the command language. See [Architecture](docs/architecture.md).

## Documentation

The API reference is on [pkg.go.dev](https://pkg.go.dev/github.com/honeybbq/teamspeak-go). The pages below are the long-form guides.

- [Guide](docs/guide.md): connecting, events, commands, file transfers and identities.
- [Configuration](docs/configuration.md): options, client version and tracing.
- [Streams](docs/streams.md): TeamSpeak 6 screen-share signalling, and interop with the TeamSpeak 6 client.
- [ServerQuery](docs/serverquery.md): the query client, its transports and SSH host-key policy.
- [Design](docs/design.md): errors, ids, absent values, events, stability, and the server behaviour the SDK works around.
- [Compatibility](docs/compatibility.md): supported Go versions and the differences from the JavaScript SDK.
- [Architecture](docs/architecture.md): module layout.

## Compatibility

| Target      | Supported                                               |
| ----------- | ------------------------------------------------------- |
| TeamSpeak 3 | Voice protocol and ServerQuery                          |
| TeamSpeak 6 | Voice protocol, ServerQuery and screen-share signalling |
| Go          | 1.26 and newer; pure Go, no CGO                         |

Details in [docs/compatibility.md](docs/compatibility.md).

## Related

- **[teamspeak-js](https://github.com/honeybbq/teamspeak-js)** — The same SDK for TypeScript and Node.js

## Acknowledgments

Protocol knowledge was primarily informed by the [TSLib](https://github.com/Splamy/TS3AudioBot) implementation in [TS3AudioBot](https://github.com/Splamy/TS3AudioBot) by Splamy. Huge thanks to the TS3AudioBot project and its contributors.

The error code names and descriptions, the permission names and descriptions, and the table of client versions with their signatures draw on [tsdeclarations](https://github.com/ReSpeak/tsdeclarations) by [ReSpeak](https://github.com/ReSpeak), used under the MIT licence; see [THIRD_PARTY_NOTICES.md](https://github.com/honeybbq/teamspeak-go/blob/main/THIRD_PARTY_NOTICES.md). Thanks to ReSpeak for documenting the protocol in the open.

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for setup and checks.

## License

[MIT](LICENSE)

---

<sub>TeamSpeak is a registered trademark of [TeamSpeak Systems, Inc.](https://teamspeak.com/). This project is not affiliated with, endorsed by, or associated with TeamSpeak Systems, Inc. in any way.</sub>

<sub>This library is an **independent implementation** built from public documentation, open-source implementations, observation of network traffic, and independent research. It contains no TeamSpeak proprietary code, headers, libraries, or binaries.</sub>

<sub>The project implements the client side only and does not implement a TeamSpeak server.</sub>
