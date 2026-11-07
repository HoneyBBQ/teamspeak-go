# Architecture

```
teamspeak-go/
├── *.go               # package teamspeak — what the clients share: the
│                      #   typed commands (Commands, on any Executor), their
│                      #   results, events, errors, and file transfer data
├── client/            # package client — the voice client: session, events,
│                      #   voice, reconnection, voice-only commands
├── serverquery/       # package serverquery — the ServerQuery client: the
│                      #   three transports, the query session, events
├── stream/            # package stream — TeamSpeak 6 screen share signalling
│                      #   over a client; e2e/ is a module of its own that
│                      #   carries a stream between two Pion peers
├── identity/          # creating, storing and inspecting identities
├── versions/          # client versions that servers accept, for
│                      #   client.WithVersion
├── errcode/           # the server's error codes, as constants
├── perm/              # the permission names, as constants
├── notify/            # the notification names, as constants
├── prop/              # the property keys of serverinfo, clientinfo and the like
├── commands/          # the command language: command names and escaping
├── api/               # the exported API of each package, as apidump writes it;
│                      #   CI fails when the code and this record disagree
└── internal/
    ├── crypto/        # packet protection: keys, EAX, the ECDH exchange
    ├── handshake/     # the client's side of the connection handshake
    ├── transport/     # UDP packets, acks, resends, generation windows, QuickLZ
    ├── discovery/     # SRV / TSDNS / direct address resolution
    ├── wire/          # the line format both protocols share
    ├── servererr/     # the error line that ends every answer
    ├── servernotify/  # notifications read into events, for both clients
    ├── eventbus/      # handlers called one at a time, in order
    ├── serverquery/   # one command at a time, each answer paired with its
    │                  #   command, under every query transport
    ├── request/       # building and encoding a typed command's line
    ├── identitykey/   # an identity's private key, for this module's packages
    ├── ftdial/        # a file transfer whose connection was never made
    ├── sshalgo/       # the SSH algorithms the query client offers
    ├── livetest/      # what the live tests of several packages share
    └── tools/apidump/ # writes and checks api/
```
