# Architecture

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
├── stream/            # package stream — TeamSpeak 6 screen share signalling
│                      #   over a client; e2e/ is a module of its own that
│                      #   carries a stream between two pion peers
├── serverquery/       # package serverquery — the ServerQuery client: the
│                      #   three transports, the query session, events
└── internal/          # crypto, handshake, transport, discovery; wire and
                       #   servererr, the line format both protocols share;
                       #   eventbus and servernotify, what the clients share
```
