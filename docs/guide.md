# Guide

How to connect, handle events, send commands, move files and manage an identity. The [configuration](configuration.md) page covers the options, [streams](streams.md) the TeamSpeak 6 screen share and [serverquery](serverquery.md) the administration client.

## Client Lifecycle

| Method | Description |
|---|---|
| `client.New(identity, addr, nickname, ...opts)` | Create a new client |
| `Connect(ctx)` | Connect, returning once the handshake completes |
| `Disconnect(ctx)` | Leave the server, close the connection and cancel a pending reconnect |
| `Status() client.Status` | `StatusDisconnected`, `StatusConnecting` or `StatusConnected` |
| `ClientID() teamspeak.ClientID` | Our clid, assigned by the server |
| `ChannelID() teamspeak.ChannelID` | The channel we are in |
| `ServerCapabilities()` | What the server said about itself in the handshake: version, family, uid hash, protocol extensions and welcome message |
| `UID() teamspeak.UID` | Our own uid, hashed as the server does |

## Events

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

### Event middleware

Event middleware sees every server event before its handlers do — the events
above except connected, disconnected and kicked, which report the connection
itself and bypass it. It receives a `client.Event`, which is one of
`TextMessageEvent`, `ClientEnterEvent`, `ClientLeaveEvent`, `ClientMovedEvent`,
`PokeEvent` or `NotificationEvent`; it may pass the event on,
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

### Receiving voice

Voice is not an event: it does not go through the event queue or the event
middleware, so no handler can delay it. A bot that wants audio makes a
`VoiceReceiver`, a bounded buffer that the client fills and the caller reads,
in a goroutine of its own. The packets carry their order, arrival time and
whether they were whispers:

```go
rx, err := c.NewVoiceReceiver(client.VoiceReceiverOptions{})
if err != nil {
	return err
}
defer rx.Close()

var p client.VoicePacket // reused: after the first frames, reading allocates nothing
for {
	if err := rx.Read(ctx, &p); err != nil {
		return err // ctx ended, or rx was closed
	}
	frame := slices.Clone(p.Data) // to keep a frame past the next Read, copy it
	handle(p.Session, p.ClientID, p.Whisper, p.Seq, p.Codec, p.ReceivedAt, frame)
}
```

`Read` waits; `TryRead` takes what has arrived and returns, for a loop that a
clock of its own drives. The receiver is the client's, not a connection's: it
may be made before `Connect` and goes on through reconnections, and every
packet says which session (`Client.Session`) it arrived in.

A packet is what the speaker sent and the server relayed, with nothing
interpreted:

- `Seq` is the speaker's own packet counter, in step with what it sent and the
  same for every listener. It wraps from 65535 to 0, so compare two with
  `int16(a-b)`. Whispers have a counter of their own, so a speaker's packets are
  told apart by `ClientID` and `Whisper`, and, because a client id names a
  client only within one session, by `Session` too. A speaker's client sets
  `Seq`: do not let it grow a buffer without bound.
- The client does not reorder, deduplicate or fill gaps. A gap in `Seq` is a
  packet lost or still to come; the server itself reorders packets now and then.
- `Data` is empty at the end of speech by convention. The end frame has its
  own `Seq`, and can be lost like any packet.
- `ReceivedAt` is the time the datagram was read from the socket, with a
  monotonic reading, so the difference of two is the time between their arrivals.

The client never waits for a receiver. One that is not read fast enough drops
its oldest packets and counts them in `Dropped`; the connection, the events and
the other receivers go on. Every receiver gets every packet, so a second
consumer makes a second receiver. `VoiceReceiver` is experimental.

### Connection ping

`c.RoundTrip()` returns the keepalive round trip of the voice connection, a
`Mean` and `Deviation` over the last 10 pongs, and false before the first pong
(pings go every 5 seconds) or when not connected. It is what other clients see
as this client's ping; the server does not report it back to the client itself.

### Server info

`ServerCapabilities()` is read from `initserver`, so it costs no round trip and
is filled in by the time `Connect` returns:

```go
caps := c.ServerCapabilities()
fmt.Println(caps.Family, caps.Version, caps.WelcomeMessage)
// caps.Extensions names the optional protocol features the server says it
// supports, such as "FILETIME" and "STREAM_P2P": empty on TeamSpeak 3.
if caps.HasExtension("STREAM_P2P") {
	// ...
}
```

It holds only what lasts the connection. The server's name, icon and banner can
be edited while a client is connected, so they are read from the view, which
follows the edits:

```go
v := c.View()
fmt.Println(v.ServerName())
// v.ServerIconID() is the icon's CRC32 (0 for none), unsigned even when the
// server sends it signed; v.ServerBannerImageURL() is "" for none.
```

## Commands

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

// Several of the connection's own permissions come in one command, in the order
// asked; a name the server does not know refuses all of them with 2562.
own, err := c.GetOwnPermissions(ctx, []teamspeak.Permission{
	teamspeak.PermissionByName(perm.ClientBanList), teamspeak.PermissionByName(perm.ChannelNeededJoinPower),
})

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

## File Transfers

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

## Identity

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
