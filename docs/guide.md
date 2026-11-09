# Guide

How to connect, handle events, receive and send voice, send commands, move files and manage an identity. The [configuration](configuration.md) page covers the options, [streams](streams.md) the TeamSpeak 6 screen share and [serverquery](serverquery.md) the administration client.

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
re-exports them as aliases, so the [ServerQuery client](serverquery.md) shares
them.

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
| `OnClientUpdated(func(ClientUpdatedEvent))` | Fires when a client in view changes properties, this client included; the event's `Changes` hold only what changed |
| `OnClientServerGroupAdded`, `OnClientServerGroupRemoved`, `OnClientChannelGroupChanged` | Fire when a client's groups change |
| `OnChannelCreated`, `OnChannelEdited`, `OnChannelMoved`, `OnChannelDeleted`, `OnChannelDescriptionChanged`, `OnChannelPasswordChanged` | Fire when a channel changes |
| `OnChannelSubscribed`, `OnChannelUnsubscribed` | Fire when a channel subscription changes |
| `OnServerEdited` | Fires when the server's settings are edited |
| `OnPluginCommand`, `OnClientChatComposing`, `OnClientChatClosed` | Fire for a plugin command and for a private chat being typed in or closed |
| `OnViewReady`, `OnViewChanged` | Fire when the server view (`View`, in Server info below) has loaded and when it has changed |

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
above except connected, disconnected, kicked and the view's, which report the
connection or the client's own state and bypass it. It receives a `client.Event`, which is any of the typed
server events above (`TextMessageEvent`, `ClientEnterEvent`, `ChannelEditedEvent`
and the rest) or a `NotificationEvent`; it may pass the event on, replace it, or
drop it by not calling `next`.

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

## Voice

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

### Sending voice

The client sends encoded audio frames. It does not encode or decode audio: bring
an Opus encoder and give `SendVoice` one encoded frame per call. Each call is
one packet, and it is written at once. The client does no pacing, so the caller
sends frames in real time, one for each frame duration of the encoder it chose
(see [flood control](flood-control.md) for what else the client leaves to you).

```go
// enc is yours: it turns one frame of PCM into one Opus frame.
for pcm := range microphone {
	frame := enc.Encode(pcm)
	if err := c.SendVoice(frame, teamspeak.CodecOpusVoice, client.VoiceOptions{}); err != nil {
		return err
	}
}
// The end of speech.
err := c.SendVoice(nil, teamspeak.CodecOpusVoice, client.VoiceOptions{})
```

- `codec` is a `teamspeak.Codec`: `CodecOpusVoice` (mono, tuned for speech) or
  `CodecOpusMusic` (stereo, tuned for music). The other constants are Speex and
  CELT, which current clients no longer play. The client writes the codec byte
  as given and does not check it.
- An empty frame marks the end of speech. The server relays it, and a
  `VoiceReceiver` gets a `VoicePacket` with empty `Data`. Send one when the
  speaker stops.
- `client.VoiceOptions` has no fields yet; pass the zero value.
- `SendVoice`, `SendWhisper` and `SendGroupWhisper` return an error instead of
  panicking. Without an open connection each returns
  `teamspeak.ErrNotConnected` (check with `errors.Is`) and sends nothing.

### Whispers

A whisper goes to the targets you name instead of to the channel.

```go
// To clients and channels.
err := c.SendWhisper(frame, client.WhisperTargets{
	Clients:  []teamspeak.ClientID{clid},
	Channels: []teamspeak.ChannelID{cid},
}, teamspeak.CodecOpusVoice)

// To a group.
target := client.WhisperToServerGroup(client.GroupWhisperAllChannels, sgid)
err = c.SendGroupWhisper(frame, target, teamspeak.CodecOpusVoice)
```

- `SendWhisper` takes `WhisperTargets{Clients, Channels}`. It returns
  `client.ErrNoWhisperTargets` for no target at all,
  `client.ErrTooManyWhisperTargets` for more than 32 clients and
  `client.ErrTooManyWhisperChannels` for more than 255 channels.
- `SendGroupWhisper` takes a `GroupWhisperTarget`, built with
  `WhisperToServerGroup`, `WhisperToChannelGroup` (each with a group id),
  `WhisperToChannelCommanders` or `WhisperToAllClients`, and a
  `GroupWhisperScope` that picks which channels it reaches. Its fields are
  unexported, so a target is always one of the constructors' results; the zero
  value, or one built with a scope the packet has no name for, returns
  `client.ErrInvalidWhisperTarget`. The doc comments of `GroupWhisperType` and
  `GroupWhisperScope` say which values were tried on a live server and which
  carry the packet's names only.
- Whether a target hears a whisper is the server's decision, from the sender's
  `i_client_whisper_power` against the target's
  `i_client_needed_whisper_power`. Talk power does not apply to a whisper.
- The receiver learns only that a packet was a whisper (`VoicePacket.Whisper`),
  not who it was for.

The rest of the rules that decide whether voice is relayed are below.

### What the server relays

The server decides whose voice reaches whom, and drops the rest without an
error. Measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0-beta13.1:

- A speaker's voice to its channel is relayed while it may talk there: its
  `IsTalker` is set, or its talk power is at least the channel's needed talk
  power. Being a priority speaker does not change that. A whisper does not need
  talk power.
- Neither is relayed while the speaker is away, input-muted, or without input
  hardware, as it last told the server with `UpdateClient`. A bot that sets
  `IsAway` is not heard.
- A listener gets neither while it is output-muted or without output hardware.
  Being away or input-muted does not stop it hearing.
- Voice reaches only the clients in the channel. Subscribing to another channel
  shows its clients, not its voice.

## Connection and server

### Connection ping

`c.RoundTrip()` returns the keepalive round trip of the voice connection, a
`Mean` and `Deviation` over the last 10 pongs, and false before the first pong
(pings go every 5 seconds) or when not connected. It is the ping this client
reports when the server asks, and other clients see it as it was then, not as it
is now; the server does not report it back to the client itself.

### Server info

`ServerCapabilities()` is read from `initserver`, so it costs no round trip and
is filled in by the time `Connect` returns:

```go
caps := c.ServerCapabilities()
fmt.Println(caps.Family, caps.Version, caps.WelcomeMessage)
// caps.Extensions names the optional protocol features the server says it
// supports, such as "FILETIME" and "STREAM_P2P": empty on TeamSpeak 3. The
// teamspeak.ServerExtension constants name the known ones.
if caps.HasExtension(teamspeak.ServerExtensionStreamP2P) {
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
| `api_channels.go`  | Create, edit, move, delete, list, channel permissions         |
| `api_clients.go`   | List, move, kick, poke, edit, the client database, permissions |
| `api_server.go`    | Server and instance settings, server groups, temp passwords, bindings |
| `api_instance.go`  | List, create, start, stop and delete virtual servers, snapshots |
| `api_access.go`    | API keys and query logins                                      |
| `api_avatars.go`   | Removing avatars and icons, setting icons                      |
| `api_permission_batches.go` | Add and delete several permissions in one command     |
| `api_groups.go`    | Channel groups, the permission catalogue, privilege keys       |
| `api_moderation.go`| Bans, complaints, offline messages, text messages, the log     |
| `api_files.go`     | List, delete, rename, create directories, transfers            |

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
| `UploadFile(ctx, host, cid, path, data, UploadFileOptions)` / `DownloadFile(ctx, host, cid, path, DownloadFileOptions)` | Negotiate and transfer in one call, with `[]byte` data; an upload is checked against the server's stored size afterwards |
| `ListFilesRecursive(cid, path, RecursiveFilesOptions)` | List a directory and every directory under it |
| `UploadAvatar`, `DownloadAvatar`, `UploadIcon`, `DownloadIcon` | The avatar and icon helpers of `client.Client` |

The data travels over its own TCP connection to the file transfer port, on the
host the client connects to: `c.Host()` for a `client.Client`. `ctx`
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

### S3 file transfer

A TeamSpeak 6 server started with S3 file transfer keeps channel files in an
S3-compatible storage and names `s3` among its extensions
(`c.ServerCapabilities().HasExtension(teamspeak.ServerExtensionS3)`). The client asks the server for a
presigned URL over the voice connection and moves the bytes with a plain HTTPS
request to the storage; nothing goes through the file transfer port, and the
classic file commands above still reach a separate store. Measured on
TeamSpeak 6 6.0.0-beta13.1.

| Method | Description |
|---|---|
| `UploadS3File(ctx, cid, path, data, UploadS3FileOptions)` | Sign, send and complete an upload in one call, with `[]byte` data |
| `DownloadS3File(ctx, cid, path, DownloadS3FileOptions)` | Sign and read a download into memory; `MaxSize` bounds it (default 64 MiB) |
| `ListS3Files(ctx, cid, S3FileOptions)` | Every file in the channel, by path, as the server last read the storage |
| `DeleteS3File(ctx, cid, path, S3FileOptions)` / `DeleteS3Files(ctx, cid, paths, S3FileOptions)` | Delete one file, or several in one command; a file that is not there is deleted without an error |
| `RenameS3File(ctx, cid, oldPath, newPath, S3FileOptions)` / `RenameS3Files(ctx, cid, []S3FileRename, S3FileOptions)` | Rename or move files within the channel |
| `InitS3FileUpload(ctx, cid, path, size, S3FileOptions)` / `InitS3FileDownload(ctx, cid, path, S3FileOptions)` | Ask for a presigned URL |
| `client.UploadS3FileData(ctx, info, reader, S3TransferOptions)` / `client.DownloadS3FileData(ctx, info, writer, S3DownloadOptions)` | Move the bytes to or from the storage, for a stream |
| `CompleteS3FileUpload(ctx, info, S3FileOptions)` | Tell the server an upload is stored, so it lists the file |

```go
err := c.UploadS3File(ctx, cid, "/docs/notes.txt", data, client.UploadS3FileOptions{})
files, err := c.ListS3Files(ctx, cid, client.S3FileOptions{})
data, err = c.DownloadS3File(ctx, cid, "/docs/notes.txt", client.DownloadS3FileOptions{})
```

- A server that does not name `s3` is refused with `*client.S3UnsupportedError`
  before anything is sent: a TeamSpeak 3 server answers with an error that
  names no command, so the command would wait out its timeout.
- The server lists a file only after it is told the upload is done:
  `UploadS3File` does that, and a stream upload must call `CompleteS3FileUpload`.
  Other clients are told nothing about an upload or a delete.
- A path runs from the channel's root, with a leading slash added when missing.
  There are no directories, only paths, but uploading into a directory the
  server does not list yet needs directory create power as well as upload
  power. A path with an empty, `.` or `..` segment, a control character or a
  trailing slash is refused with `ErrInvalidCommand`: the server signs the path
  as given, and a URL parser would change it.
- An upload sends exactly the size the URL is signed for: a reader that gives
  fewer or more bytes fails the upload with an error wrapping `ErrFileTransfer`.
- A refusal by the storage is an `*S3TransferError` with the HTTP `Status`
  (404 for a file that is not there, 403 for an expired URL) and the storage's
  `Code`; so is a request that got no answer, or a server that reports its own
  request to the storage failed. It wraps `ErrFileTransfer`, and its message never names
  the presigned URL, which is a credential until it expires (300 seconds by
  default). `S3TransferOptions.HTTPClient` routes the request through a proxy,
  trusts another certificate authority or traces it.
- A refusal by the server is the `*ServerError` it sends: 2049 (invalid file
  permissions) for an upload or download without the power, 2568 for a delete
  or a rename without it.
- A rename is a copy the server makes in the storage, and its copy request
  leaves the `x-amz-copy-source` header unsigned, which a storage that checks
  signatures refuses (RustFS, versitygw, SeaweedFS and CloudServer did,
  measured on 6.0.0-beta13.1): the server answers `success=0`, `RenameS3File`
  returns an `*S3TransferError` and the file stays. A storage that checks none,
  such as S3Mock, takes it. A file already at the new path is replaced, and
  there is no move to another channel. `RenameS3Files` is answered once, for
  its last rename only, so an earlier failure goes unreported; after a batch
  whose last rename failed, the list the server keeps shows the others a moment
  later rather than at once.
- A rename or delete without the power is refused with 2568, and a batch
  delete then deletes nothing.
- They run on the voice connection; WebQuery refuses them as unknown commands.

#### Avatars and icons over S3

In channel 0 the server signs an upload only for a name that starts with
`avatar_` or `icon_`, and keeps the file under the name it is given, unlike the
classic upload, which stores an avatar under the uploader's
`teamspeak.AvatarFileName`. The S3 and classic avatars and icons are separate
stores.

| Method | Description |
|---|---|
| `UploadS3Avatar(ctx, data, S3TransferOptions)` | Upload under the own avatar name, tell the server it is done, set `client_flag_avatar`; returns the MD5 |
| `DownloadS3Avatar(ctx, uid, S3TransferOptions)` | The avatar's bytes; false when the storage has none (404) |
| `RemoveS3Avatar(ctx)` | Delete the own avatar file and empty the flag |
| `UploadS3Icon(ctx, data, S3TransferOptions)` / `DownloadS3Icon(ctx, id, S3TransferOptions)` / `DeleteS3Icon(ctx, id)` | The icon file `/icon_<id>` in channel 0, `id` being `teamspeak.IconIDOf(data)` |

An avatar over `i_client_max_avatar_filesize` (200000 bytes by default,
inclusive) and an icon over `i_max_icon_filesize` (8192 for a Server Admin), or
an icon upload without `b_icon_manage`, is refused with 2049; deleting an icon
without `b_icon_manage`, or another client's avatar, with 2568.

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
