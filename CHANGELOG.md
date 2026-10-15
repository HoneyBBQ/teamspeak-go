# Changelog

All notable changes to this module. It follows [Semantic Versioning](https://semver.org);
from v1.0.0 on, a breaking change needs a new major version and import path.

## v1.0.0-beta.6 (2026-10-15)

Breaking changes, made before v1.0.0 so that none of them needs a `/v2` import
path later.

- `Channel.TotalClients`, `TotalFamilyClients` and `NeededSubscribePower` are
  `*int32`, nil when the answer does not carry them, which is always so for
  `GetChannelInfo`; `ListChannels` sets them. `Binding.Port` is `*uint16`, nil
  when the server reports no port. Read `*ch.TotalClients` after a nil check;
  to compare, use `reflect.DeepEqual` rather than `==` on a `Channel` or
  `Binding`.
- `ClientDatabase(ctx)` is `IterateClientDatabase(ctx, teamspeak.PagingOptions{})`;
  `PageSize` is how many records to ask for per page, 0 meaning 100. The walk
  also ends now on a page that starts at or before the last record seen, which
  is a server ignoring `start`. The new `ListClientDatabase(ctx,
  teamspeak.ClientDatabasePageOptions{Start, Limit})` reads one page.
- `ListChannels`, `ListBans`, `ListServerGroups`, `ListChannelGroups` and
  `ListMessages` take a final options argument: `teamspeak.ChannelListOptions{}`,
  `BanListOptions{}`, `ServerGroupListOptions{}`, `ChannelGroupListOptions{}`
  and `MessageListOptions{}`. They have no fields yet; pass the empty value.
- `GetClientInfo` is `GetClientProperties`, and `teamspeak.ClientInfo`, the
  entry `ListClients` returns and `ClientEnterEvent` embeds, is
  `teamspeak.ClientEntry`. Rename the uses; `evt.ClientEntry` replaces
  `evt.ClientInfo` on a `ClientEnterEvent`.
- `GetClientNameByUID` returns `(teamspeak.ClientDatabaseName, error)` instead
  of `(ClientDBID, string, error)`, and `GetClientNameByDBID` returns that
  type instead of a `string`: use `.DatabaseID` and `.Name`. `GetClientIDs`
  returns `[]teamspeak.ClientMatch` instead of `[]ClientID`: use `.ID`, and
  `.Nickname` for the name it now carries.
- `OnConnected` takes `func(client.ConnectedEvent)` and `OnDisconnected` takes
  `func(client.DisconnectedEvent)`: write `func(e client.DisconnectedEvent)`
  and read `e.Err`, which is nil after `Disconnect`. `e.WillReconnect` is true
  when the reconnect loop will try again, and `ConnectedEvent.Reconnected` is
  true when the connection came from that loop.
- `TextMessageEvent.InvokerGroups` is documented as nil when neither the
  notification nor the client knew the sender's groups; no code change.
  `ClientMovedEvent.ReasonMessage` carries the notification's `reasonmsg`.
- `SendWhisper(data, []ClientID{...}, codec)` is
  `SendWhisper(data, client.WhisperTargets{Clients: []ClientID{...}}, codec)`.
  Only clients can be addressed: the whisper packet carries no channel
  targets, so `WhisperTargets` has no `Channels` field yet. `SendVoice` takes a
  final `client.VoiceOptions{}`, an empty struct reserved for later.
- `UpdateMessageFlag(ctx, id, true)` is
  `UpdateMessageFlag(ctx, id, teamspeak.MessageFlags{Read: true})`.

## v1.0.0-beta.5 (2026-10-15)

- `client.WithVersion` chooses the platform, version and signature `clientinit`
  sends, and the new `versions` package has the versions a server accepts, one
  variable each: `client.WithVersion(versions.Windows_3_6_2_1695203293)`.
  Without the option the client sends what it always did. `New` returns
  `ErrInvalidConfig` for a version with an empty field or a signature that is
  not the base64 of 64 bytes.
- `teamspeak.HostMessageMode` names the host message modes
  (`HostMessageNone`, `HostMessageLog`, `HostMessageModal`,
  `HostMessageModalQuit`), and `ServerCapabilities.HostMessageMode` has that
  type instead of `int`. Comparisons with the constants or with a literal keep
  compiling; convert with `int(caps.HostMessageMode)` where an `int` is needed.
- `GetChannelInfo` leaves `TotalClients`, `TotalFamilyClients` and
  `NeededSubscribePower` at 0, because `channelinfo` does not carry them; the
  documentation said only `channellist` reported them without saying what
  `GetChannelInfo` returns. Use `ListChannels` for live counts.
- `ListBindings` fills `Binding.Subsystem` with the subsystem asked for, or
  `"voice"` when none was, where it came back empty. `Binding.Port` is 0 when
  the server does not report one.

## v1.0.0-beta.4 (2026-10-14)

- `teamspeak.ErrFileTransfer` is wrapped by every error `UploadFileData`,
  `DownloadFileData` and `DialFileTransfer` return, a cancelled context's
  included, which still matches `context.Canceled` or
  `context.DeadlineExceeded`. The messages lose their "failed to" stutter:
  `file transfer: dial host:port: ...`, `file transfer: send key: ...`,
  `file transfer: upload: ...`, `file transfer: download: ...`.
- `FileTransferOptions.IdleTimeout` fails a transfer that moves no byte for
  that long, with an error wrapping `ErrFileTransfer` and
  `os.ErrDeadlineExceeded`. Zero means 30 seconds; a negative value disables
  it. Before, a server that went silent held a transfer until its context
  ended.
- `DownloadFileData` checks the size the server announced: a download that
  sends more fails after that size, without writing the excess, and one that
  ends short of it fails with `io.ErrUnexpectedEOF`. Both used to succeed.
- Reconnect attempts end at once when `Disconnect` is called, rather than at
  their own timeout; `AddrResolver` implementations must honour their context.
- `Disconnect` waited a full second every time. It waited for an error line in
  answer to its goodbye, but TeamSpeak 3 and 6 answer `clientdisconnect` with
  a `notifyclientleftview` about the client itself and no error line, which
  the client also took for the server removing it. That announcement now ends
  the wait, so a disconnect takes a few milliseconds.
- `WithTrace` reports the milestones of a client's connection attempts and
  sessions: resolution (with every candidate the resolver gave), opening, the
  handshake (with the RSA puzzle level and time, the packets sent again and the
  server's public key), the session start (with the accepted nickname, talk
  power and the `initserver` parameters), the end of the welcome sequence (with
  the channel the client landed in), a failed attempt with its phase and
  target, `Disconnect`'s goodbye, the end of every session with its cause, and
  the reconnect loop's decisions. Each is an optional hook of `Trace`, called
  synchronously and with no lock held.
- `FileTransferOptions.Trace` reports one `UploadFileData`, `DownloadFileData`
  or `DialFileTransfer` call: the dial, progress (at most once per 64 KiB,
  and a final count), and exactly one of done and failed with the stage it
  failed in. The transfer key is never reported.
- `ServerCapabilities` gains `ServerID`, `ServerUID`, `HostMessage` and
  `HostMessageMode`, read from `initserver`.

## v1.0.0-beta.3 (2026-10-14)

- `ListChannels` now fills in the fields `Channel` declares: topic, default,
  permanent and password flags, codec, client limit and icon were always empty
  or zero because the request left out the flags that make the server send
  them. `Channel` also gains `IsSemiPermanent`, `MaxFamilyClients`,
  `TotalClients`, `TotalFamilyClients` and `NeededSubscribePower`.
  `Description` and `UID` are still not part of the list; `GetChannelInfo` has
  them.
- The event types are defined in the root package; `client`'s names are
  aliases, so code using them compiles unchanged.

## v1.0.0-beta.2 (2026-10-14)

- Three packages name what goes over the wire, as string constants: `commands`
  now holds the 155 command names (`commands.ServerGroupAddPerm`) next to its
  escaping, the new `notify` package the 66 notification names to match in
  `OnNotification` (`notify.ChannelEdited`), and the new `prop` package the
  property keys of `GetServerInfo`, `GetInstanceInfo`, `GetHostInfo` and
  `GetClientInfo` (`prop.VirtualServerName`). Ones that exist on only one of
  TeamSpeak 3 and 6, or only on the voice protocol, say so.
- The new `perm` package names every permission TeamSpeak 3.13 and 6 servers
  list, as string constants for `PermissionByName`:
  `teamspeak.PermissionByName(perm.ClientTalkPower)`. Seven exist only on
  TeamSpeak 6 and say so.
- `ListPermissions` gave every permission the id 0 over the voice protocol,
  whose `notifypermissionlist` sends no `permid`. There a permission's id is
  its place in the list, counting from 1, which the `failed_permid` of refused
  commands confirms on TeamSpeak 3 and 6; `ID` is now that. Over ServerQuery
  the id the server sends is used.
- A connection attempt could hang until its timeout when the server dropped a
  packet of the handshake, which it does under load: only the first packet
  was ever sent again. Every handshake step is now resent until the server
  answers the last one.
- A client panicked, and the connection closed, when a notification that one
  command in flight waits for arrived while a command the client has no answer
  shape for, such as `whoami`, `clientlist` or anything sent through `Exec`,
  was in flight too: `notifyservergrouplist` while `ServerGroupList` and
  `ClientList` were both pending. Such a command is now passed over.
- A tab, a no-break space or another Unicode space inside a value moved the
  boundaries between the fields of a batched row, so a nickname such as
  `a<no-break space>clid=1` could give its row a `clid` of its own. Rows are
  split on the space alone, as the command parser does, and a value keeps
  every other kind of space.
- A line of rows that each named a field of their own made the rows grow with
  the square of the line: TeamSpeak leaves out of a row the fields unchanged
  from the one before, so every row took on all the fields of all the rows
  before it, and one line of a few hundred kilobytes from a server, or from
  anyone who could forge its first packets, expanded to gigabytes. The rows of
  a line are now held to a size in proportion to the line itself; past it,
  rows carry only the fields they were sent with. The rows of a real server's
  line never come near it.
- After the 16-bit packet id wrapped, a command the server sent again because
  its acknowledgement was lost, with an id just behind the receive window, was
  taken for one far ahead of it and dropped unanswered, so the server went on
  sending it. It is now recognised as already delivered and acknowledged
  again.

## v1.0.0-beta.1 (2026-10-12)

The API settled for 1.0. Almost every signature changed; the
[migration guide](#migrating-from-v02-and-v03) walks through each one.
ServerQuery is not in this beta: its executor exists as
`internal/serverquery` and is published as `serverquery` once implemented,
before v1.0.0.

### Layout

- The module root, package `teamspeak`, holds what every TeamSpeak connection
  shares: the typed commands (`*teamspeak.Commands`), ids, errors and result
  types. The voice client is `github.com/honeybbq/teamspeak-go/client`.
  Identities are `github.com/honeybbq/teamspeak-go/identity`, server error
  codes `github.com/honeybbq/teamspeak-go/errcode`.
- Protocol internals — `crypto`, `handshake`, `transport`, `discovery` — are
  under `internal/` and no longer importable. They were never stable API.
- The typed commands run on any `teamspeak.Executor`, so the same methods will
  run over ServerQuery. A client embeds them.

### Correctness

- About 35 queries answer with a notification rather than data rows
  (`servergrouplist` with `notifyservergrouplist`, and so on); they returned
  nothing. Each command now declares where its answer arrives, measured on
  TeamSpeak 3 and 6 (`docs/voice-protocol-responses.md` in teamspeak-js).
- `ftinitupload` and `ftinitdownload` are answered after their `error`, matched
  by `clientftfid`; they returned no key. A failure the server reports in
  `notifystatusfiletransfer` is a `*ServerError`.
- Two commands in flight could take each other's rows.
- `CreateChannel` returned channel id 0; group creation and copy returned the
  first group in the list rather than the new one.
- A value that really contained `\s` was unescaped twice and came back with a
  space in it.
- A message containing `return_code=` suppressed the real one and timed out.
- `SendTextMessage` did not wait for the server's answer, so a permission
  refusal was lost.
- A command with no connection to send it on waited out its timeout, or
  panicked; it now fails with `ErrNotConnected` at once, and a lost
  connection fails every command in flight.
- The reconnect policy's "permanent refusals" named the wrong codes, so a
  wrong server password (1028) was retried until the attempts ran out.
- A kick, a ban or the server stopping left the client "connected" for a
  minute, then reported the end with a nil error. The session now ends at once
  with a `*client.RemovedError`. Channel kicks were never reported.
- An empty list (`banlist` on a server with no bans) failed with error 1281; it
  returns no rows. Every list and find does so, the permission lists,
  `ListFiles`, `GetClientIDs` and `GetServerGroupsByClient` among them, and
  `FindClients` and `FindChannels` treat 512 and 768, which TeamSpeak 3 and 6
  answer a find with no match, as no match.
- A command defined to answer with a row — the `Get…` and `Init…` methods,
  `CreateChannel`, `AddPrivilegeKey`, `ViewLog` and the group creators —
  fails with an error wrapping `teamspeak.ErrNoData`
  when the server acknowledges it without that row, or without the field it
  must hold. Several returned 0, `""` or empty `Properties`.
- `BanClient` returns every ban id the server reports: it bans the uid and
  the IP (and the MyTeamSpeak id), two or three bans. Over ServerQuery each
  has an id; over the voice protocol TeamSpeak 3 and 6 report none, measured,
  so `BanClient` returns an empty slice and `AddBan` 0 — the bans are made,
  and `ListBans` finds their ids.
- An `error` line without a `return_code` drops the rows before it; the next
  command answered took them as its own.
- `GetChannelDescription` and the channel subscriptions are typed requests,
  so command middleware sees them.
- `ftrenamefile` always sends `cpw`, with `tcid` and `tcpw` only for a move
  into another channel, and `logview` always sends `reverse` and `instance`,
  `lines` only above 0 — the rules the JavaScript SDK follows too.
- `AddTempPassword` always created an empty password; `ViewLog` returned no
  lines; TeamSpeak 6 file times were read in the wrong unit; transfer speeds
  and negative icon ids read as 0.
- Event handlers ran on a goroutine each, so events could arrive out of order
  and handlers raced. They now run one at a time, in order. The integration
  suite runs under `-race` on both server generations with no races reported.

### Go idioms

- Every operation that waits takes a `context.Context` first: `Connect`,
  `Disconnect`, every typed command, `Exec`, file transfers, identity
  generation. A command without a deadline gives up after ten seconds.
- `client.New` returns an error for an invalid configuration; options are an
  opaque `client.Option`.
- Errors are matched with `errors.Is`: `teamspeak.ErrServer`, an
  `errcode.Code`, `teamspeak.ErrNotConnected`, `client.ErrAlreadyConnected`,
  `client.ErrConnectionTimeout`, `client.ErrInvalidAddress`,
  `teamspeak.ErrNoData`, `context.DeadlineExceeded`; `errors.As` for
  `*teamspeak.ServerError` and `*client.RemovedError`.
- Ids are named types, times are `time.Time`, durations `time.Duration`,
  enums have `String` methods.
- `On…` methods return a function that removes the handler.
- Logging is silent by default and never includes a command's parameters,
  which carry password hashes and privilege keys. `identity.Identity`'s
  `String` and `LogValue` never include its private key.

### Security

- Nothing a network peer sends can crash or hang the client. Packet parsing,
  decryption, reassembly, QuickLZ, every handshake step and command handling
  are bounds-checked, and a panic below the read loop closes the connection
  with a cause instead of the process. Fuzz tests cover each entry point.
  Before the handshake completes, a step the client cannot use ends `Connect`
  with an error wrapping `client.ErrHandshake`.
- QuickLZ refused nothing: a three-byte header could panic, and a nine-byte
  one allocate 2 GiB. Declared sizes are capped at 1 MiB, as is a command
  reassembled from fragments.
- The public dummy key is accepted only before crypto init (and, once, for
  the server's Ack of `clientek`); a forged command under it was taken for
  the server's. Init1 is ignored once the handshake is complete, and its RSA
  puzzle is capped at 100000 squarings.
- `initserver` after `Disconnect`, on a replaced connection, or before crypto
  init (under the public dummy key) can no longer bring the client to
  connected.
- A command packet flagged unencrypted is dropped. Its only authentication is
  the fake signature, which every plaintext ping and voice packet shows, so an
  on-path peer could forge text messages, kicks and command answers. Measured
  on TeamSpeak 3 and 6, the servers send only Init1 unencrypted before crypto
  init, and voice, whisper, ping, pong and Ack after it; those are still
  accepted.
- With `WithPacketConn`, datagrams from any address but the server's are
  dropped instead of read as the server's.
- A server error or ban from a connection that a new `Connect` has replaced
  no longer fails or disconnects the new one.
- Before crypto init, when everything is sealed with the public dummy key,
  only `clientinitiv`, `initivexpand2` and `error` are handled; notifications,
  data rows and unknown commands are dropped. A pre-init error may fail the
  attempt, but a ban stops the client only once crypto init is complete.
- A license chain longer than 8 blocks fails the handshake. TeamSpeak 3 sends
  2 blocks and TeamSpeak 6 sends 3.
- A packet is decrypted under its own generation only. Guessing the previous
  one let a packet recorded before the 16-bit id wrapped be replayed after
  it; guessing the next never decrypted a packet on either server.
- One Init1 RSA challenge is solved per connection; the same one again gets
  the same answer, a different one none, and the clientinitiv alpha is chosen
  once.
- A datagram over 4096 bytes is dropped; the command receive queues hold at
  most 1 MiB, which bounds fragment reassembly too, and QuickLZ refuses a
  declared size its input could not expand to.
- TSDNS and nickname lookup answers are read through an 8 KiB limit.
- Logs carry a command's name and parameter count, never its parameters or a
  message body. The client keeps only the hashes of its passwords; `*Client`,
  `Request`, the transfer infos, `PrivilegeKey` and `TempPassword` format
  without secrets, through `fmt` and through log/slog's text and JSON
  handlers alike. `json.Marshal` keeps the secret in the last four: it is the
  caller's own data. `identity.Identity` cannot be marshalled.

### Lifecycle

- Sending before `Connect` or between reconnects returns
  `teamspeak.ErrNotConnected`; `SendVoice`, `SendWhisper` and `ExecNoWait`
  panicked.
- With `WithPacketConn`, a closed connection's reader stops (its read deadline
  is set), so a reconnect on the same `PacketConn` is its only reader.
- Connect's dial honours its context. The handler and crypto state are read
  under one lock and are per connection; the live reconnect test sends
  commands concurrently under `-race`.
- Voice is dropped, with a rate-limited warning, while more than 256 event
  deliveries are waiting; other events are always delivered.
- A handler or event middleware that panics is recovered and logged at Error
  with the event type; the rest are still delivered. It crashed the process.
- A `Disconnect` can no longer be undone by a reconnect already under way, a
  reconnect loop ends once the caller has reconnected by hand, and a drop that
  arrives while a loop is ending is retried rather than lost.
- `Connect` waits for a `Disconnect` that is still saying goodbye, so the old
  session is closed and announced before the new one starts; a `Disconnect`
  during that wait wins, and `Connect` returns `ErrNotConnected`. A second
  `Disconnect` joins the first.
- A session's `disconnected` is queued before `Disconnect` returns and
  before the next `Connect` can queue anything, so handlers, which run one
  at a time from one ordered queue, see it before the new session's
  `connected` and before any other event of the new session. `Connect` and
  `Disconnect` never wait for handlers, so a handler may call either.
- The goodbye waits a second at most, however long `ctx` allows.
- Resolution, the default chain or a `WithResolver` one, gets 10 seconds in
  all; a resolver that ignores its context is not waited for past it.
- The flood throttle releases waiting commands in arrival order.

### Added

- `errcode`: every server error code by name.
- `client.ErrInvalidAddress`: an address with no host, a host no host name or
  IP can be, or a port outside 1–65535 fails `Connect` at once, and is not
  retried.
- `client.OnNotification`: every notification as it arrived, for the ones the
  SDK does not model.
- `client.ServerCapabilities` reports the server's name, icon, host banner and
  welcome message from the handshake.
- `(*Commands).ClientDatabase`: an iterator over the whole client database.
- `teamspeak.Permission`, `teamspeak.Reason`, `teamspeak.GroupType` and the
  other enumerations.
- Runnable examples on pkg.go.dev.

The server info and raw notifications follow the
[EchoSixHIYA fork](https://github.com/EchoSixHIYA/teamspeak-js), by illusia.

### Differences from teamspeak-js

The two SDKs share their decisions and names; the README's compatibility
section lists where the languages force a difference. The one new here:
JavaScript's `disconnect()` resolves after its `disconnected` has been
delivered, safe there because a listener awaiting it yields to the delivery
loop; Go's `Disconnect` returns once the event is queued and guarantees
order instead, since a Go handler blocking on its own delivery would
deadlock.

## Migrating from v0.2 and v0.3

The changes from the earlier v1 previews are listed first, under
[Changes in the last preview](#changes-in-the-last-preview).

### Changes in the last preview

| Before | Now |
| --- | --- |
| `id.PrivateKey`, `id.Offset` | unexported; `id.Offset()`, `id.Export()` |
| `err = id.UpgradeToLevel(ctx, n)` | `id, err = id.UpgradeToLevel(ctx, n)` (a new identity; `n` ≤ 160) |
| `identity.UID(pk, alg)` returns `string` | returns `teamspeak.UID` |
| `c.UniqueIdentifier()` | `c.UID()` |
| `Channel.UniqueIdentifier string` | `Channel.UID teamspeak.ChannelUID` |
| `client.TextMessage`, `VoiceData`, `RawNotification`, `ClientLeftViewEvent` | `TextMessageEvent`, `VoiceDataEvent`, `NotificationEvent`, `ClientLeaveEvent` |
| `ClientMovedEvent.ID`, `ClientLeftViewEvent.ID` | `.ClientID` |
| `CommandMiddleware func(func(string) error) func(string) error` | `func(next teamspeak.Executor) teamspeak.Executor`, with `teamspeak.ExecutorFunc` |
| `ListClients(ctx)` | `ListClients(ctx, teamspeak.ClientListOptions{})` |
| `MoveClient(ctx, clid, cid, pw)` | `MoveClient(ctx, clid, cid, ClientMoveOptions{Password: pw})` |
| `KickClient(ctx, clid, reason, msg)` | `KickClient(ctx, clid, reason, ClientKickOptions{ReasonMessage: msg})` |
| `BanClient(ctx, clid, d, reason)` | `BanClient(ctx, clid, BanClientOptions{Duration: d, Reason: reason})` |
| `AddClientPermission(ctx, dbid, p, v, skip)` | `…, ClientPermissionOptions{Skip: skip})` |
| `AddServerGroupPermission(ctx, sgid, ServerGroupPermission{Permission, Value, Negated, Skip})` | `AddServerGroupPermission(ctx, sgid, perm, value, ServerGroupPermissionOptions{Negated, Skip})` |
| `DeleteChannel(ctx, cid, force)`, `DeleteServerGroup`, `DeleteChannelGroup` | `ChannelDeleteOptions{Force}`, `GroupDeleteOptions{Force}` |
| `ChannelCreateOptions`/`ChannelEditOptions` `ChannelName`, `ChannelTopic`, `ChannelCodec`, `ChannelOrder`, `ChannelMaxClients`, `ChannelDeleteDelay`, … | `Name`, `Topic`, `Codec`, `Order`, `MaxClients`, `DeleteDelay`, …, as on `Channel` |
| `ChannelFlagPassword`, `ChannelFlagPermanent`, `ChannelFlagSemiPermanent`, `ChannelFlagDefault` | `HasPassword`, `IsPermanent`, `IsSemiPermanent`, `IsDefault` |
| `ClientUpdateOptions` `InputMuted`, `OutputMuted`, `InputHardware`, `OutputHardware`, `Away`, `TalkRequestMsg` | `IsInputMuted`, `IsOutputMuted`, `HasInputHardware`, `HasOutputHardware`, `IsAway`, `TalkRequestMessage` |
| `ClientUpdateOptions.TalkRequest *int32` | `IsRequestingTalk *bool` |
| `ChannelGroupClientListOptions{ClientDBID, ChannelGroupID}` | `{DatabaseID, GroupID}`, as on `ChannelGroupMembership` |
| `KickOptions` | `ClientKickOptions` |
| `KickedEvent.Message`, `RemovedError.Message` | `.ReasonMessage`, as on `ClientLeaveEvent` |
| `TokenType`, `TokenServerGroup`, `TokenChannelGroup` | `PrivilegeKeyType`, `PrivilegeKeyServerGroup`, `PrivilegeKeyChannelGroup` |
| `MoveChannel(ctx, cid, parent, order)` | `…, ChannelMoveOptions{Order: order})` |
| `ListServerGroupClients(ctx, sgid, names, uids)` | `…, ServerGroupClientListOptions{Names, UIDs})` |
| `ListChannelGroupClients(ctx, cid, dbid, cgid)` | `ListChannelGroupClients(ctx, ChannelGroupClientListOptions{…})` |
| `ListComplaints(ctx, dbid)`, `ListBindings(ctx, sub)` | `ComplaintListOptions{TargetDatabaseID}`, `BindingListOptions{Subsystem}` |
| `ListFiles`, `GetFileInfo`, `DeleteFile`, `CreateDirectory` taking `pw` | `FileOptions{Password: pw}` |
| `InitFileUpload(ctx, cid, path, size, pw, overwrite)` | `…, size, FileUploadOptions{Password, Overwrite, Resume})` |
| `InitFileDownload(ctx, cid, path, pw, seek)` | `…, path, FileDownloadOptions{Password, SeekPosition})` |
| `StopFileTransfer(ctx, id, remove)` | `…, FileTransferStopOptions{RemovePartialFile: remove})` |
| `RenameFileOptions` | `FileRenameOptions` |
| ban, message and transfer ids as `uint64`/`uint16` | `BanID`, `MessageID`, `ClientFileTransferID`, `ServerFileTransferID` |
| `Binding.Port int`, `SortID uint64` | `uint16`, `int32` |
| `PermissionLocation{ID1, ID2}` | `ServerGroupID`, `DatabaseID`, `ChannelID`, `ChannelGroupID`, set by `Target` |
| `WhoAmI`, `GetConnectionInfo` → `map[string]string` | `teamspeak.WhoAmI`, `teamspeak.ServerConnectionInfo` |
| `ListPermissions`, `GetPermissionOverview` → maps | `[]PermissionInfo`, `[]PermissionOverviewEntry` |
| `GetServerInfo`, `GetClientInfo`, `GetHostInfo`, `GetInstanceInfo` → `map[string]string` | `teamspeak.Properties` (the same map, named) |
| `ListTokens`, `AddToken`, `DeleteToken`, `UseToken` | the `PrivilegeKey` methods |
| `ReconnectOptions{Enabled: true, …}` | `WithReconnect(ReconnectOptions{…})` alone |
| `commands.ParseCommand`, `BuildCommand`, `Command`, … | internal; `commands` keeps `Escape` and `Unescape` |
| a dot-less address looked up at named.myteamspeak.com | resolved as a host; opt in with `client.WithNicknameLookup()` |
| `ServerFamilyUnknown == "unknown"` | the zero value `""`; `String()` still says "unknown" |
| `c.Commands = …` | not assignable; the typed commands are still the client's methods |
| `banID, err := c.BanClient(…)` | `banIDs, err := c.BanClient(…)`, a `[]BanID` |
| `DialFileTransfer(ctx, host, port, key, dialer)`, and `dialer` last in `UploadFileData`, `DownloadFileData` | `…, FileTransferOptions{Dialer: dialer})`; `nil` is `FileTransferOptions{}` |
| `req.Encode(…)`, `client.ParseServerCapabilities(…)` | internal; `c.ServerCapabilities()` reports the record |
| `Complaint.Timestamp`, `OfflineMessage.Timestamp` | `.Created`, `.Sent` |
| `TempPassword.Start`, `.End` | `.Starts`, `.Ends` |
| `FileEntry.ModifiedAt`, `PrivilegeKey.CreatedAt` | `.Modified`, `.Created` |
| `PermissionLocation.ClientDBID` | `.DatabaseID` |
| `ServerGroupClient`, `BuildVersion` | `ServerGroupMember`, `ServerVersion` |
| `client.ErrTimedOut` | `client.ErrConnectionTimeout` |
| a missing row read as `0`, `""` or empty `Properties` | an error wrapping `teamspeak.ErrNoData` |

A deleted file list is now sent the way the server reads it, so
`DeleteFile` with several paths deletes them all instead of failing with
2054.

### Imports

| v0.x | v1 |
| --- | --- |
| `teamspeak.NewClient`, `teamspeak.With…` | `client.New`, `client.With…` |
| `crypto.GenerateIdentity`, `crypto.IdentityFromString` | `identity.Generate(ctx, level)`, `identity.Parse` |
| `crypto.GetUidFromPublicKey` | `identity.UID(publicKey, identity.UIDSHA1)`, a `teamspeak.UID` |
| `transport`, `handshake`, `crypto`, `discovery` | internal; no replacement |

### Connecting

```go
// v0.x
c := teamspeak.NewClient(id, "ts.example.com", "bot")
if err := c.Connect(); err != nil { … }
if err := c.WaitConnected(ctx); err != nil { … }
defer c.Disconnect()

// v1
c, err := client.New(id, "ts.example.com", "bot")
if err != nil { … }
if err := c.Connect(ctx); err != nil { … } // returns once the handshake completes
defer c.Disconnect(context.WithoutCancel(ctx))
```

`Connect` replaces `Connect` plus `WaitConnected`: it returns the handshake's
failure, such as the server's error for a wrong password, and abandons the
attempt when `ctx` is done.

### Commands

Every typed command takes `ctx` first and named ids:

```go
// v0.x
channels, err := c.ListChannels()
err = c.ClientMove(clid, 5, "")

// v1
channels, err := c.ListChannels(ctx)
err = c.MoveClient(ctx, clid, teamspeak.ChannelID(5), teamspeak.ClientMoveOptions{})
```

Raw commands:

| v0.x | v1 |
| --- | --- |
| `ExecCommandWithResponse(line, timeout)` | `Exec(ctx, line)` |
| `ExecCommand(line, timeout)` | `Exec(ctx, line)`, ignoring the rows |
| `SendCommandNoWait(line)` | `ExecNoWait(ctx, line)` |

Optional parameters are pointer fields, set with Go's `new`: `ChannelCreateOptions{Name: "Room", Topic: new("hello")}`. A
permission is `teamspeak.PermissionByName(perm.ClientTalkPower)` or
`PermissionByID(id)`, in place of the `permID`, `permSID` pair. Text messages
are `SendPrivateMessage`, `SendChannelMessage` and `SendServerMessage`. A
missing pointer field still means "not sent"; an empty string is sent empty.

### Errors

In v0.x a server error was an unexported error whose text held the code
(`TeamSpeak server error: … (id=2568)`), so telling refusals apart meant
parsing the message. In v1 it is a `*teamspeak.ServerError` with a typed code:

```go
if errors.Is(err, errcode.PermissionsClientInsufficient) { … }

var se *teamspeak.ServerError
if errors.As(err, &se) {
	log.Print(se.Code, se.Message, se.FailedPermID)
}
```

### Events

```go
// v0.x
c.OnTextMessage(func(m teamspeak.TextMessage) { … })
c.OnKicked(func(reason string) { … })

// v1
stop := c.OnTextMessage(func(m client.TextMessageEvent) { … })
defer stop()
c.OnKicked(func(e client.KickedEvent) { … }) // e.ReasonMessage, e.Reason, e.InvokerName
```

`OnClientEnter` receives a `client.ClientEnterEvent`, which embeds
`teamspeak.ClientInfo`. `ReasonID` fields are `Reason teamspeak.Reason`.
`OnDisconnected` receives nil only after `Disconnect`; otherwise the cause.

Middleware is set when the client is built, with `client.WithCommandMiddleware`
and `client.WithEventMiddleware`; `UseCommandMiddleware` and
`UseEventMiddleware` are gone, since changing a chain while commands run raced.
Event middleware receives a `client.Event`. Command middleware wraps the typed
commands rather than the wire: it receives and returns a `teamspeak.Executor`,
sees the request and the caller's context, and can answer a command itself.
Raw `Exec` lines bypass it.

### Reconnecting

`WithReconnect` turns reconnection on; `ReconnectOptions` has no `Enabled`.
`client.DefaultBackoffPolicy` is a function, and `BackoffDelay(policy,
attempt, random)` is `policy.Delay(attempt)`. A zero `Jitter` now means the
default; a negative one turns jitter off.

### File transfers

```go
// v0.x
info, err := c.FileTransferInitUpload(cid, "/a.txt", "", size, true) // password, then size
err = teamspeak.UploadFileData(host, info, r)

// v1
info, err := c.InitFileUpload(ctx, cid, "/a.txt", size, teamspeak.FileUploadOptions{Overwrite: true})
err = teamspeak.UploadFileData(ctx, host, info, r, teamspeak.FileTransferOptions{})
```

`FileTransferOptions.Dialer` is a `teamspeak.FileTransferDialer` — any
`DialContext`, such as a `*net.Dialer` or a proxy; the zero options dial
directly.
