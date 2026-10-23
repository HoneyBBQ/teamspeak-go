# Changelog

All notable changes to this module. It follows [Semantic Versioning](https://semver.org);
from v1.0.0 on, a breaking change needs a new major version and import path.

## Unreleased

### Added

- `ServerCapabilities.Extensions` lists the names in the server's
  `virtualserver_capability_extensions`, in the server's order and each once:
  `FILETIME` and `STREAM_P2P` on TeamSpeak 6, empty on TeamSpeak 3. Test one
  with `caps.HasExtension("STREAM_P2P")`. The SDK does not refuse a command
  because a name is missing. `ServerCapabilities()` and the trace hooks hand out
  a copy, so changing `Extensions` changes nothing in the client.
- `ServerView.ServerName()`, `ServerIconID()` and `ServerBannerImageURL()` read
  the server's name, icon and banner from the view, which follows the server's
  edits.
- `stream.Info.Transport` reports how a stream's media travels, from the `mode`
  the server sends with a stream's announcement and info, nil when it never
  did. `stream.TransportP2P` (1) is the only value named; another is reported
  with its number and reads as `Transport(2)`.
- `Watch` returns a `*stream.TransportUnsupportedError`, with the `StreamID` and
  the `Transport`, before sending anything, for a stream whose reported
  transport is not `TransportP2P`: its signalling is not one this package
  carries. A stream with no reported transport is tried as before. Catch it
  with `errors.As`.

### Changed

- **Breaking:** `ServerCapabilities` keeps only what lasts the connection.
  `Name`, `IconID` and `HostBannerImageURL` are gone: they were read once from
  `initserver` and went stale when the server was edited, while the view
  followed the edit. Write `c.View().ServerName()`, `c.View().ServerIconID()`
  (the unsigned CRC32 as before, 0 for none) and
  `c.View().ServerBannerImageURL()` (`""` for none) instead. The rest stay:
  what identifies the server, and `WelcomeMessage`, `HostMessage` and
  `HostMessageMode`, which are what the server greeted this connection with.

### Fixed

- A client that reconnects now asks for the nickname it was given, not the one
  the server called it. When the requested name was taken the server assigns a
  suffixed one ("bot" becomes "bot1"), and the reconnect used to ask for "bot1"
  and get "bot12" while the old session still held it, drifting further on
  every drop; an admin's rename stuck across reconnects in the same way. Every
  connection attempt now sends the requested name, which a successful
  `clientupdate` of the client's own nickname changes. The nickname the server
  reports for the client, in events, the client list and `SessionStartInfo`,
  is unchanged.
- `(*Commands).UpdateClient` sends `ClientUpdateOptions.Nickname`. It was
  accepted and left out of the command.
- A refusal over WebQuery now says which permission was missing.
  `*teamspeak.ServerError` has a `FailedPermission` field, the permission's
  name as WebQuery reports it in `status.failed_permission` (for example
  `b_serverinstance_info_view` for a guest's `hostinfo`); `""` when the server
  named none. WebQuery sends the name and no id, so it is kept as sent rather
  than mapped to a `FailedPermID`, which the voice protocol and raw or SSH
  ServerQuery still fill. `*serverquery.WebQueryHTTPError` carries it too.
- A channel created while a client is connected now holds the server's defaults
  in the view, as the next welcome lists it, instead of zeros: codec 4, quality
  5, no client limit, and the rest of what the notification does not carry.
  Before, `View().Channel(id)` reported codec 0 and a limit of 0 clients for it.
- Icon ids above 2^31 are read in every form the server sends them. The voice
  protocol announces a channel's new icon in `notifychanneledited` as the
  negative 32-bit id sign-extended to 64 bits (`18446744072424443899` for the
  icon `3009859579`), which was read as no icon, so `ChannelEditedEvent` and
  the view reported 0. It now reads as the same id as `channelinfo`'s unsigned
  form and `servergrouplist`'s signed one, wherever an icon id is parsed.
- A ServerQuery client now reads the channel of each client in the listing it
  takes on connecting. A `clientlist` row names the channel `cid`, which was
  not read, so every client in that roster was in channel 0 until a move or an
  enter notification replaced its record.

## v1.0.0-beta.14 (2026-10-23)

### Added

- `(*Commands).FindClientDatabaseByUID(ctx, pattern)` finds database ids by
  unique identifier (`clientdbfind -uid`), next to `FindClientDatabase`, which
  searches nicknames. On TeamSpeak 3 and 6, over ServerQuery and the voice
  protocol alike, the pattern is SQL `LIKE` over the whole uid, ignoring case:
  without `%` (any run of characters) or `_` (any one character) it must be the
  entire uid, so a prefix needs a trailing `%`. No match is an empty slice, and
  a server answers at most 50 ids.

## v1.0.0-beta.13 (2026-10-22)

### Added

- The `stream` package does the signalling of TeamSpeak 6 streams, the screen
  share: `stream.New(c, ...)` finds the streams of the clients in view
  (`List`, `OnStarted`, `OnStopped`), `Publish` starts one and delivers a
  `JoinRequest` for each client that asks to watch, to `Accept` with an SDP
  offer or `Deny`, and `Watch` asks to watch and returns the publisher's offer.
  SDP and ICE are strings, so any WebRTC stack plugs in; the package has no
  WebRTC dependency. `stream/e2e`, a module of its own, carries a stream
  between two peers of a WebRTC library over a live server. TeamSpeak does not
  document the protocol; it was verified against the server 6.0.0-beta13.1 and
  the client 6.0.0-beta5 (macOS), and a TeamSpeak update may break it. A
  TeamSpeak 3 server does not do streams: `Publish` and `Watch` return a
  `*stream.UnsupportedError` before sending.
- Names for the TeamSpeak 6 stream (screen share) protocol: the commands
  `commands.SetupStream`, `StopStream`, `JoinStreamRequest`,
  `RespondJoinStreamRequest`, `StreamSignaling` and `RequestStreamInfo`, their
  notifications in `notify` (`StreamStarted`, `StreamInfo`, `StreamStopped`,
  `JoinStreamRequest`, `RespondJoinStreamRequest`, `StreamSignaling`,
  `StreamClientJoined`, `StreamClientLeft`), and the error codes
  `errcode.StreamNotFound` (5635), `StreamNotParticipating` (5636),
  `StreamAlreadyJoined` (5638) and `StreamJoinRequestRedacted` (5639). The
  protocol is undocumented by TeamSpeak.

### Changed

- `setupstream` (also sent with `Exec`) now resolves with the
  `notifystreamstarted` row that echoes its `return_code`, whether that row
  arrives before or after the command's `error`. Before, the row was not part
  of the answer, and an announcement could not be told from another client's.
  A command whose announcement never arrives waits until its context ends, so
  `Exec("setupstream ...")` now blocks until the announcement arrives (or its
  context ends) instead of returning with the command's `error`.

## v1.0.0-beta.12 (2026-10-22)

### Changed

- Docs: the README, the contributing guide and the `client` package comment describe the library as an independent implementation instead of a clean-room one. The README's disclaimer says it implements the client side only.
- The serverquery package documentation lists the server behaviour the SDK
  works around, with the server version each was measured on, where the code
  is, what tests pin it and when it can go. It now says when TeamSpeak 6's
  WebQuery answers a create without its id (a Server Admin voice client is
  connected), why the lookup by name that follows is exact, and its one gap.
  The doc comments of `CreateChannel`, `CreateServerGroup`,
  `CreateChannelGroup`, `CopyServerGroup`, `CopyChannelGroup` and `ErrNoData`
  say the same.
- `StopFileTransfer` and the package documentation say that TeamSpeak 6
  crashes on `ftstop` for any transfer that is not the connection's own, not
  only one that does not exist.

### Fixed

- Voice, whisper, ping and pong now follow the generation of their own inbound
  16-bit packet ids, so audio from the server keeps decrypting after a packet
  id wraps from 65535 to 0, also when packets were lost across the wrap.
  Before, the receive side used generation 0 for them, and remote audio
  stopped for good at the first wrap while the connection stayed up.

## v1.0.0-beta.11 (2026-10-18)

### Added

- Several values in one command. `Commands.KickClients`, `MoveClients` and
  `BanClients` act on several clients with one command; `AddClientsToServerGroup`
  and `RemoveClientsFromServerGroup` change the members of a group; and the
  permission batches (`AddChannelPermissions`, `AddChannelGroupPermissions`,
  `AddChannelClientPermissions`, `AddClientPermissions`,
  `AddServerGroupPermissions`, `AddServerGroupPermissionsByType` and the
  `Delete...` twins) set or remove several permissions of one target. They send
  `-continueonerror` where the server documents it, as the option
  `ContinueOnError`. The server answers one status per command, never one per
  item, so each returns an error (`BanClients` also the ids it was told of); what
  was measured on TeamSpeak 3.13.8 and 6 beta13.1 about which items are applied
  on a failure, and which error the flag leaves, is in each doc comment.
  `BanClients` returns every ban id the server reports, none over the voice
  protocol.

### Fixed

- A command with several rows (`ftdeletefile` with several names, `clientmute`
  for several clients) went over WebQuery as one value with the rows run
  together: the transport now sends an array of objects, the form both servers
  read as the pipe-separated line.
- The `GetPermissionIDByName` documentation said an unknown name gives a false
  second result. The server refuses it with 2562, as on TeamSpeak 3 and 6 alike,
  and that error is what is returned; the doc now says so. Behaviour is
  unchanged.
- `Commands.UploadFile` and `DownloadFile` transfer a file in one call: they
  negotiate with `InitFileUpload` / `InitFileDownload` and move the bytes with
  `UploadFileData` / `DownloadFileData`, so the voice client and the ServerQuery
  client both have them. `DownloadFile` returns the bytes and refuses a file
  over `DownloadFileOptions.MaxSize` (64 MiB by default) before fetching it.
  Measured on TeamSpeak 3.13.8 and 6 beta13.1 over raw ServerQuery, SSH and the
  voice protocol; WebQuery refuses the negotiation with 5120.
- `Commands.ListFilesRecursive` lists a directory and every directory under it
  and returns each entry with its full path (`FileTreeEntry`); `MaxDepth` bounds
  the walk as `find -maxdepth` does.
- `serverquery.Custom` makes a `Dialer` from a function that opens a
  `serverquery.Transport`, the three-method line carrier (`WriteLine`,
  `ReadLine`, `Close`) the client already ran over, so a tunnel, a proxy or an
  in-memory pipe can carry a session. The client sends no login over it and
  `quit` on Disconnect; a nil open function is `ErrInvalidConfig` and one that
  fails is `ErrDial` wrapping its error. Measured on TeamSpeak 3.13.8 over a
  caller's TCP connection, and on 3.13.8 and 6 beta13.1 over a caller's own
  WebQuery transport.
- `serverquery.WebQueryHTTPError` (`Status`, and `Code`, `Message` and
  `ExtraMessage` when the body has a WebQuery status) is what the web dialer
  returns for an answer with an HTTP status outside 2xx, found with
  `errors.As`. Measured: 401 with code 5122 for a wrong key, 5120 outside the
  guest scope, 5124 for a refused guest, on both servers. It wraps the same
  `*teamspeak.ServerError` as before, so matching a code or `ErrNoGuestAccess`
  is unchanged; an answer with no WebQuery body (a proxy's 502) has only the
  status and still wraps `ErrDial`.

- A ServerQuery client no longer loses the rows of an answer that TeamSpeak 6
  writes after the `error` line over SSH, and no longer hands them to the next
  command. Measured on TeamSpeak 6 beta13.1, about one `channelcreate` in ten
  and one `servergroupadd` in eight were answered that way (a quarter of the
  creates while other sessions were creating channels, and with them one
  command in five was given a stray row as its own answer), as were `banclient`
  answers when events were registered and, rarely, a `clientlist`. The row
  follows the `error` line by well under a millisecond, on the same stream:
  nothing arrives on the SSH session's stderr. TeamSpeak 3 never did it, over
  raw TCP or SSH, and WebQuery answers whole.

  Now, for the commands that return what they made (channels, groups, bans,
  privilege keys, API keys, virtual servers) and for reads (`...list`,
  `...info`, `get...`, `whoami`, `version`), a successful answer that has no
  rows yet is held for up to 250 ms, and one with rows is held until they stop
  (25 ms), and nothing is sent in the meantime, so the rows are attributed to
  their own command. A create whose row still has not come resolves as before,
  and that row, should it arrive later, is dropped instead of becoming the next
  command's answer. Ids of a successful `BanClient` that the server did not
  send at all are still not recovered: a ban has no field that ties it to the
  call, so its documentation says the result may be empty.

## v1.0.0-beta.10 (2026-10-18)

### Added

- `ChannelCreateOptions` and `ChannelEditOptions` can write what `Channel`
  already reads: `BannerURL` and `BannerMode` (measured honoured on TeamSpeak 3
  3.13.8 and TeamSpeak 6 beta13.1 over every query transport), and
  `CodecLatencyFactor`, `IsUnencrypted`, `IsMaxClientsUnlimited`,
  `IsMaxFamilyClientsUnlimited` and `IsMaxFamilyClientsInherited`.
- `BanEntry.Enforcements`, how many times a ban turned a client away; both
  servers send it.
- `TempPassword.CreatorNickname` and `CreatorUID`, which the list always carried.
- `client.AttemptFailedInfo.WaitingFor`, what the attempt was waiting for when
  it ended, in the words of a cancelled `Connect`'s error.
- `serverquery.Client.ServerVersion` returns the version string the server answered
  the `version` command with, `""` before connecting.
- Enter, leave and move events name the channels the server names. `ClientMovedEvent`
  has `FromChannelID` (`cfid`: TeamSpeak 6 sends it, TeamSpeak 3.13.8 does not
  on a move, so it is 0 there); `ClientLeaveEvent` has `FromChannelID` and
  `TargetChannelID` (`ctid`, 0 for a disconnect); `ClientEnterEvent` has
  `FromChannelID` and `Reason` of its own, apart from the client's record
  (`ReasonNone` on connecting, `ReasonSubscription` when it comes into view
  because this client moved into its channel).
- `ClientChatClosedEvent` and `OnClientChatClosed`, for `notifyclientchatclosed`,
  which the server sends after the other client has written to this one.
- `Commands.GetClientUIDInfoByID` returns the nickname and MyTeamSpeak id
  `clientgetuidfromclid` sends with the uid; `ClientDatabaseName.UID` is the uid
  `clientgetnamefromdbid` sends.
- `ClientDatabaseEntry` has `AvatarHash` and the four byte counts
  (`TotalBytesUploaded`, `TotalBytesDownloaded`, `MonthBytesUploaded`,
  `MonthBytesDownloaded`) from `clientdbinfo`, and `LoginName` from
  `clientdblist`.
- `Channel.EmptyFor` (`seconds_empty`; nil for a channel that holds a client,
  where both servers send -1), `Channel.StorageQuota` (TeamSpeak 6) and
  `Channel.FilePath`.
- `WhoAmI.ServerUUID` and `OriginServerID`; `VirtualServer.UUID`,
  `GuestCanCreateChannels`, `GuestCanCreateHomebase` and `WeblistEnabled`
  (TeamSpeak 6).
- `TempPassword.TargetChannelPassword`, kept out of `String`, `GoString` and
  `LogValue` like the password.
- `ClientEntry.TalkRequestedAt`, the time `client_talk_request` carries.
- `notify.BanUpdate` names `notifybanupdate`, and `serverquery.CategoryTokenUsed`
  registers the `tokenused` category, which is never registered by default. Both
  stay `NotificationEvent`s.

### Changed

- `client.Connect` names what the attempt was waiting for when the caller's
  context ends it, such as `context deadline exceeded while waiting for the
  server's answer to clientek`, where a TeamSpeak 6 server sometimes never
  answers the key exchange. `errors.Is` still finds `context.DeadlineExceeded` or
  `context.Canceled`; a comparison with `==` no longer does. The same error
  reaches the `disconnected` event and the trace's `AttemptFailed`.

### Fixed

- The `CreateDirectory` documentation no longer says it creates missing
  parents: both servers refuse a path under a missing parent with 2052.
- The `BanClient` documentation says what the servers do: two bans (uid and
  address), and an answer that TeamSpeak 6 has left without any `banid` though
  both bans were made; list the bans before and after to find them.
- The live suite waits a moment after each SSH query session, because a
  TeamSpeak 3 server still closing one drops the next connection before reading
  anything, which a WebQuery request made straight after would see as `EOF`.

## v1.0.0-beta.9 (2026-10-18)

### Removed

Breaking, and made before v1.0.0: how to connect and authenticate belongs to the
dialer, and what to do on the session stays an option of the client. SSH and
Web already took their credentials in their dialer; the raw TCP login was the
exception, and was refused at run time for the other two.

- `serverquery.WithLogin` is gone. Give the login to the TCP dialer with the new
  `TCPLogin(addr, name, password)`, or `TCPLoginWith(addr, name, password,
  options)` for a `TCPOptions`. `TCP` and `TCPWith` stay for a connection with
  no login, and an empty name is still refused by `New` with `ErrInvalidConfig`.
  A login over SSH or Web, which `New` used to refuse at run time, can no
  longer be written. `Client.Login` is unchanged, and the login is still sent
  again on every reconnect.

  ```go
  // before
  c, err := serverquery.New(serverquery.TCP(addr),
  	serverquery.WithLogin("serveradmin", password),
  	serverquery.WithServer(1))

  // after
  c, err := serverquery.New(serverquery.TCPLogin(addr, "serveradmin", password),
  	serverquery.WithServer(1))
  ```

### Added

- `ServerView` also holds the groups and the server's settings. `ServerGroups`
  and `ChannelGroups` are the group lists the server last sent, in ascending id,
  with `ServerGroup(id)` and `ChannelGroup(id)` to look one up; the server sends
  the whole list after every change to a group, so the view replaces its set
  with each and a group missing from a list is gone. `GroupsLoaded` is false
  until both lists of the connection have arrived, which is just after
  `ViewReadyEvent`, so empty lists mean none only once it is true. A group's
  permissions and members are not in it. `Server` holds the `virtualserver_`
  settings by their wire names, as `GetServerInfo` returns them: it starts from
  what the server says on connecting and follows `ServerEditedEvent`, but the
  server announces an edit of the welcome message, the client limit and some
  other settings without naming them, so those are as of the last
  `GetServerVariables`. The view merges every answer to that, whoever asked,
  and holds none of the counters and statistics in it, such as the clients
  online and the uptime. Experimental.
- `(*client.Client).GetServerVariables` returns what `servergetvariables`
  answers, the settings that change while the server runs, counters included.
  Experimental.
- `OnViewChanged` reports that the view is newer than the last time a handler
  was told, with its `Revision`. It follows the typed events of the
  notifications that changed the view and says nothing of what changed. A burst
  of notifications that arrives while a handler is busy gives one event after
  the last of them, but a flood cannot hold it back for more than 64 packets.
  It is not sent while the view is loading or when nothing changed since the
  last `ViewReadyEvent` or `ViewChangedEvent`, and is sent once more when the
  view goes stale. Experimental.
- `ChannelDeletedEvent.Previous` and `ClientLeaveEvent.Previous` hold the
  channel as the voice client's view held it, and the client as it knew it,
  just before they were removed, a copy for each handler. A channel deleted with
  subchannels gives one event for each, the subchannels first. They are nil
  when the client did not hold the record, and always nil on the ServerQuery
  client. Experimental.
- `errcode.APIKeyOutOfScope` (5120), `APIKeyInvalid` (5122) and `APIKeyMissing`
  (5124) name the codes WebQuery refuses access with.
- `serverquery.ErrNoGuestAccess`: `Connect` with `SSHGuest` or `WebGuest` to a
  server that offers no guest access, such as any TeamSpeak 3 server, now says
  so. The error wraps the server's own refusal, so `ErrAuth` and the code still
  match. The `WithServer` documentation no longer says that leaving the server
  out addresses the instance over TeamSpeak 3's WebQuery, which runs every
  command on a virtual server.

### Fixed

- A client can connect to a server that is under a burst of connections. Such a
  server raises its protection level and asks for a bigger Init1 puzzle: 100000
  squarings at level 1 and 1000000 at level 2, where it asks for 10000 when
  calm; the client refused anything above 100000. The cap is now 4000000, four
  times the highest level measured. The puzzle is solved off the receive loop,
  so the connection keeps receiving, and cancelling the `Connect` context stops
  the solve. A level above the cap fails `Connect` with an error wrapping
  `ErrPuzzleTooHard` and `ErrHandshake`.
- The SSH transport could not connect to a TeamSpeak 3 server: the ssh library
  asks for `rsa-sha2-256` and the server signs with `rsa-sha2-512` whichever
  it was asked for, so the handshake failed with "invalid signature algorithm".
  The transport now prefers `rsa-sha2-512` among the host key algorithms.
  TeamSpeak 3 has served SSH ServerQuery since 3.3, and WebQuery since 3.12;
  the documentation said TeamSpeak 6 only.

## v1.0.0-beta.8 (2026-10-17)

### Removed

Breaking, and made before v1.0.0: two options the server never honoured.

- `ClientDatabaseEditOptions.Nickname` is gone. `EditClientDatabase` sent
  `client_nickname`, which `clientdbedit` does not take: TeamSpeak 3 and
  TeamSpeak 6 both answered error 1542 (missing required parameter). The
  command edits `Description` only, and there is no way to change a stored
  nickname through it.
- `ServerGroupClientListOptions.UIDs` is gone. It sent `-uid`, which
  `servergroupclientlist` ignores, so the rows stayed `cldbid` only. Set
  `Names` instead: the server then returns each member's nickname and unique
  identifier together, so `ServerGroupMember.UID` is filled by `Names`.

### Added

- Avatar and icon helpers. `Client.UploadAvatar` hashes an image, uploads it and
  sets the client's avatar flag; `Client.DownloadAvatar` reads any client's
  avatar from `AvatarFileName(uid)`, the name the server stores it under
  (`avatar_` and the unique identifier in the letters a to p, which is not the
  MD5 name); `Commands.RemoveAvatar` deletes your own. `Client.UploadIcon` sends
  an icon under its CRC-32 id (`IconIDOf`), `DownloadIcon` and
  `Commands.RemoveIcon` read and delete one, and `SetChannelIcon`,
  `SetServerGroupIcon`, `SetChannelGroupIcon`, `SetClientIcon` and
  `SetServerIcon` point a record at it. `Client.Host` is the host the file
  transfer port is on.
- `(*client.Client).MuteClients` and `UnmuteClients` stop and resume hearing
  other clients on a voice connection: the server no longer forwards the muted
  clients' voice to the caller, while everyone else still hears them. Both
  take a list of client ids.
- `ClientEntry` and `Channel` carry more of what the server reports. A client
  gains `DatabaseID`, `AwayMessage`, `IsInputMuted`, `IsOutputMuted`,
  `TalkPower`, `Description`, `Avatar`, `Country`, `Version`, `Platform` and
  others; a channel gains `IsMaxClientsUnlimited`, `DeleteDelay`,
  `NamePhonetic` and others. A flag, count or duration is a pointer, and nil
  means the answer did not carry it, which is not the same as false or 0: no
  `ListClients` flag brings some of them, and `ListChannels` brings none of the
  new channel fields, so `GetChannelInfo` is where to read them. Each field's
  comment says which flag brings it. The existing fields are unchanged. Because
the optional ones are pointers, a plain assignment of a record shares them;
`ClientEntry.Clone` and `Channel.Clone` return a copy that shares no memory.
- `ClientChanges` and `ChannelChanges` hold the properties a notification
  carried, under the names of `ClientEntry` and `Channel`. Every field is a
  pointer and nil means unchanged, so a pointer to `""`, `false` or an empty
  list is a change; `ServerGroups` is the complete new list. Their `Apply`
  methods return a copy of a record with the changes made, sharing no memory
  with either.
- `OnClientUpdated` reports a client changing its nickname, away or mute state,
  server groups, talk power or description, itself included, with the
  `ClientChanges` the notification carried. `OnClientServerGroupAdded` and
  `OnClientServerGroupRemoved` name the group and who changed it, and
  `OnClientChannelGroupChanged` a client's channel group changing in a channel,
  which every move of a client does too. These are on the voice client only: a
  TeamSpeak 3 ServerQuery connection is not sent the notifications.
- The voice client keeps what it knows of other clients current: a client's
  server groups follow `ClientUpdatedEvent`, and its channel group follows
  `ClientChannelGroupChangedEvent` when the channel is the one it is in. The
  groups a `TextMessageEvent` carries as `InvokerGroups` were stale after any
  group change, and are now the current ones; the client's own nickname follows
  the server's rename.
- Typed methods for the documented commands that could only be reached through
  `Exec`, on `*teamspeak.Commands` and so on both clients. API keys:
  `AddAPIKey`, `ListAPIKeys` and `DeleteAPIKey`. Query logins: `AddQueryLogin`,
  `ListQueryLogins`, `DeleteQueryLogin` and `SetQueryLogin` (ServerQuery only;
  the voice protocol answers 2). Client custom properties: `SetCustomProperty`,
  `DeleteCustomProperty`, `ListCustomProperties` and `FindCustomProperty`.
  `SendOfflineMessage` completes the offline message set, and
  `GetOwnPermission` reads a permission's value (an `OwnPermission`) for the
  connection's own client. A secret the server shows once — the key of
  `AddAPIKey`, the password of `AddQueryLogin` and `SetQueryLogin`, the token
  of `CreateServer`, a snapshot's data — is a plain field of the result
  (`APIKeyCreated.Key`, `QueryLoginCreated.Password`, `ServerCreated.Token`,
  `ServerSnapshot.Data`), and the result's `String`, `GoString` and `LogValue`
  leave it out, as `PrivilegeKey` does with its token.
- Instance administration, which needs a ServerQuery connection with the
  instance permissions (a voice Server Admin is refused with 2568):
  `ListServers`, `CreateServer`, `StartServer`, `StopServer`, `DeleteServer`
  (with `-noevent`), `StopInstance` and `SendGlobalMessage`;
  `AddServerGroupPermissionByType` and `DeleteServerGroupPermissionByType` set
  or remove a permission on every regular group of one `GroupAutoUpdateType`
  across all virtual servers; `CreateServerSnapshot` and `DeployServerSnapshot`
  (with a password, `-keepfiles`, and `-mapping`, which returns the
  `ChannelMapping` of each channel). A server without a license runs one
  virtual server, so `CreateServer` needs the first stopped. A deploy drops the
  deploying connection's server selection over raw TCP and SSH.
- Bans: `BanOptions` takes `MyTSID` and `LastNickname`, and `BanEntry` reads
  `MyTSID`; both servers send the field. `BanListOptions` pages with `Start`
  and `Limit` (the server caps a page at 200). `FindBans` sends `banfind`,
  which only TeamSpeak 6 has: over SSH and the voice protocol, not WebQuery,
  which refuses it, and not TeamSpeak 3.
- `PrivilegeKeyOptions.CustomSet` sends `tokencustomset`, and
  `PrivilegeKey.CustomSet` reads `token_customset`. Each ident and value is
  escaped inside the set as well as in the parameter: sent with only the
  parameter's escape, a value with a space reaches the client that redeems the
  key cut at the space.
- `FindClientsWith` takes `ClientFindOptions{ChannelID, ChannelUID}`, which
  send `-cid` and `-chuid` so that TeamSpeak 6 reports each client's channel in
  `ClientMatch.ChannelID` and `ChannelUID`. The flags report; they filter
  nothing, and TeamSpeak 3 accepts them and leaves the channel out.
  `FindClients` is unchanged.
- `FileUploadInfo.IP` and `FileDownloadInfo.IP` carry the `ip` the server adds
  when the file transfer is not reachable at the address of the connection.
- `serverquery.Client` gains the session commands: `Login`, `Logout`, `Use`
  (with `ByID` and `ByPort`), `RegisterNotifications` and
  `UnregisterNotifications`. After a `Use` the client reads its own id again,
  and `Logout` clears it, since the id belongs to the server selected. A `Use`
  the server refuses leaves the connection on no server, which was measured on
  both generations; the client forgets its id with it. A reconnect starts over
  from the options given to `New`, as it always did, and does not repeat what
  was done by hand.
- The voice client's response table maps the answers it was missing, so a raw
  `Exec` returns their rows: `tokenadd`, `tokenlist`, `apikeyadd`,
  `apikeylist`, TeamSpeak 6's `permget`, `getconnectioninfo`,
  `clientgetvariables`, `servergetvariables`, `clientsetserverquerylogin` and
  `banfind`. The rows of `clientgetvariables` and `getconnectioninfo` are the
  ones for the client asked about, not the same notification sent for another.
- `ClientListOptions.Icon` sends `-icon`, which fills `ClientEntry.IconID` in a
  list; no other list brings it.
- `OnChannelCreated`, `OnChannelEdited`, `OnChannelMoved`, `OnChannelDeleted`,
  `OnChannelDescriptionChanged`, `OnChannelPasswordChanged` and `OnServerEdited`
  report changes to channels and to the server, on the voice client and on the
  ServerQuery client, which receives them through the `channel` and `server`
  categories it registers by default. `ChannelCreatedEvent` and
  `ChannelEditedEvent` carry `Changes`, a `ChannelChanges` holding only the
  properties the server sent; for a new channel, a nil field has the server's
  default. `ServerEditedEvent.Changes` holds the changed `virtualserver_`
  properties by their wire names, and none for a welcome message change.
- The voice client also reports its own subscriptions
  (`OnChannelSubscribed`, `OnChannelUnsubscribed`), plugin commands
  (`OnPluginCommand`, which the sender receives too when it sent to its channel
  or the server) and a client typing a private message to it
  (`OnClientChatComposing`). Neither TeamSpeak 3 over raw ServerQuery nor
  TeamSpeak 6 over SSH sends a query connection these, nor `OnClientUpdated`,
  the group events or `OnClientChannelGroupChanged`, so the ServerQuery client
  has no such methods; the `serverquery` documentation lists what each category
  delivers.
- `Commands.SendPluginCommand` sends a plugin command to the sender's channel
  (`PluginToChannel`, the zero value), to every client (`PluginToServer`) or to
  one (`PluginToClient`). `Commands.SendChatComposing` sends the typing
  indicator, and `Commands.ClosePrivateChat` tells a client the private chat is
  closed, which the server delivers only to a client that was sent a private
  message first. A ServerQuery connection cannot send any of them.
- `SendWhisper` can name channels as well as clients (`WhisperTargets.Channels`,
  at most 255; clients stay at most 32), and `SendGroupWhisper` whispers to a
  server group, a channel group, the channel commanders or everyone, within the
  channels a scope picks. Build the target with `WhisperToServerGroup`,
  `WhisperToChannelGroup`, `WhisperToChannelCommanders` or `WhisperToAllClients`:
  the group id is the kind its type takes, and a target not built by one of them
  is refused with `ErrInvalidWhisperTarget`. `GroupWhisperType` and
  `GroupWhisperScope` name the packet's two enums. Whether a client hears it
  is the server's decision, from the whisper powers.
- `WithPrivilegeKey` sends a privilege key as `client_default_token` in
  `clientinit`; the server adds the key's group when it accepts the join and the
  key is spent, so it is sent on the first successful connection only and a
  reconnection does not present it again. `WithMetaData` sends `client_meta_data`
  the same way, on every connection, and `ClientUpdateOptions.MetaData` changes
  it while connected.
- `DisconnectWithMessage` leaves with a message that bystanders receive as
  `ClientLeaveEvent.ReasonMessage`; `Disconnect` sends `Shutdown`. The goodbye
  now carries `reasonid=8`, without which both servers drop the message.
- The client answers `notifyconnectioninforequest` with `setconnectioninfo`
  from what it has measured: the keepalive round trip (mean and standard
  deviation of the last 10 pongs, left out until the first), packets and bytes
  sent and received per class, counted as whole datagrams with their headers
  and resends, and the bandwidth of the last second and the last minute.
  `GetClientConnectionInfo` reads another client's figures as a
  `ClientConnectionInfo`, with durations for ping, deviation, connected and idle
  time; a client that has not reported yet shows zeros.
- `VerifyServerPassword` and `VerifyChannelPassword` check a password on the
  voice client without joining or moving: true for a match, false for error 1028
  or 781, an error for anything else.
- `CreateChannel` looks the channel up by its exact name and parent when the
  answer carries no `cid`, and `CreateServerGroup`, `CreateChannelGroup` and the
  copies that allocate a group look it up by name and type when the answer names
  none. TeamSpeak 6's WebQuery has been seen answering a create that succeeded
  with status ok and no body, and a server refuses a duplicate, so the match is
  the object just made. `ErrNoData` from a create now means the command took
  effect: `AddPrivilegeKey` and `AddAPIKey` cannot look their object up, and
  say so, and for an API key the secret is lost, so find it with `ListAPIKeys`
  and remove it with `DeleteAPIKey`.


- `serverquery.SSHGuest`, `SSHGuestWith`, `WebGuest` and `WebGuestWith` connect
  as the guest TeamSpeak 6 beta13 serves without an account: the SSH user
  `guest` with no password, and WebQuery with no api key. The access is the
  Guest ServerQuery group's, so a refused command comes back as the server's
  own error (2568 over SSH; 5120, out of scope, over WebQuery for a command the
  guest scope leaves out). The SSH host key policy applies as it does for an
  account. The server switches guest access off with `--query-ssh-allow-guest=0`
  and `--query-http-allow-guest=0`.
- `perm` names the 255 `i_needed_modify_power_*` permissions, one per
  permission, as `NeededModifyPower` followed by the permission's name, seven of
  them TeamSpeak 6 only.
- `serverquery`'s package documentation records the commands TeamSpeak 6
  beta13.1 lists or documents and answers with `command not found`:
  `authenticationtoken`, `chatlogintoken` and the `homebase*` commands, and that
  `clientdblist -homebaseonly` is accepted without being applied.
- `ChannelTree`, in the root package, keeps the channels of a server in the
  order the server shows them. `NewChannelTree` builds one from channel records
  in any order, such as `ListChannels` returns, and `ApplyCreated`,
  `ApplyEdited`, `ApplyMoved` and `ApplyDeleted` follow the four channel events,
  so a ServerQuery connection, which receives them, can keep a tree. It never
  changes: each of those returns a new tree, and the records it returns are
  copies. `Get`, `Children`, `Path` and `Len` read it. A channel's `Order` in a
  tree is worked out from its place and is not the value an event carried,
  because the server rewrites the `channel_order` of the sibling after a channel
  that was created, moved or deleted, and tells no one. An event the tree cannot
  place puts the channel at the end of its parent and makes `Consistent` report
  false. Experimental.
- `(*client.Client).View` returns a `ServerView` of what the voice client knows
  of the server: the channel tree in the server's order (`Channels`, `Channel`,
  `Children`, `Path`) and the clients it has been told about and where they are
  (`Clients`, `Client`, `ClientsIn`), with `Self`, `Revision` and a `Status`
  (`ViewEmpty`, `ViewLoading`, `ViewLive`, `ViewStale`). It is a copy, kept
  current by the notifications, and shares its clients with the record
  `TextMessageEvent.InvokerGroups` reads. `WaitView` returns once it is live,
  which is when the server has finished the channel list, and `OnViewReady`
  reports that, on every reconnection too. A reconnection clears the view; a
  connection that ends leaves the last view, stale. The channels' `TotalClients`
  and `TotalFamilyClients` are nil in it, since the server sends them once and
  nothing updates them. Clients in channels the client is not subscribed to are
  not in it. Experimental.

### Changed

- `serverquery.Web` and `serverquery.SSH` refuse an empty api key, an empty
  password, an empty user and the user `guest` with `ErrInvalidConfig`: the
  server answers each of them as a guest, which would turn a missing credential
  into a quiet downgrade. Use the guest constructors to connect as one.
- `ListChannels` also sends `-secondsempty -banners`. The banner fills
  `Channel.BannerURL` and `BannerMode`; `Channel` has no field for the
  `seconds_empty` the first adds.

### Fixed

- `GetClientConnectionInfo` failed with `ErrNoData` now and then on TeamSpeak 6
  when several commands were in flight, because the server sent the end of the
  answer before the figures. It now takes the `notifyconnectioninfo` row that
  names the client asked about, whichever side of the command's `error` it
  falls on, and waits for it until the context gives up.
- `GetChannelDescription` returned an empty description, or failed, when
  another channel edit arrived while it waited, because it read the first row
  of the answer. It now takes the row for the requested channel that carries
  the description, and fails with `ErrNoData` if there is none. Its answer, a
  channel edit with reason `ReasonChannelUpdate` and no invoker, is not a
  change and produces no `ChannelEditedEvent`; it still reaches
  `OnNotification`.
- Over SSH, a TeamSpeak 6 server can hold the end of a reply until the client
  writes again; the SSH transport now writes an empty line when a command has
  waited 2 seconds, and once a second after, which releases it.
- After the server unsubscribed the voice client from a channel, the client
  kept what it knew of the channel's clients, though the server sends no leave
  for them and nothing about them afterwards, so their `InvokerGroups` and
  channels went stale. They are now forgotten when `ChannelUnsubscribedEvent`
  arrives, except the client itself, and subscribing again announces them anew.
  The documentation of `ClientEnterEvent` and `ChannelUnsubscribedEvent` says
  what the client is and is not told.

## v1.0.0-beta.7 (2026-10-17)

### Security

- The SSH transport verifies the server's host key, and refuses to dial with
  no policy rather than accepting whatever answers the port. `SSHWith` takes
  `SSHOptions.HostKeyCheck`, with `KnownHosts(path)` checking against an
  OpenSSH known_hosts file and `InsecureIgnoreHostKey()` accepting anything.
  `SSH(addr, user, password)` on its own now produces a dialer `New` refuses,
  naming the three ways to supply a policy: the query account it logs in as is
  normally `serveradmin`, and an unchecked key hands that password to anyone
  who can answer the port. `HostKeyCheck` together with `SSHOptions.Open` is
  refused as well: the connection `Open` returns has already made its
  handshake, so the check would never run. A host key that was refused is not
  retried by `DefaultShouldRetry`, whether it is unknown or has changed.

### Added

- `serverquery`, a client for TeamSpeak's administrative interface, running the
  same typed commands as the voice client. It is **experimental**: unlike the
  rest of the module it may change in a minor release. Three transports, chosen
  by the `Dialer` passed to `New`: `TCP(addr)` (raw ServerQuery, TeamSpeak 3
  only), `SSH(addr, user, password)` (TeamSpeak 6 only, off by default) and
  `Web(baseURL, apiKey)` (TeamSpeak 6's WebQuery). The server's notifications
  arrive as events over TCP and SSH; WebQuery has no session for the server to
  push to, so it delivers none and refuses file transfers. `TCPWith`, `SSHWith`
  and `WebWith` supply a dialer, an SSH connection or an `*http.Client`, and
  `Stats` reports the connection's identity and byte counters.
- The shared pieces the two clients now use are in the root package:
  `Status`, `ServerFamily` (with `ServerFamilyForVersion`), `ConnectedEvent`,
  `DisconnectedEvent`, `BackoffPolicy`, `ReconnectOptions`, `ShouldRetryFunc`,
  `DefaultBackoffPolicy`, `CommandMiddleware`, `ErrAlreadyConnected` and
  `ErrMissingDependency`. `client` re-exports each of them under the name it
  already had, so nothing that imported `client` has to change.

### Changed

- `AddBan` returns `(teamspeak.BanID, bool, error)`. The bool is false when the
  server reported no id — the voice protocol answers `banadd` with nothing,
  measured — so a zero `BanID` no longer has to stand for both "ban 0" and "no
  id". It matches `GetPermissionIDByName`, which already answers that way.
  `BanClient` is unchanged: an empty slice says the server reported none.
  `banIDs` now takes a row that carries `banid` rather than one whose value is
  non-zero, so a ban the server really numbered 0 is no longer dropped.

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
| `ListServerGroupClients(ctx, sgid, names, uids)` | `…, ServerGroupClientListOptions{Names})`; the uid comes with `Names` |
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
