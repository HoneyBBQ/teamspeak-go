// Package serverquery runs the typed commands over ServerQuery, TeamSpeak's
// line-based administration protocol, and delivers the server's notifications
// as events.
//
// Create a client with [New] and a Dialer from [TCP], [SSH] or [Web], then
// [Client.Connect]:
//
//	c, err := serverquery.New(
//		serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", password),
//		serverquery.WithServer(1))
//	err = c.Connect(ctx)
//	defer c.Disconnect(context.WithoutCancel(ctx))
//	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
//
// The typed commands come from the embedded [teamspeak.Commands], exactly as
// the voice client's do. What is here is the session: connecting, the query
// login, the three transports, and the events.
//
// # Transports
//
// ServerQuery runs over three transports, and they do not offer the same
// things:
//
//   - [TCP] is the raw protocol, on port 10011, which only TeamSpeak 3 serves.
//     It needs `login` ([TCPLogin]) unless the address is already allowlisted, and it
//     delivers notifications.
//   - [SSH] carries the same session on port 10022. TeamSpeak 3 (3.3 and later)
//     and TeamSpeak 6 both serve it, off by default: a TS3 server needs
//     `query_protocols` to list `ssh`. The SSH login replaces `login`, so no
//     query password goes over the wire, and it delivers notifications.
//   - [Web] is WebQuery, the HTTP interface of TeamSpeak 3 (3.12 and later,
//     off until `query_protocols` lists `http`) and TeamSpeak 6, on port 10080,
//     where an api key replaces the login. It has no session for the server to
//     push to, so it delivers no events and refuses file transfers.
//
// # Guest access
//
// TeamSpeak 6 beta13 and later let a connection in without an account, with the
// access of the Guest ServerQuery group: [SSHGuest] over SSH (the user "guest",
// no password) and [WebGuest] over WebQuery (no api key). The server switches
// them off with --query-ssh-allow-guest=0 and --query-http-allow-guest=0. A
// server without guest access, which TeamSpeak 3 is, refuses a guest connection
// and Connect says so: the error wraps [ErrNoGuestAccess] and the server's own
// refusal ([ErrAuth] over SSH, code 5124 over WebQuery).
//
// A guest is only ever a deliberate choice. [SSH] and [Web] refuse an empty
// password, an empty api key and the user name "guest" with [ErrInvalidConfig],
// because the server answers each of those as a guest and would otherwise turn a
// missing credential into a quiet downgrade; a wrong api key is refused by the
// server itself (5122). The host key policy of [SSHGuestWith] is as strict as
// for any SSH connection.
//
// What a guest may run is the server's to say. Over SSH, after `use`, whoami and
// version answer and an administrative command is refused with 2568 (insufficient
// client permissions). Over WebQuery the guest scope allows fewer commands: those
// outside it answer HTTP 401, code 5120 (errcode.APIKeyOutOfScope, "command not allowed for guest access"),
// and the rest are checked against the group's permissions as usual.
//
// # Commands the server lists and does not serve
//
// Measured against TeamSpeak 6 beta13.1 over SSH as serveradmin, these answer
// `error id=256 msg=command not found`, with and without their documented
// parameters: authenticationtoken (also with duration=60) and chatlogintoken,
// both of which `help` lists, and homebaseset (cldbid=1), homebaseisset,
// homebasedel and homebaselist. They have no typed command here for that
// reason. `clientdblist -homebaseonly` is accepted without error, but the
// filter is not applied: the full list comes back, with no homebase field.
//
// # Server behaviour the SDK works around
//
// The SDK does not fix the server, and it never makes up data on the server's
// behalf: when it cannot know something it returns an error that says so. A
// lookup by a unique key is not made-up data: it reads back what the server
// did. A workaround for server behaviour stays only while it is harmless on a
// correct server, small and in one place, documented with the server version
// where the behaviour was measured, and pinned by a test. Each entry names the
// server and version, what the SDK does, where the code is, the test that pins
// it, and when it can go: when a server release no longer shows the behaviour,
// re-measured.
//
//   - Held reply over SSH. TeamSpeak 6 6.0.0-beta13.1 can hold back the last
//     line of a reply, usually "error id=0 msg=ok", until the client writes
//     again. The SSH transport writes an empty line once a command has waited
//     2 s, and every second after. Code: Nudger in internal/serverquery/client.go
//     and nudgingStream in ssh.go. Test: TestClient_NudgesAnUnansweredCommandUntilItsErrorLine
//     in internal/serverquery. Removable when a TeamSpeak 6 release no longer
//     holds a reply over SSH.
//   - Create rows after the error line over SSH. TeamSpeak 6 6.0.0-beta13.1 can
//     write the rows that answer a create (channelcreate, the group creates and
//     copies, banadd, banclient, privilegekeyadd, tokenadd, apikeyadd,
//     servercreate), and now and then a read, after the command's error line.
//     The answer is held briefly, and the next command is not sent until it is
//     complete, so a row is never handed to the wrong command. Code:
//     internal/serverquery/late_rows.go. Tests:
//     TestClient_GivesACreateTheRowThatFollowedItsErrorLine and
//     TestClient_DoesNotHandALateRowThatMissedItsGraceToTheNextCommand in
//     internal/serverquery, and TestQueryLateRows_CreateKeepsItsRowAndTheNextCommandNeverGetsIt
//     live. Removable when a TeamSpeak 6 release writes every row before the
//     error line over SSH.
//   - SSH host key algorithm. TeamSpeak 3 3.13.8 signs its SSH host key with
//     rsa-sha2-512 only, so the SSH transport prefers that algorithm to
//     rsa-sha2-256. Code: internal/sshalgo/sshalgo.go. Test:
//     TestHostKeyAlgorithms_PrefersRSASHA512OverRSASHA256, and every live SSH
//     test against TeamSpeak 3. Removable when a TeamSpeak 3 release signs with
//     what was negotiated.
//   - Connection right after an SSH session closes. TeamSpeak 3 3.13.8 resets a
//     connection made within a few milliseconds of an SSH session closing (4 to
//     14 in 100 within 3 ms). The SDK does nothing, because a retry cannot know
//     the command did not run; only the test suites wait, 50 ms. Code:
//     sshTeardown in serverquery/integration_test.go. Test: the live suites
//     themselves, which fail without the wait. Removable when a TeamSpeak 3
//     release no longer shows it.
//   - ftstop for a transfer that is not the connection's own. TeamSpeak 6
//     6.0.0-beta13.1 crashes on a ServerQuery ftstop for a transfer that does
//     not exist or belongs to another client.
//     The SDK does nothing and [teamspeak.Commands.StopFileTransfer] says so.
//     Code: none. Test: none, since the test would crash the server;
//     TestQueryFiles_ActiveTransferStopped stops only its own. Removable when a
//     TeamSpeak 6 release no longer crashes.
//   - Create answered with no body over WebQuery. Measured on TeamSpeak 6
//     6.0.0-beta13.1 over WebQuery, when a Server Admin voice client is
//     connected: channelcreate, channelgroupadd, channelgroupcopy,
//     servergroupadd and servergroupcopy are answered with HTTP 200, status ok
//     and no body, in 2 to 75% of the creates of a run, because the server
//     writes the id after its status and the HTTP answer has none. On a quiet
//     server, or with only a plain voice client, the id came back every time;
//     TeamSpeak 3 is unaffected. The SDK looks the object up by its unique key:
//     group name and type, or channel name under its parent. That is exact,
//     since the server refuses a duplicate (1282 for a group, 771 for a
//     channel); the one gap is another client renaming or deleting the object
//     between the create and the lookup. It runs only when the id is missing,
//     so it never runs on a correct server. Code: createdServerGroup in
//     api_server.go, createdChannelGroup in api_groups.go, and CreateChannel in
//     api_channels.go. Tests: TestCreatedGroups_WithoutRowsFindTheGroupByNameAndType,
//     TestCreatedGroups_WithoutRowsAndNoMatchIsNoData,
//     TestCreateChannel_WithoutACidFindsTheChannelByNameAndParent and
//     TestCreateChannel_WithoutACidAndNoMatchIsNoData, and live
//     TestIntegration_CreateRecoversFromAnAnswerWithoutRows.
//     Removable when a TeamSpeak 6 release, re-measured under these
//     conditions, returns the id.
//
// # Events
//
// [Client.OnTextMessage] and the rest deliver the five notification categories
// both TCP and SSH accept: server, channel, textserver, textchannel and
// textprivate. Registration is automatic; [WithEvents] narrows it, and
// [WithoutEvents] turns it off. `bans` is opt-in, because TeamSpeak 3 refuses
// it.
//
// Over a transport that cannot deliver events, an On… call for a server event
// returns a function that does nothing and logs once at Warn, rather than
// failing: the WebQuery api key the server prints is accepted for the commands
// and refused only for events, so a client that refused the connection would
// refuse the one TS6 serves by default. [Client.OnConnected] and
// [Client.OnDisconnected] report the connection itself and work everywhere.
//
// # Experimental
//
// This package is experimental and ships as such: it may change in a minor
// release, unlike the rest of the module, which follows semantic versioning
// from v1.0.0. Every exported name here may change.
package serverquery
