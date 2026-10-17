// Package serverquery runs the typed commands over ServerQuery, TeamSpeak's
// line-based administration protocol, and delivers the server's notifications
// as events.
//
// Create a client with [New] and a Dialer from [TCP], [SSH] or [Web], then
// [Client.Connect]:
//
//	c, err := serverquery.New(serverquery.TCP("127.0.0.1:10011"),
//		serverquery.WithLogin("serveradmin", password),
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
//     It needs `login` unless the address is already allowlisted, and it
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
