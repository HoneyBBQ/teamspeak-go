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
//   - [SSH] carries the same session on port 10022, and only TeamSpeak 6 serves
//     it, off by default. The SSH login replaces `login`, so no query password
//     goes over the wire, and it delivers notifications.
//   - [Web] is TeamSpeak 6's WebQuery, on port 10080, an HTTP interface where
//     an api key replaces the login. It has no session for the server to push
//     to, so it delivers no events and refuses file transfers.
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
