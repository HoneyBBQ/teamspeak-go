// Package teamspeak is what the TeamSpeak clients in this module share: the
// typed commands, the results they return, and the errors they report.
//
// The commands are methods of [Commands], which runs on any [Executor] — a
// connection able to execute a command. A client embeds Commands, so with the
// voice client
//
//	c, err := client.New(id, "ts.example.com", "bot")
//	...
//	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
//
// Import a client rather than this package on its own: [client] speaks the
// voice protocol, the way the TeamSpeak application does. A ServerQuery client
// will run the same commands.
//
// # Packages
//
//   - [client] is the voice client: session, events, voice, reconnection and
//     file transfers.
//   - serverquery runs the same commands over ServerQuery, on raw TCP, SSH or
//     WebQuery.
//   - stream does the signalling of TeamSpeak 6 screen share.
//   - identity creates, stores and inspects identities; versions lists the
//     client versions a server accepts.
//   - errcode, perm, notify, prop and commands hold the server's constants and
//     the command language.
//
// # Documentation
//
// Longer guides are in the repository's docs directory:
//
//   - [the guide]: connecting, events, commands, file transfers, identities
//   - [the configuration]: options, client version, tracing
//   - [streams]: TeamSpeak 6 screen share
//   - [ServerQuery]: the query client and its transports
//   - [the design conventions]: errors, ids, absent values, stability
//   - [compatibility]: supported Go versions, differences from teamspeak-js
//
// [client]: https://pkg.go.dev/github.com/honeybbq/teamspeak-go/client
// [the guide]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/guide.md
// [the configuration]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/configuration.md
// [streams]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/streams.md
// [ServerQuery]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/serverquery.md
// [the design conventions]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/design.md
// [compatibility]: https://github.com/honeybbq/teamspeak-go/blob/main/docs/compatibility.md
package teamspeak
