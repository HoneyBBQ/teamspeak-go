// Package teamspeak is what the TeamSpeak clients in this module share: the
// typed commands, the results they return, and the errors they report.
//
// The commands are methods of [Commands], which runs on any [Executor] — a
// connection able to execute a command. A client embeds Commands, so with the
// voice client
//
//	c, err := client.New(id, "ts.example.com", "bot")
//	...
//	channels, err := c.ListChannels(ctx)
//
// Import a client rather than this package on its own: [client] speaks the
// voice protocol, the way the TeamSpeak application does. A ServerQuery client
// will run the same commands.
//
// [client]: https://pkg.go.dev/github.com/honeybbq/teamspeak-go/client
package teamspeak
