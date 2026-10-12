// Package client is a clean-room TeamSpeak client: it connects over the voice
// protocol, the way the TeamSpeak application does, and needs no proprietary
// SDK.
//
// Create one with [New] and an identity from the identity package, then
// [Client.Connect], which returns once the handshake completes:
//
//	id, err := identity.Generate(ctx, 8)
//	c, err := client.New(id, "ts.example.com", "bot")
//	err = c.Connect(ctx)
//	defer c.Disconnect(context.WithoutCancel(ctx))
//	channels, err := c.ListChannels(ctx)
//
// The typed commands come from the embedded [teamspeak.Commands]; this package
// adds the session itself — events, voice, whispers, reconnection — and the
// few commands only the voice protocol has.
package client
