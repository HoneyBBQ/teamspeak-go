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
//
// # Events
//
// Handlers registered with the On… methods run one at a time, in the order
// their events arrived, on a goroutine of the client's own, so a handler may
// call the client without stalling the connection. A handler that blocks holds
// up the events behind it. A handler or event middleware that panics is
// recovered and logged at Error with the event type; the other handlers and
// later events are still delivered.
package client
