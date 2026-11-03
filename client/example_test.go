package client_test

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// Connect returns once the handshake has completed, and Disconnect says
// goodbye before closing the connection.
func ExampleNew() { //nolint:testableexamples // connects to a server, so it is compiled, not run
	ctx := context.Background()

	id, err := identity.Generate(ctx, 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "bot", client.WithDefaultChannel("Lobby"))
	if err != nil {
		log.Fatal(err)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = c.Connect(connectCtx)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()

	caps := c.ServerCapabilities()
	fmt.Printf("connected to %q, %s %s\n", c.View().ServerName(), caps.Family, caps.Version)
}

// A handler is registered before connecting, so it hears the events that
// arrive during the handshake too, and removed by calling what it returned.
func ExampleClient_OnTextMessage() {
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "bot")
	if err != nil {
		log.Fatal(err)
	}

	stop := c.OnTextMessage(func(msg client.TextMessageEvent) {
		fmt.Printf("%s: %s\n", msg.InvokerName, msg.Message)
	})
	// No further messages reach the handler once stop returns.
	stop()
	// Output:
}

// The typed commands are methods of the client, from the embedded
// teamspeak.Commands.
func ExampleClient_ListChannels() { //nolint:testableexamples // connects to a server, so it is compiled, not run
	ctx := context.Background()
	id, err := identity.Generate(ctx, 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "bot")
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	_ = c.Disconnect(context.WithoutCancel(ctx))
	if err != nil {
		log.Fatal(err)
	}
	for _, ch := range channels {
		fmt.Println(ch.ID, ch.Name)
	}
}

// Event middleware sees every server event, and may pass it on, replace it or
// drop it. This one drops text messages that look like commands for another
// bot.
func ExampleWithEventMiddleware() {
	ignoreCommands := func(next func(client.Event)) func(client.Event) {
		return func(evt client.Event) {
			if msg, ok := evt.(client.TextMessageEvent); ok && strings.HasPrefix(msg.Message, "!") {
				return
			}
			next(evt)
		}
	}

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.New(id, "ts.example.com", "bot", client.WithEventMiddleware(ignoreCommands))
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// OnNotification hears every notification as the server sent it: the way to
// act on one the SDK has no typed event for.
func ExampleClient_OnNotification() {
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "bot")
	if err != nil {
		log.Fatal(err)
	}

	c.OnNotification(func(n client.NotificationEvent) {
		if n.Name == "notifychanneledited" {
			fmt.Println("channel", n.Params["cid"], "edited")
		}
	})
	// Output:
}

// A receiver takes the voice packets the client receives, in its own
// goroutine and at its own pace. Read fills the packet it is given, reusing
// Data's capacity, so copy a frame to keep it past the next Read.
func ExampleVoiceReceiver() { //nolint:testableexamples // needs a connected client, so it is compiled, not run
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "recorder")
	if err != nil {
		log.Fatal(err)
	}
	rx, err := c.NewVoiceReceiver(client.VoiceReceiverOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = rx.Close() }()

	// A speaker's packets are told apart by the session, the client and
	// whether they were whispered: each of those has its own Seq.
	type stream struct {
		session uint64
		id      teamspeak.ClientID
		whisper bool
	}
	last := map[stream]uint16{}
	var p client.VoicePacket
	for {
		err = rx.Read(context.Background(), &p)
		if err != nil {
			return // the receiver was closed
		}
		key := stream{p.Session, p.ClientID, p.Whisper}
		if prev, ok := last[key]; ok && int16(p.Seq-prev) <= 0 {
			continue // late, or a repeat: Seq wraps, so compare as int16(a-b)
		}
		last[key] = p.Seq
		frame := slices.Clone(p.Data)
		fmt.Println(p.ClientID, p.Codec, len(frame), p.ReceivedAt)
	}
}

// TryRead is for a loop with a clock of its own, such as an audio device's,
// that takes what has arrived on each tick and must not wait.
func ExampleVoiceReceiver_TryRead() { //nolint:testableexamples // needs a connected client, so it is compiled, not run
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "player")
	if err != nil {
		log.Fatal(err)
	}
	rx, err := c.NewVoiceReceiver(client.VoiceReceiverOptions{Capacity: 256})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = rx.Close() }()

	var p client.VoicePacket
	var lastDropped uint64
	for range time.Tick(10 * time.Millisecond) {
		for rx.TryRead(&p) {
			fmt.Println(p.ClientID, p.Seq, len(p.Data))
		}
		// Packets this receiver dropped for being full, not the network's
		// losses: those are gaps in Seq.
		if d := rx.Dropped(); d != lastDropped {
			fmt.Println("dropped", d-lastDropped)
			lastDropped = d
		}
	}
}
