package client_test

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

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
	fmt.Printf("connected to %q, %s %s\n", caps.Name, caps.Family, caps.Version)
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

	stop := c.OnTextMessage(func(msg client.TextMessage) {
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

	channels, err := c.ListChannels(ctx)
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
			if msg, ok := evt.(client.TextMessage); ok && strings.HasPrefix(msg.Message, "!") {
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

	c.OnNotification(func(n client.RawNotification) {
		if n.Name == "notifychanneledited" {
			fmt.Println("channel", n.Params["cid"], "edited")
		}
	})
	// Output:
}
