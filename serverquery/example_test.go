package serverquery_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// The typed commands are the voice client's, run over a ServerQuery connection.
func ExampleNew() { //nolint:testableexamples // connects to a server, so it is compiled, not run
	ctx := context.Background()

	c, err := serverquery.New(
		serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", os.Getenv("QUERY_PASSWORD")),
		serverquery.WithServer(1),
		serverquery.WithNickname("bot"),
	)
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()

	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		log.Print(err)

		return
	}
	fmt.Println(len(channels), "channels")
}

// The SSH transport needs a host key policy; KnownHosts reads an OpenSSH
// known_hosts file from the path it is given.
func ExampleKnownHosts() { //nolint:testableexamples // connects to a server, so it is compiled, not run
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	check, err := serverquery.KnownHosts(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal(err)
	}
	c, err := serverquery.New(serverquery.SSHWith("ts.example.com:10022", "serveradmin", os.Getenv("QUERY_PASSWORD"),
		serverquery.SSHOptions{HostKeyCheck: check}))
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

// Events are delivered over the raw TCP and SSH transports.
func ExampleClient_OnTextMessage() { //nolint:testableexamples // needs a server, so it is compiled, not run
	c, err := serverquery.New(serverquery.TCPLogin("127.0.0.1:10011", "serveradmin", os.Getenv("QUERY_PASSWORD")))
	if err != nil {
		log.Fatal(err)
	}
	c.OnTextMessage(func(m teamspeak.TextMessageEvent) {
		fmt.Println(m.InvokerName, "said", m.Message)
	})
}
