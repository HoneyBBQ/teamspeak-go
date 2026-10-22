package stream_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/stream"
)

// connect returns a connected client, for the examples.
func connect(ctx context.Context) *client.Client {
	id, err := identity.Generate(ctx, 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "streamer")
	if err != nil {
		log.Fatal(err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = c.Connect(connectCtx)
	if err != nil {
		log.Fatal(err)
	}

	return c
}

// A viewer watches a stream that was announced. The SDP offer in the view is
// handed to a WebRTC peer connection, and the answer and the candidates it
// produces go back through the view.
func ExampleStreams_Watch() { //nolint:testableexamples // needs a server, so it is compiled, not run
	ctx := context.Background()
	c := connect(ctx)
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()
	s := stream.New(c, stream.Options{})
	defer func() { _ = s.Close(context.WithoutCancel(ctx)) }()

	found := make(chan stream.Info, 1)
	s.OnStarted(func(info stream.Info) { found <- info })
	info := <-found

	watchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	view, err := s.Watch(watchCtx, info.ID, stream.WatchOptions{Message: "hello"})
	if err != nil {
		log.Fatal(err)
	}
	view.OnCandidate(func(candidate stream.IceCandidate) {
		// Give it to the peer connection.
		fmt.Println("candidate from the publisher:", candidate.Candidate)
	})
	view.OnClosed(func(closed stream.PeerClosed) { fmt.Println("the stream ended:", closed.Cause) })

	fmt.Println("offer:", len(view.Offer()), "bytes")
	// Create the answer with the peer connection, then:
	err = view.Answer(ctx, "v=0 ...")
	if err != nil {
		log.Fatal(err)
	}
}

// A publisher announces a stream and lets in every client that asks, with an
// SDP offer from its own WebRTC peer connection.
func ExampleStreams_Publish() { //nolint:testableexamples // needs a server, so it is compiled, not run
	ctx := context.Background()
	c := connect(ctx)
	defer func() { _ = c.Disconnect(context.WithoutCancel(ctx)) }()
	s := stream.New(c, stream.Options{})
	defer func() { _ = s.Close(context.WithoutCancel(ctx)) }()

	published, err := s.Publish(ctx, stream.PublishOptions{Name: "Demo", Audio: true})
	if err != nil {
		log.Fatal(err)
	}
	published.OnRequest(func(request *stream.JoinRequest) {
		// Make a peer connection for this viewer and an offer with an audio
		// section, even for a screen share: the TeamSpeak 6 client does not
		// answer an offer without one.
		offer := "v=0 ..."
		viewer, err := request.Accept(ctx, offer, "welcome")
		if err != nil {
			log.Print(err)

			return
		}
		viewer.OnAnswer(func(sdp string) { fmt.Println("answer:", len(sdp), "bytes") })
		viewer.OnCandidate(func(candidate stream.IceCandidate) { fmt.Println("candidate:", candidate.Candidate) })
	})
	published.OnEnded(func(ended stream.Ended) { fmt.Println("ended:", ended.Cause) })
	defer func() { _ = published.Stop(context.WithoutCancel(ctx), 0) }()
}
