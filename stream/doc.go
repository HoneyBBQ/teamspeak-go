// Package stream does the signalling of TeamSpeak 6 streams, the screen share:
// which streams exist, publishing one, and watching one.
//
// The video itself is not here. A stream travels between its publisher and each
// viewer over WebRTC, which is the application's: this package hands it the
// SDP and ICE messages as strings and carries the ones it sends back, so any
// WebRTC stack plugs in, and the package has no WebRTC dependency.
//
// # Experimental protocol
//
// TeamSpeak does not document the stream protocol. This package was verified
// against a TeamSpeak 6 server 6.0.0-beta13.1 and the TeamSpeak 6 client
// 6.0.0-beta5 (macOS). A TeamSpeak update may break it. A TeamSpeak 3 server
// does not do streams and answers none of the commands, so Publish and Watch
// return an *UnsupportedError before sending anything.
//
// # Use
//
// New attaches a Streams to a client, before or after it connects. It finds the
// streams of the clients the client sees: a client that sets client_is_streaming
// is asked for them, so a stream that started before this client came is found
// too.
//
//	s := stream.New(c, stream.Options{})
//	defer s.Close(context.WithoutCancel(ctx))
//
//	s.OnStarted(func(info stream.Info) { fmt.Println(info.Name, "is streaming") })
//	view, err := s.Watch(ctx, id, stream.WatchOptions{})
//	// give view.Offer() to a WebRTC peer connection, and send its answer with
//	// view.Answer.
//
// Publish starts a stream, and a Published delivers a JoinRequest for each
// client that asks to watch. The server relays every request, from any channel,
// and enforces neither the viewer limit nor the accessibility: deciding is the
// publisher's job.
//
// # Handlers
//
// Like the client's, events are delivered to handlers registered with On...
// methods, each of which returns a function that removes the handler. Every
// handler of a Streams and of the objects it makes runs on one goroutine, one
// at a time, in the order the events happened. A handler may call any method of
// this package, including ones that wait for the server: the answers are handled
// by the client, not by the goroutine the handler runs on. A handler that blocks
// holds up the events behind it. A panic in a handler is recovered and logged.
//
// An event that happens while there is no handler for it, before the first is
// registered or after the last was removed, is kept for the next, up to 256,
// where losing it would lose a request, a signalling message or an end: the
// errors and warnings of a Streams, the requests and the end of a Published, the
// close of a JoinRequest and every event of a Peer.
//
// # Goroutines
//
// Close ends every session the Streams made and waits for what it started.
// Every goroutine the package starts ends on its own: a command it sent ends
// within its deadline, and Publish keeps the setupstream open for five seconds
// past the caller's deadline on purpose (see Publish).
//
// # Differences from the other SDK
//
// This is the same behaviour as the @honeybbq/teamspeak/stream package of
// teamspeak-js, in Go's terms: contexts instead of signals and timeouts,
// handlers registered with On... instead of an event emitter, and Close, which
// returns what failed, instead of dispose.
package stream
