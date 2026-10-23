# Streams

TeamSpeak 6 clients can share a screen, a window or a camera. The `stream`
package does the signalling of that: it finds the streams of the clients in
view, publishes one, and watches one. The video itself travels between the
publisher and each viewer over WebRTC, which is yours: `stream` hands you the
SDP and the ICE candidates as strings and takes them back, so any WebRTC stack
plugs in. The package has no WebRTC dependency; the examples below use
[pion](https://github.com/pion/webrtc).

TeamSpeak does not document this protocol. It was verified against the
TeamSpeak 6 server 6.0.0-beta13.1 and the TeamSpeak 6 client 6.0.0-beta5
(macOS), and a TeamSpeak update may break it. A TeamSpeak 3 server does not
answer the stream commands at all, so `Publish` and `Watch` return a
`*stream.UnsupportedError` before sending anything.

Watching: find a stream with `List` or wait for `OnStarted`, ask to watch it,
and give the publisher's offer to a peer connection. The viewer's connection
is receive-only.

```go
s := stream.New(c, stream.Options{})
defer s.Close(context.WithoutCancel(ctx))

s.OnStarted(func(info stream.Info) { log.Printf("%s is streaming", info.Name) })

view, err := s.Watch(ctx, info.ID, stream.WatchOptions{Message: "may I watch?"})
if err != nil {
	return err
}

pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
if err != nil {
	return err
}
pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) { /* read the RTP */ })
view.OnClosed(func(stream.PeerClosedEvent) { pc.Close() })

err = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: view.Offer()})
if err != nil {
	return err
}
// Candidates that arrived with the offer are delivered to the first handler.
view.OnCandidate(func(c stream.IceCandidate) {
	_ = pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: c.Candidate, SDPMid: c.SDPMid, SDPMLineIndex: c.SDPMLineIndex})
})
answer, err := pc.CreateAnswer(nil)
if err != nil {
	return err
}
if err = pc.SetLocalDescription(answer); err != nil {
	return err
}
// The answer goes first, then the candidates pc.OnICECandidate finds, with view.SendCandidate.
err = view.Answer(ctx, answer.SDP)
```

Publishing: the publisher makes the offer, one peer connection for each viewer.
The server relays every request to watch, from any channel, and enforces
neither the viewer limit nor the accessibility: deciding who is let in is the
publisher's job, and `OnRequest` is called for each one, with nothing accepted
for you.

```go
pub, err := s.Publish(ctx, stream.PublishOptions{Name: "My screen", Audio: true})
if err != nil {
	return err
}
pub.OnRequest(func(request *stream.JoinRequest) {
	if !allowed(request.Viewer()) {
		_ = request.Deny(ctx, "Not today")

		return
	}
	pc, _ := webrtc.NewPeerConnection(webrtc.Configuration{})
	// Add the video track, and always offer audio, even with nothing to send
	// (see the interop notes below).
	_, _ = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	offer, _ := pc.CreateOffer(nil)
	_ = pc.SetLocalDescription(offer)

	viewer, err := request.Accept(ctx, offer.SDP, "welcome")
	if err != nil {
		return
	}
	viewer.OnAnswer(func(sdp string) {
		_ = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp})
	})
	viewer.OnCandidate(func(c stream.IceCandidate) {
		_ = pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: c.Candidate, SDPMid: c.SDPMid, SDPMLineIndex: c.SDPMLineIndex})
	})
	viewer.OnClosed(func(stream.PeerClosedEvent) { pc.Close() })
	// Send the candidates pc.OnICECandidate finds with viewer.SendCandidate.
})

err = pub.Stop(ctx, 0)
```

A complete pair of peers, over a live server, is in
[stream/e2e](../stream/e2e), a module of its own so that the WebRTC stack stays
out of this module's dependencies.

A request that nobody has answered can end: the viewer withdraws it or goes
out of view, or the stream ends. `request.OnClosed` is called then, with the
state `stream.RequestWithdrawn` or `stream.RequestEnded`, so a UI can drop the request
without polling `request.State()`; `Accept` and `Deny` then return
`stream.ErrNotPending`. It is not called for a request that was accepted or
denied.

## Interop with the TeamSpeak 6 client

What follows was observed with the TeamSpeak 6 client 6.0.0-beta5 (macOS)
against a TeamSpeak 6 server 6.0.0-beta13.1.

- **Offer audio, always.** When you publish, the client answers an offer only
  if it has an `m=audio` section. For a video-only offer it never answers: it
  shows a fallback picture and keeps the "Join" button, which then does
  nothing, because the server already counts the viewer as joined. Add a
  send-only audio transceiver even when there is no audio track; an audio
  section before the video section was accepted. `Accept` and
  `ViewerPeer.SendOffer` send an offer without audio unchanged, and call
  `Streams.OnWarning` with the code `stream.WarningOfferWithoutAudio`.
- **Trim the codecs.** The client's own offers carry one video and one audio
  section, about 3.9 KB. A browser's offer with every codec is about 6 KB with
  audio and video, and about 4.8 KB for video alone, against a limit of about
  9.2 KB for a command line. pion's offer with its default codecs, one VP8
  track and an audio transceiver, is about 5.6 KB. Narrowing the codecs keeps
  room for the candidates and the message.
- **Accept every request.** A viewer in the client shows "waiting" until the
  publisher answers. When it withdraws and asks again, that is a new request,
  with a new `JoinRequest`.
- **A channel switch ends the viewing, not the stream.** The client leaves a
  stream it watches when it changes channel, so the publisher sees that viewer
  leave. The server does not end a stream when its publisher or a viewer
  changes channel.
- Denying, stopping, leaving, disconnecting and several viewers at once, some
  of them the client and some the SDK, behaved as they do between SDK clients.

Things to know:

- A client may run several streams, so every stream is known by its id. `List`
  is what this client has heard of. A stream that ends while its publisher is
  out of the channel is reported to nobody there, and stays listed until the
  connection ends.
- A stream survives its publisher changing channel, with no event. It ends
  when the publisher stops it or disconnects.
- The server drops a command line longer than about 9.2 KB without an answer.
  Stream commands are checked first and return a `*stream.PayloadTooLargeError`;
  an SDP offer or an ICE candidate is a few kilobytes at most.
- The server lets anyone stop any stream. `Streams` sends `stopstream` only for
  streams it published, and treats a `notifystreamstopped` for any stream as
  final.
- The server remembers no decision, so a client can ask again, and every ask
  is relayed. To refuse for good, set `Options.RememberDenied` (the 1024 most
  recent uids, in memory only; a requester out of view is looked up with
  `clientgetuidfromclid`), or leave the request unanswered. The server has no
  way to remove a viewer: closing a viewer's peer ends your side of it, and
  stopping the stream ends it for everyone.
- `Streams.Close` stops the streams published through that `Streams` and
  leaves the ones it watched, while the client is connected, and returns what
  failed. A stream whose `Publish` gave up after the command went out is
  stopped when its announcement arrives, so none is left running unseen;
  `Close` waits for that command, within its context, and returns the failure
  of the stop.
- A client whose `client_is_streaming` clears, or that comes into view not
  streaming, has its streams dropped, after a grace of two seconds:
  `OnStopped` with `stream.EndCauseGone`. The server clears the flag right before
  it reports the stop, so a stop that arrives in that time ends the stream with
  its own cause and reason instead, and a flag set again cancels the drop.
- The bitrate the server reports for a stream is not the one requested.
- A client announces that it streams only with `client_is_streaming`, and a
  stream that was running before you came is not announced at all. `Streams`
  asks for the streams of each client that sets the flag, once, on a
  TeamSpeak 6 server.
- Handlers run one at a time on a goroutine of the `Streams`, in order, and
  may call any method of the package. A request, a signalling message or an
  end that happens before its first handler is registered is kept for it, up
  to 256.
