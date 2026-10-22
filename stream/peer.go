package stream

import (
	"context"
	"fmt"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// Peer is one end of a stream's signalling with one other client. SDP and ICE
// are opaque strings here: any WebRTC stack can be plugged in.
//
// A ViewerPeer and a View are Peers. Their handlers run on the Streams' queue.
// An event that happens before its handler is first registered is kept, up to
// 256 per event, and delivered to the first handler of that event, so nothing
// is lost in the time between receiving a peer and attaching to it.
type Peer struct {
	s *Streams
	// pub is the stream a viewer's peer belongs to; nil for a View.
	pub       *Published
	offer     *topic[string]
	answer    *topic[string]
	candidate *topic[IceCandidate]
	signal    *topic[RawSignal]
	closedT   *topic[PeerClosed]
	streamID  ID
	clientID  teamspeak.ClientID
	closed    bool
}

func newPeer(s *Streams, pub *Published, id ID, clid teamspeak.ClientID) *Peer {
	p := &Peer{s: s, pub: pub, streamID: id, clientID: clid}
	// Once for the peer, not for every message past the bound.
	reported := false
	drop := func(name string) {
		if reported {
			return
		}
		reported = true
		s.reportLocked(fmt.Errorf("%w %s of stream %s from client %d: %d are waiting for a handler",
			errDropped, name, id, clid, maxKept))
	}
	p.offer = newTopic[string](&s.bus, "offer", true)
	p.answer = newTopic[string](&s.bus, "answer", true)
	p.candidate = newTopic[IceCandidate](&s.bus, "candidate", true)
	p.signal = newTopic[RawSignal](&s.bus, "signal", true)
	p.closedT = newTopic[PeerClosed](&s.bus, "peer closed", true)
	p.offer.onDrop, p.answer.onDrop, p.candidate.onDrop, p.signal.onDrop, p.closedT.onDrop = drop, drop, drop, drop, drop
	p.candidate.clone = func(c IceCandidate) IceCandidate {
		c.SDPMid, c.SDPMLineIndex = clonePtr(c.SDPMid), clonePtr(c.SDPMLineIndex)

		return c
	}

	return p
}

// StreamID returns the stream.
func (p *Peer) StreamID() ID { return p.streamID }

// ClientID returns the client at the other end.
func (p *Peer) ClientID() teamspeak.ClientID { return p.clientID }

// Closed reports whether the peer has closed.
func (p *Peer) Closed() bool {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.closed
}

// OnOffer registers a handler for a renegotiation offer from the publisher: an
// SDP. It returns a function that removes the handler.
func (p *Peer) OnOffer(handler func(sdp string)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.offer.on(handler)
}

// OnAnswer registers a handler for the viewer's SDP answer. It returns a
// function that removes the handler.
func (p *Peer) OnAnswer(handler func(sdp string)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.answer.on(handler)
}

// OnCandidate registers a handler for an ICE candidate from the other end. It
// returns a function that removes the handler.
func (p *Peer) OnCandidate(handler func(IceCandidate)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.candidate.on(handler)
}

// OnSignal registers a handler for a signalling message that is none of the
// above, or was not shaped as they are. It returns a function that removes the
// handler.
func (p *Peer) OnSignal(handler func(RawSignal)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.signal.on(handler)
}

// OnClosed registers a handler for the peer closing, for whatever cause. It
// returns a function that removes the handler.
func (p *Peer) OnClosed(handler func(PeerClosed)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.closedT.on(handler)
}

// SendCandidate sends an ICE candidate to the other end.
func (p *Peer) SendCandidate(ctx context.Context, c IceCandidate) error {
	return p.sendJSON(ctx, candidateJSON(c))
}

// SendSignal sends a signalling message this package has no method for, as
// {"cmd":cmd,"args":args} with args encoded as JSON (left out when nil). The
// server relays it unseen, and a receiver that does not understand the shape
// drops it without a word.
func (p *Peer) SendSignal(ctx context.Context, cmd string, args any) error {
	text, err := encodeSignal(cmd, args)
	if err != nil {
		return fmt.Errorf("stream: encoding the signal: %w", err)
	}

	return p.sendJSON(ctx, text)
}

// Close stops sending and delivering for this peer. On a viewer's side this
// also leaves the stream, and Close returns what the server answered. The
// publisher's side sends nothing: the server has no way to remove a viewer, so
// a viewer closed here stays a participant on the server and may keep
// signalling, which is ignored, and may ask again, which is a new request. Stop
// the stream to end it for everyone. Closing a closed peer does nothing.
func (p *Peer) Close(ctx context.Context) error {
	p.s.mu.Lock()
	if p.closed {
		p.s.mu.Unlock()

		return nil
	}
	p.endLocked(PeerClosed{Cause: CauseClosed})
	p.s.mu.Unlock()

	if p.pub != nil {
		return nil
	}

	return p.s.leave(ctx, p.streamID, p.clientID)
}

func (p *Peer) sendJSON(ctx context.Context, text string) error {
	if p.Closed() {
		return ErrClosed
	}

	return p.s.send(ctx, signalRequest(p.streamID, p.clientID, text), p.streamID)
}

// deliverLocked takes a signalling JSON from the other end.
func (p *Peer) deliverLocked(text string) {
	if p.closed {
		return
	}
	sig := parseSignal(text)
	switch sig.kind {
	case signalOffer:
		p.offer.emit(sig.sdp)
	case signalAnswer:
		p.answer.emit(sig.sdp)
	case signalCandidate:
		p.candidate.emit(sig.candidate)
	case signalRaw:
		p.signal.emit(sig.raw)
	}
}

// endLocked closes the peer without telling the server, once.
func (p *Peer) endLocked(c PeerClosed) {
	if p.closed {
		return
	}
	p.closed = true
	if p.pub != nil {
		if v := p.pub.peers[p.clientID]; v != nil && v.Peer == p {
			delete(p.pub.peers, p.clientID)
			p.pub.closedViewers.add(p.clientID)
		}
	} else if w := p.s.watching[p.streamID]; w != nil && w.view != nil && w.view.Peer == p {
		delete(p.s.watching, p.streamID)
	}
	p.closedT.emit(c)
}

// ViewerPeer is the publisher's end for one accepted viewer.
type ViewerPeer struct {
	*Peer
}

// SendOffer sends an SDP offer, to renegotiate. The first offer goes with
// JoinRequest.Accept. The server relays the message unseen, and whether a
// viewer takes it is up to the viewer: renegotiation has not been tried. An
// offer with no m=audio section is sent as it is, with a
// WarningOfferWithoutAudio.
func (v *ViewerPeer) SendOffer(ctx context.Context, sdp string) error {
	if !hasAudioSection(sdp) {
		v.s.mu.Lock()
		v.s.warnNoAudioLocked(v.streamID, v.clientID)
		v.s.mu.Unlock()
	}

	return v.sendJSON(ctx, offerJSON(sdp))
}

// View is the viewer's end of a stream it was let into, made by Streams.Watch.
// It is unrelated to client.ServerView.
type View struct {
	*Peer

	offer string
}

// Offer returns the publisher's SDP offer.
func (v *View) Offer() string { return v.offer }

// Answer sends the SDP answer to the offer.
func (v *View) Answer(ctx context.Context, sdp string) error {
	return v.sendJSON(ctx, answerJSON(sdp))
}

// Leave leaves the stream: the same as Close.
func (v *View) Leave(ctx context.Context) error {
	return v.Close(ctx)
}
