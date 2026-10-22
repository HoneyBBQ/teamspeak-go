package stream

import (
	"context"
	"fmt"
	"slices"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// lookupTimeout bounds the lookup of a requester who is out of view.
const lookupTimeout = 10 * time.Second

// maxClosedViewers is how many viewers whose peer is over are remembered, to
// ignore what they still send.
const maxClosedViewers = 1024

// Published is a stream this client publishes. Make one with Streams.Publish.
//
// Its handlers run on the Streams' queue. A request or an end that happens
// before OnRequest or OnEnded is first called is kept, up to 256, and delivered
// to the first handler.
type Published struct {
	s        *Streams
	requests *topic[*JoinRequest]
	ended    *topic[EndedEvent]
	// peers are the viewers let in and still there.
	peers   map[teamspeak.ClientID]*ViewerPeer
	pending map[teamspeak.ClientID]*JoinRequest
	// resolving are the viewers asked about, until the answer comes back, so
	// that a repeat is no new request.
	resolving map[teamspeak.ClientID]struct{}
	// closedViewers are the viewers whose peer is over: what they still send is
	// not worth a report.
	closedViewers *lru[teamspeak.ClientID]
	id            ID
	// queue holds the requests waiting for the one ahead of them to be
	// announced, so that they are announced in the order they came, whatever
	// the lookups take.
	queue   []lookup
	initial Info
	// owner is this client's id on the connection that started the stream.
	owner teamspeak.ClientID
	// working is whether the goroutine that drains queue is running.
	working bool
	done    bool
}

// lookup is a request waiting to be announced.
type lookup struct {
	message string
	viewer  Viewer
	// known is whether viewer is complete: the client was in view.
	known bool
}

func newPublished(s *Streams, initial Info) *Published {
	p := &Published{
		s:             s,
		id:            initial.ID,
		initial:       initial,
		peers:         make(map[teamspeak.ClientID]*ViewerPeer),
		pending:       make(map[teamspeak.ClientID]*JoinRequest),
		resolving:     make(map[teamspeak.ClientID]struct{}),
		closedViewers: newLRU[teamspeak.ClientID](maxClosedViewers),
	}
	// Reported once for the stream, not for every event past the bound.
	reported := false
	drop := func(name string) {
		if reported {
			return
		}
		reported = true
		s.reportLocked(fmt.Errorf("%w %s of stream %s: %d are waiting for a handler", errDropped, name, p.id, maxKept))
	}
	p.requests = newTopic[*JoinRequest](&s.bus, "request", true)
	p.requests.onDrop = drop
	p.ended = newTopic[EndedEvent](&s.bus, "ended", true)
	p.ended.onDrop = drop

	return p
}

// ID returns the stream's id.
func (p *Published) ID() ID { return p.id }

// Info returns what is known of the stream now.
func (p *Published) Info() Info {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	if info := p.s.known(p.id); info != nil {
		return info.clone()
	}

	return p.initial.clone()
}

// Ended reports whether the stream has ended.
func (p *Published) Ended() bool {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.done
}

// Viewers returns the viewers let in and still there, by client id. It is this
// client's own, live list; Info.Viewers, which every client has for every
// stream, is the count the server last reported and includes pending requests.
func (p *Published) Viewers() []*ViewerPeer {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	out := make([]*ViewerPeer, 0, len(p.peers))
	for _, v := range p.peers {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b *ViewerPeer) int { return int(a.clientID) - int(b.clientID) })

	return out
}

// OnRequest registers a handler for a client asking to watch. It returns a
// function that removes the handler.
func (p *Published) OnRequest(handler func(*JoinRequest)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.requests.on(handler)
}

// OnEnded registers a handler for the stream ending. It returns a function that
// removes the handler.
func (p *Published) OnEnded(handler func(EndedEvent)) func() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	return p.ended.on(handler)
}

// Stop stops the stream, for everyone. reason is a number the server passes to
// the viewers (0 is the usual one). Stop returns once the server took the
// command, with the stream ended here too: the server tells the one who
// stopped nothing. A stream the server no longer knows counts as stopped; on any
// other failure the stream is left running.
func (p *Published) Stop(ctx context.Context, reason uint32) error {
	if p.Ended() {
		return nil
	}
	err := p.s.stopStream(ctx, p.id, reason)
	if err != nil {
		return err
	}
	p.s.mu.Lock()
	defer p.s.mu.Unlock()

	p.s.endLocked(p.id, reason, EndCauseStopped)

	return nil
}

// openViewerLocked makes the peer for a viewer this stream let in.
func (p *Published) openViewerLocked(clid teamspeak.ClientID) *ViewerPeer {
	v := &ViewerPeer{Peer: newPeer(p.s, p, p.id, clid)}
	p.closedViewers.remove(clid)
	p.peers[clid] = v

	return v
}

// requestLocked is a viewer asking to watch. entry is the viewer as the client
// has it in view, or nil.
func (p *Published) requestLocked(clid teamspeak.ClientID, message string, entry *teamspeak.ClientEntry) {
	// Asking again while pending, being looked up or let in is no new request.
	if _, resolving := p.resolving[clid]; p.done || p.peers[clid] != nil || resolving || p.pending[clid] != nil {
		return
	}
	p.resolving[clid] = struct{}{}
	w := lookup{message: message, viewer: Viewer{ClientID: clid}}
	if entry != nil {
		w.viewer = Viewer{ClientID: clid, UID: entry.UID, Nickname: entry.Nickname}
		w.known = true
	}
	// Nothing to wait for, and nothing ahead of it to wait for: at once.
	if w.known && !p.working {
		p.announceLocked(w)

		return
	}
	p.queue = append(p.queue, w)
	if !p.working {
		ctx := p.s.conn
		p.working = p.s.spawnLocked(func() { p.drain(ctx) })
	}
}

// drain announces the queued requests, one after another.
func (p *Published) drain(ctx context.Context) {
	for {
		p.s.mu.Lock()
		if p.done || len(p.queue) == 0 {
			p.queue, p.working = nil, false
			p.s.mu.Unlock()

			return
		}
		w := p.queue[0]
		p.queue = p.queue[1:]
		p.s.mu.Unlock()

		if !w.known {
			w.viewer = p.s.identity(ctx, w.viewer.ClientID)
		}
		p.s.mu.Lock()
		p.announceLocked(w)
		p.s.mu.Unlock()
	}
}

func (p *Published) announceLocked(w lookup) {
	clid := w.viewer.ClientID
	// Withdrawn, or the stream over, while the lookup was out.
	if _, ok := p.resolving[clid]; !ok || p.done {
		return
	}
	delete(p.resolving, clid)
	if p.s.deniedLocked(w.viewer) {
		return
	}
	r := &JoinRequest{p: p, viewer: w.viewer, message: w.message}
	r.closed = newTopic[RequestState](&p.s.bus, "request closed", true)
	p.pending[clid] = r
	p.requests.emit(r)
}

// dropPendingLocked is a client that left view: a request of its that nobody
// answered is forgotten, as the client id may be reused.
func (p *Published) dropPendingLocked(clid teamspeak.ClientID) {
	delete(p.resolving, clid)
	if r := p.pending[clid]; r != nil {
		r.closeLocked(RequestWithdrawn)
		delete(p.pending, clid)
	}
}

// viewerGoneLocked is a viewer that is gone, by saying so or by disconnecting.
func (p *Published) viewerGoneLocked(clid teamspeak.ClientID) {
	p.dropPendingLocked(clid)
	if v := p.peers[clid]; v != nil {
		v.endLocked(PeerClosedEvent{Cause: PeerCauseLeft})
	}
}

// signalLocked takes a signalling JSON from a viewer; it reports false when
// this stream has no such viewer. A viewer whose peer is over is answered true
// and ignored: the server cannot remove a viewer, so it may keep sending.
func (p *Published) signalLocked(clid teamspeak.ClientID, text string) bool {
	v := p.peers[clid]
	if v == nil {
		return p.closedViewers.has(clid)
	}
	v.deliverLocked(text)

	return true
}

// finishLocked ends the stream and everything that hangs on it, once.
func (p *Published) finishLocked(e EndedEvent) {
	if p.done {
		return
	}
	p.done = true
	for clid, r := range p.pending {
		r.closeLocked(RequestEnded)
		delete(p.pending, clid)
	}
	closed := PeerClosedEvent{Cause: e.Cause.peer()}
	if closed.Cause == PeerCauseStopped {
		closed.Reason = e.Reason
	}
	for _, v := range p.viewersLocked() {
		v.endLocked(closed)
	}
	p.ended.emit(e)
}

func (p *Published) viewersLocked() []*ViewerPeer {
	out := make([]*ViewerPeer, 0, len(p.peers))
	for _, v := range p.peers {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b *ViewerPeer) int { return int(a.clientID) - int(b.clientID) })

	return out
}

// JoinRequest is a client asking to watch a stream this client publishes. The
// server relays every request, from any channel, and enforces neither the
// viewer limit nor the accessibility: deciding is the publisher's job, and
// nothing is accepted for it. A request is answered once.
type JoinRequest struct {
	p       *Published
	closed  *topic[RequestState]
	message string
	viewer  Viewer
	state   RequestState
}

// StreamID returns the stream asked for.
func (r *JoinRequest) StreamID() ID { return r.p.id }

// Viewer returns who asked.
func (r *JoinRequest) Viewer() Viewer { return r.viewer }

// Message returns the message that came with the request; it may be empty.
func (r *JoinRequest) Message() string { return r.message }

// State returns where the request stands.
func (r *JoinRequest) State() RequestState {
	r.p.s.mu.Lock()
	defer r.p.s.mu.Unlock()

	return r.state
}

// OnClosed registers a handler for a request nobody had answered closing: the
// viewer withdrew it or left view (the handler gets RequestWithdrawn), or the
// stream ended (RequestEnded). It is called once, and
// never for a request that was accepted or denied, nor when Accept or Deny
// themselves are called. From then on Accept and Deny return ErrNotPending. A
// close that happens before the first handler is registered is kept for it. It
// returns a function that removes the handler.
func (r *JoinRequest) OnClosed(handler func(RequestState)) func() {
	r.p.s.mu.Lock()
	defer r.p.s.mu.Unlock()

	return r.closed.on(handler)
}

// Accept lets the viewer in, with the SDP offer it will answer and a message
// that goes with it, which may be empty. It returns the peer once the server
// took the answer. An offer that is too long returns a *PayloadTooLargeError
// before sending and without using the request up, so it may be shortened and
// tried again. An offer with no m=audio section is sent as it is, with a
// WarningOfferWithoutAudio on Streams.OnWarning. A request that was answered or
// is no longer pending returns ErrNotPending.
func (r *JoinRequest) Accept(ctx context.Context, offer, message string) (*ViewerPeer, error) {
	if offer == "" {
		return nil, fmt.Errorf("%w: the offer must be a non-empty SDP string", ErrInvalidOptions)
	}
	s, clid := r.p.s, r.viewer.ClientID
	req := respondRequest(r.p.id, clid, message, offer, true)

	s.mu.Lock()
	if r.state != RequestPending {
		state := r.state
		s.mu.Unlock()

		return nil, fmt.Errorf("%w: it is %s", ErrNotPending, state)
	}
	// Before the request is used up: a too long offer may be shortened and tried again.
	err := assertFits(req)
	if err != nil {
		s.mu.Unlock()

		return nil, err
	}
	if !hasAudioSection(offer) {
		s.warnNoAudioLocked(r.p.id, clid)
	}
	r.state = RequestAccepted
	delete(r.p.pending, clid)
	// Made before the offer goes out: the viewer answers, and the publisher's
	// side starts sending candidates, as soon as it has the offer, and what
	// arrives before this returns waits in the peer for its first handler.
	peer := r.p.openViewerLocked(clid)
	s.mu.Unlock()

	err = s.send(ctx, req, r.p.id)
	if err != nil {
		s.mu.Lock()
		r.state = RequestFailed
		peer.endLocked(PeerClosedEvent{Cause: PeerCauseClosed})
		s.mu.Unlock()

		return nil, err
	}

	return peer, nil
}

// Deny refuses, with a reason the viewer sees, which may be empty. The server
// forgets a refusal, so the viewer may ask again; with Options.RememberDenied,
// requests from this client's unique identifier are then left unanswered.
func (r *JoinRequest) Deny(ctx context.Context, reason string) error {
	s, clid := r.p.s, r.viewer.ClientID
	req := respondRequest(r.p.id, clid, reason, "", false)

	s.mu.Lock()
	if r.state != RequestPending {
		state := r.state
		s.mu.Unlock()

		return fmt.Errorf("%w: it is %s", ErrNotPending, state)
	}
	err := assertFits(req)
	if err != nil {
		s.mu.Unlock()

		return err
	}
	r.state = RequestDenied
	delete(r.p.pending, clid)
	s.mu.Unlock()

	err = s.send(ctx, req, r.p.id)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		r.state = RequestFailed

		return err
	}
	s.rememberLocked(r.viewer)

	return nil
}

// closeLocked is the request not being answered: the viewer withdrew it, or the
// stream ended.
func (r *JoinRequest) closeLocked(state RequestState) {
	if r.state != RequestPending {
		return
	}
	r.state = state
	r.closed.emit(state)
}

// identity asks the server who a client out of view is. A client it cannot name
// is still announced, with no uid.
func (s *Streams) identity(ctx context.Context, clid teamspeak.ClientID) Viewer {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	info, err := s.cmds.GetClientUIDInfoByID(ctx, clid)
	if err != nil {
		return Viewer{ClientID: clid}
	}

	return Viewer{ClientID: clid, UID: info.UID, Nickname: info.Nickname}
}

// deniedLocked reports whether a viewer was denied and is to be left unanswered.
func (s *Streams) deniedLocked(v Viewer) bool {
	return s.remember && v.UID != "" && s.denied.has(v.UID)
}

func (s *Streams) rememberLocked(v Viewer) {
	if s.remember && v.UID != "" {
		s.denied.add(v.UID)
	}
}

// warnNoAudioLocked warns that an offer for a viewer has no audio section.
func (s *Streams) warnNoAudioLocked(id ID, clid teamspeak.ClientID) {
	s.warnings.emit(WarningEvent{
		Code:     WarningOfferWithoutAudio,
		StreamID: id,
		ClientID: clid,
		Message: fmt.Sprintf("the offer for client %d has no m=audio section: "+
			"the TeamSpeak 6 client does not answer an offer without audio, and its Join button then does nothing", clid),
	})
}
