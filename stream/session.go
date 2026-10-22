package stream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/notify"
)

// usable returns why streams cannot be used now: the Streams is closed, or the
// server is not TeamSpeak 6.
func (s *Streams) usable() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if caps := s.host.ServerCapabilities(); caps.Family != client.ServerFamilyTS6 {
		return &UnsupportedError{Family: caps.Family, Version: caps.Version}
	}

	return nil
}

func (s *Streams) observe() connState {
	return connState{
		self:   s.host.ClientID(),
		status: s.host.Status(),
		ts6:    s.host.ServerCapabilities().Family == client.ServerFamilyTS6,
	}
}

// spawnLocked runs fn on a goroutine that Close waits for. It reports false,
// and runs nothing, once the Streams is closed. fn must end on its own: every
// one is bounded by a deadline or by the connection's context.
func (s *Streams) spawnLocked(fn func()) bool {
	if s.closed {
		return false
	}
	s.wg.Go(fn)

	return true
}

// reportLocked tells OnError of a failure nobody awaits. With no handler yet,
// it is logged as well, since the event is kept for a handler that may never
// come.
func (s *Streams) reportLocked(err error) {
	if !s.errs.attached {
		s.logger.Warn("stream: unhandled error", slog.Any("error", err))
	}
	s.errs.emit(err)
}

func (s *Streams) report(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reportLocked(err)
}

// send sends a stream command. A stream the server does not know is an
// *EndedError.
func (s *Streams) send(ctx context.Context, req teamspeak.Request, id ID) error {
	err := assertFits(req)
	if err != nil {
		return err
	}
	_, err = s.host.Send(ctx, req)

	return endedOr(err, id)
}

// stopStream sends stopstream; a stream the server no longer knows is stopped
// already.
func (s *Streams) stopStream(ctx context.Context, id ID, reason uint32) error {
	_, err := s.host.Send(ctx, stopRequest(id, reason))
	if errors.Is(err, errcode.StreamNotFound) {
		return nil
	}

	return err
}

// leave tells the server this client stops watching; a stream or connection
// already gone is no failure.
func (s *Streams) leave(ctx context.Context, id ID, streamer teamspeak.ClientID) error {
	err := s.send(ctx, joinRequest(id, streamer, "", true), id)
	var ended *EndedError
	if errors.As(err, &ended) || isGone(err) {
		return nil
	}

	return err
}

// farewell notes a failure of a command that ends a session of a Streams that
// is closed, for Close to return; if Close has returned already it is logged.
func (s *Streams) farewell(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closeDone {
		s.logger.Warn("stream: a command after Close failed", slog.Any("error", err))

		return
	}
	s.farewellErrs = append(s.farewellErrs, err)
}

// goodbye runs a best-effort command for a session that is over: the result is
// reported, not returned, and the command outlives the call that caused it by
// up to goodbyeTimeout.
func (s *Streams) goodbye(base context.Context, what string, fn func(context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.goodbyeLocked(base, what, fn)
}

func (s *Streams) goodbyeLocked(base context.Context, what string, fn func(context.Context) error) {
	s.spawnLocked(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(base), goodbyeTimeout)
		defer cancel()
		err := fn(ctx)
		if err != nil && !isGone(err) {
			s.report(fmt.Errorf("stream: %s: %w", what, err))
		}
	})
}

// known returns the stream with this id, or nil. The pointer is good until the
// lock is released.
func (s *Streams) known(id ID) *Info {
	for i := range s.infos {
		if s.infos[i].ID == id {
			return &s.infos[i]
		}
	}

	return nil
}

// learnLocked records what is known of a stream and reports it; knowing it
// again changes nothing.
func (s *Streams) learnLocked(info Info) {
	if s.orphans.has(info.ID) {
		return
	}
	prev := s.known(info.ID)
	switch {
	case prev == nil:
		s.infos = append(s.infos, info)
		s.started.emit(info)
	case !prev.equal(info):
		*prev = info
		s.updated.emit(info)
	default:
		*prev = info
	}
}

// endLocked is a stream over, for whatever hangs on it; it is forgotten.
func (s *Streams) endLocked(id ID, reason uint32, cause EndCause) {
	var info *Info
	if i := slices.IndexFunc(s.infos, func(x Info) bool { return x.ID == id }); i >= 0 {
		removed := s.infos[i]
		info = &removed
		s.infos = slices.Delete(s.infos, i, i+1)
		if !slices.ContainsFunc(s.infos, func(x Info) bool { return x.ClientID == removed.ClientID }) {
			s.cancelGoneLocked(removed.ClientID)
		}
	}

	if p := s.published[id]; p != nil {
		delete(s.published, id)
		p.finishLocked(EndedEvent{Cause: cause, Reason: reason})
	}
	if w := s.watching[id]; w != nil {
		delete(s.watching, id)
		if w.view != nil {
			s.closedViews.add(id)
			w.view.endLocked(PeerClosedEvent{Cause: PeerCauseStopped, Reason: reason})
		} else {
			w.settleLocked(nil, &EndedError{StreamID: id})
		}
	}
	if info != nil {
		s.stopped.emit(StoppedEvent{Info: *info, Cause: cause, Reason: reason})
	}
}

// resetLocked ends the sessions of a connection that ended, or of everything
// when the Streams closed (EndCauseShutdown), and forgets. For the latter it
// returns the commands that tell the server.
//
// The client delivers its disconnected event after the fact, and a Publish or a
// Watch may have started on the next connection by then, so a disconnect ends
// only what was started under another client id than the connection that is up
// now, c. Everything else a reset forgets reaches this Streams through the
// client's events, which are delivered in order, so a lagging one does not
// reach what the next connection made.
func (s *Streams) resetLocked(cause EndCause, c connState) []func(context.Context) error {
	var goodbyes []func(context.Context) error
	err := teamspeak.ErrNotConnected
	if cause == EndCauseShutdown {
		err = ErrClosed
		goodbyes = s.farewellsLocked()
	}
	survives := func(owner teamspeak.ClientID) bool {
		return cause == EndCauseDisconnected && c.status == client.StatusConnected && owner != 0 && owner == c.self
	}
	s.gen++
	s.cancelConn()
	if cause != EndCauseShutdown {
		s.conn, s.cancelConn = context.WithCancel(context.Background())
	}
	for att := range s.attempts {
		if !survives(att.owner) {
			att.settleLocked(nil, err)
			delete(s.attempts, att)
		}
	}
	s.orphans.clear()
	for _, t := range s.gone {
		t.Stop()
	}
	clear(s.gone)
	clear(s.asked)
	s.infos = nil

	s.endSessionsLocked(cause, err, survives)

	return goodbyes
}

// endSessionsLocked ends the published streams and the watches that do not
// survive, with cause; a watch still waiting fails with err.
func (s *Streams) endSessionsLocked(cause EndCause, err error, survives func(teamspeak.ClientID) bool) {
	published := slices.SortedFunc(maps.Values(s.published), func(a, b *Published) int { return cmpID(a.id, b.id) })
	for _, p := range published {
		if !survives(p.owner) {
			delete(s.published, p.id)
			p.finishLocked(EndedEvent{Cause: cause})
		}
	}
	for _, id := range slices.SortedFunc(maps.Keys(s.watching), cmpID) {
		w := s.watching[id]
		if survives(w.owner) {
			continue
		}
		delete(s.watching, id)
		if w.view != nil {
			w.view.endLocked(PeerClosedEvent{Cause: cause.peer()})
		} else {
			w.settleLocked(nil, err)
		}
	}
}

// farewellsLocked are the commands that tell the server this Streams is done: it
// stops what it published and leaves what it watched.
func (s *Streams) farewellsLocked() []func(context.Context) error {
	var goodbyes []func(context.Context) error
	for _, p := range slices.SortedFunc(maps.Values(s.published), func(a, b *Published) int { return cmpID(a.id, b.id) }) {
		goodbyes = append(goodbyes, func(ctx context.Context) error { return s.stopStream(ctx, p.id, 0) })
	}
	for id, w := range s.watching {
		// A view being closed has its leave out already.
		if !w.closing {
			goodbyes = append(goodbyes, func(ctx context.Context) error { return s.leave(ctx, id, w.streamer) })
		}
	}

	return goodbyes
}

// disconnected is the connection ending: nothing is sent, the server ends the
// streams itself.
func (s *Streams) disconnected() {
	c := s.observe()

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed {
		s.resetLocked(EndCauseDisconnected, c)
	}
}

// forgetLocked is a client that no longer streams, or came into view not
// streaming: its streams are over unless the server's stop follows.
func (s *Streams) forgetLocked(clid teamspeak.ClientID) {
	delete(s.asked, clid)
	if s.gone[clid] != nil || !slices.ContainsFunc(s.infos, func(i Info) bool { return i.ClientID == clid }) {
		return
	}
	// The stop notification may follow at once, with the reason: it wins.
	s.gone[clid] = time.AfterFunc(goneGrace, func() { s.goneFired(clid) })
}

func (s *Streams) goneFired(clid teamspeak.ClientID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A timer that was stopped can still fire; whether this one is current is
	// settled here, under the lock, by whether the client is still waiting.
	if s.gone[clid] == nil || s.closed {
		return
	}
	delete(s.gone, clid)
	for _, info := range slices.Clone(s.infos) {
		if info.ClientID == clid {
			s.endLocked(info.ID, 0, EndCauseGone)
		}
	}
}

func (s *Streams) cancelGoneLocked(clid teamspeak.ClientID) {
	if t := s.gone[clid]; t != nil {
		t.Stop()
		delete(s.gone, clid)
	}
}

// rescan asks for the streams of the clients in view that stream. It runs when
// the Streams is made and when the client connects, since the clients may be
// announced while the connection is still being made.
func (s *Streams) rescan() {
	entries := s.host.Entries()
	c := s.observe()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range entries {
		if e.IsStreaming != nil && *e.IsStreaming {
			s.cancelGoneLocked(e.ID)
			s.discoverLocked(e.ID, c)
		}
	}
}

// discoverLocked asks for the streams of a client that says it streams, once.
// The answer is one notifystreaminfo per stream, which onNotification takes.
func (s *Streams) discoverLocked(clid teamspeak.ClientID, c connState) {
	if _, asked := s.asked[clid]; asked || clid == 0 || clid == c.self || !c.ts6 || c.status != client.StatusConnected {
		return
	}
	ctx, gen := s.conn, s.gen
	if s.spawnLocked(func() { s.askInfo(ctx, gen, clid) }) {
		s.asked[clid] = struct{}{}
	}
}

func (s *Streams) askInfo(ctx context.Context, gen uint64, clid teamspeak.ClientID) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	_, err := s.host.Send(ctx, infoRequest(clid))
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// The connection changed: the new one asks again for itself.
	if s.gen != gen {
		return
	}
	// Asked again the next time the client is seen to stream.
	delete(s.asked, clid)
	if !isGone(err) {
		s.reportLocked(fmt.Errorf("stream: requeststreaminfo for client %d: %w", clid, err))
	}
}

func (s *Streams) onClientEnter(e client.ClientEnterEvent) {
	if e.IsStreaming == nil {
		return
	}
	c := s.observe()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	if *e.IsStreaming {
		s.cancelGoneLocked(e.ID)
		s.discoverLocked(e.ID, c)
	} else {
		// Coming into view not streaming: whatever was known of it is over.
		s.forgetLocked(e.ID)
	}
}

func (s *Streams) onClientUpdated(e client.ClientUpdatedEvent) {
	streaming := e.Changes.IsStreaming
	if streaming == nil {
		return
	}
	c := s.observe()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	// The flag clears with the last stream; a stream that starts later is looked up again.
	if *streaming {
		s.cancelGoneLocked(e.ClientID)
		s.discoverLocked(e.ClientID, c)
	} else {
		s.forgetLocked(e.ClientID)
	}
}

func (s *Streams) onClientLeave(e client.ClientLeaveEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	delete(s.asked, e.ClientID)
	// A request nobody answered goes with the client: its id may be reused.
	for _, p := range s.published {
		p.dropPendingLocked(e.ClientID)
	}
}

func (s *Streams) onNotification(e client.NotificationEvent) {
	// What the handlers below need of the client is read here, before the lock.
	var (
		self  teamspeak.ClientID
		entry *teamspeak.ClientEntry
	)
	switch e.Name {
	case notify.StreamClientLeft:
		self = s.host.ClientID()
	case notify.JoinStreamRequest:
		if clid := clidOf(e.Params); clid != 0 && e.Params["is_remove"] != "1" {
			if found, ok := s.host.Entry(clid); ok {
				entry = &found
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed {
		s.dispatchLocked(e.Name, e.Params, self, entry)
	}
}

func (s *Streams) dispatchLocked(
	name string, params map[string]string, self teamspeak.ClientID, entry *teamspeak.ClientEntry,
) {
	switch name {
	case notify.StreamStarted, notify.StreamInfo:
		s.onInfoLocked(params)
	case notify.JoinStreamRequest:
		s.onJoinRequestLocked(params, entry)
	case notify.RespondJoinStreamRequest:
		s.onRespondLocked(params)
	case notify.StreamSignaling:
		s.onSignalingLocked(params)
	case notify.StreamClientJoined:
		s.onClientJoinedLocked(params)
	case notify.StreamClientLeft:
		s.onClientLeftLocked(params, self)
	case notify.StreamStopped:
		if id := ID(params["id"]); id != "" {
			s.endLocked(id, reasonOf(params), EndCauseServer)
			s.orphans.remove(id)
		}
	}
}

func (s *Streams) onClientJoinedLocked(params map[string]string) {
	clid := clidOf(params)
	if info := s.known(ID(params["id"])); info != nil && clid != 0 {
		s.viewerJoined.emit(ViewerEvent{Info: info.clone(), ClientID: clid})
	}
}

// onInfoLocked takes an announcement or a reply to requeststreaminfo. The
// publisher's own announcement is no different: Publish finds it by the answer
// to its command, and this is told of it the same way, in either order.
func (s *Streams) onInfoLocked(params map[string]string) {
	// The empty notifystreaminfo for a client that streams nothing has no id.
	if info, ok := infoFrom(params, s.known(ID(params["id"]))); ok {
		s.learnLocked(info)
	}
}

func (s *Streams) onJoinRequestLocked(params map[string]string, entry *teamspeak.ClientEntry) {
	p := s.published[ID(params["id"])]
	clid := clidOf(params)
	if p == nil || clid == 0 {
		return
	}
	if params["is_remove"] == "1" {
		p.viewerGoneLocked(clid)

		return
	}
	p.requestLocked(clid, params["msg"], entry)
}

func (s *Streams) onClientLeftLocked(params map[string]string, self teamspeak.ClientID) {
	id := ID(params["id"])
	clid := clidOf(params)
	if clid == 0 {
		return
	}
	if p := s.published[id]; p != nil {
		p.viewerGoneLocked(clid)
	}
	// Others leaving is not this view's end; this client leaving is.
	if w := s.watching[id]; w != nil && w.view != nil && clid == self {
		w.view.endLocked(PeerClosedEvent{Cause: PeerCauseLeft})
	}
	if info := s.known(id); info != nil {
		s.viewerLeft.emit(ViewerEvent{Info: info.clone(), ClientID: clid})
	}
}

func (s *Streams) onSignalingLocked(params map[string]string) {
	id := ID(params["id"])
	clid := clidOf(params)
	text := params["json"]
	if p := s.published[id]; p != nil && p.signalLocked(clid, text) {
		return
	}
	w := s.watching[id]
	switch {
	case w != nil && w.view != nil:
		w.view.deliverLocked(text)
	case w != nil:
		w.early = append(w.early, text)
		if len(w.early) > maxKept {
			// The oldest goes, as from a peer's queue, and the first time is reported.
			w.early = slices.Delete(w.early, 0, 1)
			if !w.overflowed {
				w.overflowed = true
				s.reportLocked(fmt.Errorf("%w signalling message of stream %s: %d are waiting for the publisher's answer",
					errDropped, id, maxKept))
			}
		}
	case s.closedViews.has(id):
		// The server cannot remove a viewer, so a publisher may keep sending to
		// a view that is over.
	default:
		s.reportLocked(fmt.Errorf("%w: stream %s, client %d", errNoSession, id, clid))
	}
}

// finishAttempt settles a Publish with the answer to its setupstream, or stops
// the stream the answer names when nobody is waiting for it. It runs on the
// goroutine that sent the command.
func (s *Streams) finishAttempt(base context.Context, att *attempt, rows []map[string]string, err error) {
	s.mu.Lock()
	delete(s.attempts, att)
	var (
		info Info
		have bool
	)
	for _, row := range rows {
		if found, ok := infoFrom(row, s.known(ID(row["id"]))); ok {
			info, have = found, true
		}
	}
	var stop bool
	closed := s.closed
	switch {
	case att.settled:
		// The connection ended or the Streams closed while the command was out.
		// After a close the client is still connected and the server still runs
		// the stream; after a disconnect it ended with the session.
		stop = have && s.closed
	case err != nil:
		att.settleLocked(nil, err)
	case !have:
		att.settleLocked(nil, errNoStream)
	case att.abandoned:
		s.orphanLocked(info)
		att.settled = true
		stop = true
	default:
		att.settleLocked(s.adoptLocked(info, att.owner), nil)
	}
	s.mu.Unlock()

	if stop {
		s.stopOrphan(base, info.ID, closed)
	}
}

// stopOrphan stops a stream nobody is waiting for, if the client is still
// connected. A failure goes to Close, which waits for this, or else to OnError.
func (s *Streams) stopOrphan(base context.Context, id ID, closed bool) {
	if s.host.Status() != client.StatusConnected {
		return
	}
	ctx, cancel := context.WithTimeout(base, goodbyeTimeout)
	defer cancel()
	err := s.stopStream(ctx, id, 0)
	if err == nil || isGone(err) {
		return
	}
	err = fmt.Errorf("stream: stopstream for stream %s: %w", id, err)
	if closed {
		s.farewell(err)

		return
	}
	s.report(err)
}

// adoptLocked is the stream of a Publish that is waiting: learned if the
// notification has not been, and published.
func (s *Streams) adoptLocked(info Info, owner teamspeak.ClientID) *Published {
	s.learnLocked(info)
	p := s.published[info.ID]
	if p == nil {
		initial := info
		if known := s.known(info.ID); known != nil {
			initial = *known
		}
		p = newPublished(s, initial.clone())
		p.owner = owner
		s.published[info.ID] = p
	}

	return p
}

// orphanLocked is a stream nobody is waiting for: it is reported over if it was
// reported started, and its late rows are ignored.
func (s *Streams) orphanLocked(info Info) {
	s.orphans.add(info.ID)
	s.endLocked(info.ID, 0, EndCauseStopped)
}

func (s *Streams) watch(ctx context.Context, id ID, streamer teamspeak.ClientID, opts WatchOptions) (*View, error) {
	self := s.host.ClientID()
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()

		return nil, ErrClosed
	case s.watching[id] != nil:
		s.mu.Unlock()

		return nil, fmt.Errorf("%w %s", ErrAlreadyWatching, id)
	}
	err := ctx.Err()
	if err != nil {
		s.mu.Unlock()

		return nil, err
	}
	w := &watch{streamer: streamer, owner: self, done: make(chan struct{})}
	s.watching[id] = w
	s.closedViews.remove(id)
	s.mu.Unlock()

	view, withdraw, err := s.ask(ctx, w, id, opts.Message)
	if err != nil && withdraw {
		s.goodbye(ctx, "withdrawing a request to watch stream "+string(id), func(ctx context.Context) error {
			return s.leave(ctx, id, streamer)
		})
	}

	return view, err
}

// ask sends the join request and waits for the publisher's answer. When it
// fails, the request is gone from s.watching by the time it returns, decided
// under the lock, so that an answer that comes after finds nothing to join. It
// also reports whether the request may have reached the server and so is to be
// withdrawn: not when the server answered, or the command never left the
// flood throttle.
func (s *Streams) ask(ctx context.Context, w *watch, id ID, message string) (*View, bool, error) {
	err := s.send(ctx, joinRequest(id, w.streamer, message, false), id)
	if err == nil {
		var cancel context.CancelFunc
		ctx, cancel = withDefaultTimeout(ctx, watchTimeout)
		defer cancel()
		select {
		case <-w.done:
		case <-ctx.Done():
			err = fmt.Errorf("%s: %w", commands.JoinStreamRequest, ctx.Err())
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if w.settled {
		// The stream's end can be heard while the join request is being sent;
		// the server's own refusal, when that is what came back, says more.
		if _, ended := errors.AsType[*EndedError](err); ended && w.view == nil {
			return nil, false, err
		}

		return w.view, false, w.err
	}
	// Abandoned here, in the same breath as the decision: from now on an
	// answer finds no watch.
	delete(s.watching, id)
	w.settled = true

	return nil, isContextError(err) && mayHaveBeenSent(err), err
}

// isContextError reports whether err is the end of a context.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// mayHaveBeenSent reports whether a command that failed with the end of a
// context may have reached the server. The client returns the context's own
// error, unwrapped, for a command that never left its flood throttle, and wraps
// it with the command's name once the command was sent and its answer awaited.
func mayHaveBeenSent(err error) bool {
	//nolint:errorlint,err113 // the error itself, not what it wraps, says the command was never sent
	return err != context.Canceled && err != context.DeadlineExceeded
}

func (s *Streams) onRespondLocked(params map[string]string) {
	id := ID(params["id"])
	w := s.watching[id]
	if w == nil || w.settled {
		return
	}
	if params["decision"] != "1" {
		delete(s.watching, id)
		w.settleLocked(nil, &JoinDeniedError{StreamID: id, Message: params["msg"]})

		return
	}
	offer := params["offer"]
	if offer == "" {
		delete(s.watching, id)
		w.settleLocked(nil, errNoOffer)
		streamer := w.streamer
		s.goodbyeLocked(s.conn, "leaving stream "+string(id), func(ctx context.Context) error {
			return s.leave(ctx, id, streamer)
		})

		return
	}
	view := &View{Peer: newPeer(s, nil, id, w.streamer), offer: offer}
	w.view = view
	// What the publisher sent right behind the offer, ahead of the application's first call.
	for _, text := range w.early {
		view.deliverLocked(text)
	}
	w.early = nil
	w.settleLocked(view, nil)
}

// withDefaultTimeout returns ctx, or a child of it that ends after d when ctx
// has no deadline of its own.
func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, d)
}

// startAttempt sends the setupstream of a Publish and registers the attempt
// for its answer.
//
// The command is the application's to cancel only until it is sent: after that
// the answer is what says which stream it started, and the stream is stopped if
// nobody waits for it. So it runs on a context that survives ctx (keeping its
// values) for the wait and the announcement window, and its goroutine ends when
// that context does.
func (s *Streams) startAttempt(ctx, waitCtx context.Context, req teamspeak.Request) (*attempt, error) {
	att := &attempt{done: make(chan struct{}), owner: s.host.ClientID()}
	deadline, _ := waitCtx.Deadline()
	base := context.WithoutCancel(ctx)
	sendCtx, cancel := context.WithTimeout(base, time.Until(deadline)+announceWindow)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close waits for the goroutine, and so for the stop it sends if the stream
	// turns up after all.
	started := s.spawnLocked(func() {
		defer cancel()
		rows, err := s.host.Send(sendCtx, req)
		s.finishAttempt(base, att, rows, err)
	})
	if !started {
		cancel()

		return nil, ErrClosed
	}
	s.attempts[att] = struct{}{}

	return att, nil
}

// await waits for the answer to a Publish. A caller that stops waiting leaves
// the attempt abandoned, unless the answer landed meanwhile, in which case it
// gets the stream: nothing is left running unseen.
func (s *Streams) await(waitCtx context.Context, att *attempt) (*Published, error) {
	select {
	case <-att.done:
	case <-waitCtx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !att.settled {
		att.abandoned = true

		return nil, fmt.Errorf("%s: %w", commands.SetupStream, waitCtx.Err())
	}

	return att.pub, att.err
}
