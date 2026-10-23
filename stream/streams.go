package stream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
)

const (
	// publishTimeout is how long Publish waits for the announcement when its
	// context sets no deadline.
	publishTimeout = 10 * time.Second
	// watchTimeout is how long Watch waits for the publisher to decide when its
	// context sets no deadline.
	watchTimeout = 60 * time.Second
	// commandTimeout bounds the commands the package sends on its own account.
	commandTimeout = 10 * time.Second
	// goodbyeTimeout bounds a best-effort command sent as a session ends, which
	// must outlive the call that ended it.
	goodbyeTimeout = 5 * time.Second
	// announceWindow is how long the setupstream of a Publish stays open for the
	// server's answer beyond the caller's own deadline, so that however early
	// the caller gives up, the command listens for at least this long after: a
	// stream announced within it is stopped rather than left running unseen. The
	// announcement followed the command by at most 20 ms in the measurements
	// (five clients publishing ten streams each at once).
	announceWindow = 5 * time.Second
	// goneGrace is how long a cleared client_is_streaming waits before it ends
	// that client's streams. The server clears the flag right before it sends
	// notifystreamstopped, which carries the reason and is the authority; the
	// flag is only a hint.
	goneGrace = 2 * time.Second
	// maxOrphans is how many streams stopped for a Publish that gave up are
	// remembered, to ignore their late rows.
	maxOrphans = 16
	// maxDenied is how many denied clients Options.RememberDenied remembers.
	maxDenied = 1024
)

// Streams does TeamSpeak 6 streams, the screen share, over one client: it
// tells which streams exist, publishes one and watches one. Make it with New
// and end it with Close.
//
// A Streams is safe for concurrent use. Its handlers, and those of every
// object it makes, run one at a time on a goroutine of the Streams' own, in
// the order the events happened; see the package documentation.
type Streams struct {
	host   host
	cmds   *teamspeak.Commands
	logger *slog.Logger

	// conn is the context of the current connection: it ends when the
	// connection does, and with it the lookups and discovery requests made for it.
	conn       context.Context
	cancelConn context.CancelFunc

	// offs remove the subscriptions to the client.
	offs      []func()
	infos     []Info
	asked     map[teamspeak.ClientID]struct{}
	gone      map[teamspeak.ClientID]*time.Timer
	published map[ID]*Published
	watching  map[ID]*watch
	attempts  map[*attempt]struct{}
	denied    *lru[teamspeak.UID]
	orphans   *lru[ID]
	// farewellErrs are the failures of the commands that end a closed
	// Streams' sessions; Close returns them. closeDone is set once it has.
	farewellErrs []error
	// closedViews are the streams whose view is over: what their publisher
	// still sends is not worth a report.
	closedViews *lru[ID]

	started      *topic[Info]
	updated      *topic[Info]
	stopped      *topic[StoppedEvent]
	viewerJoined *topic[ViewerEvent]
	viewerLeft   *topic[ViewerEvent]
	errs         *topic[error]
	warnings     *topic[WarningEvent]

	bus bus
	// wg counts the goroutines Close waits for.
	wg sync.WaitGroup
	// gen counts the connections and closings this Streams has seen. The result
	// of a command sent in an older one is not for the current one.
	gen uint64
	// mu guards everything above it that is not set once. It is never held while
	// calling the client or a handler.
	mu        sync.Mutex
	remember  bool
	closed    bool
	closeDone bool
}

// New returns a Streams over c, which may not have connected yet: nothing is
// sent until it has, and on a server that is not TeamSpeak 6 nothing is ever
// sent. It finds the streams of the clients c sees: a client with
// client_is_streaming set is asked for them with requeststreaminfo, so a stream
// that started before this client came is found too.
//
// New panics if c is nil. Call Close to detach from c.
func New(c *client.Client, opts Options) *Streams {
	if c == nil {
		panic("stream: New needs a client")
	}

	return newStreams(clientHost{c}, opts)
}

func newStreams(h host, opts Options) *Streams {
	s := &Streams{
		host:        h,
		logger:      cmpLogger(opts.Logger),
		remember:    opts.RememberDenied,
		asked:       make(map[teamspeak.ClientID]struct{}),
		gone:        make(map[teamspeak.ClientID]*time.Timer),
		published:   make(map[ID]*Published),
		watching:    make(map[ID]*watch),
		attempts:    make(map[*attempt]struct{}),
		denied:      newLRU[teamspeak.UID](maxDenied),
		orphans:     newLRU[ID](maxOrphans),
		closedViews: newLRU[ID](maxClosedViewers),
	}
	s.cmds = teamspeak.NewCommands(teamspeak.ExecutorFunc(h.Send))
	s.conn, s.cancelConn = context.WithCancel(context.Background())
	s.bus = bus{logger: s.logger, mu: &s.mu}
	s.started = newTopic[Info](&s.bus, "started", false)
	s.updated = newTopic[Info](&s.bus, "updated", false)
	s.stopped = newTopic[StoppedEvent](&s.bus, "stopped", false)
	s.viewerJoined = newTopic[ViewerEvent](&s.bus, "viewer joined", false)
	s.viewerLeft = newTopic[ViewerEvent](&s.bus, "viewer left", false)
	s.errs = newTopic[error](&s.bus, "error", true)
	s.warnings = newTopic[WarningEvent](&s.bus, "warning", true)
	s.started.clone, s.updated.clone = Info.clone, Info.clone
	s.stopped.clone = func(e StoppedEvent) StoppedEvent {
		e.Info = e.Info.clone()

		return e
	}
	s.viewerJoined.clone = func(e ViewerEvent) ViewerEvent {
		e.Info = e.Info.clone()

		return e
	}
	s.viewerLeft.clone = s.viewerJoined.clone

	s.offs = []func(){
		h.OnNotification(s.onNotification),
		h.OnClientEnter(s.onClientEnter),
		h.OnClientUpdated(s.onClientUpdated),
		h.OnClientLeave(s.onClientLeave),
		h.OnConnected(func(client.ConnectedEvent) { s.rescan() }),
		h.OnDisconnected(func(client.DisconnectedEvent) { s.disconnected() }),
	}
	s.rescan()

	return s
}

func cmpLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}

	return l
}

// connState is what the callbacks read of the client before they take the lock.
type connState struct {
	status client.Status
	self   teamspeak.ClientID
	ts6    bool
}

func endedOr(err error, id ID) error {
	if errors.Is(err, errcode.StreamNotFound) {
		return &EndedError{StreamID: id, err: err}
	}

	return err
}

func cmpID(a, b ID) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// attempt is a Publish whose setupstream is out, and what became of it.
type attempt struct {
	pub *Published
	err error
	// done is closed when the outcome is settled.
	done chan struct{}
	// owner is this client's id on the connection the command was sent on.
	owner teamspeak.ClientID
	// abandoned is set once the caller has stopped waiting: an announcement
	// then is not theirs to receive.
	abandoned bool
	settled   bool
}

func (a *attempt) settleLocked(pub *Published, err error) {
	if a.settled {
		return
	}
	a.settled, a.pub, a.err = true, pub, err
	close(a.done)
}

func publishRequest(o PublishOptions) (teamspeak.Request, error) {
	source, accessibility, bitrate := SourceScreen, AccessibilityPublic, 1_500_000
	if o.Source != nil {
		source = *o.Source
	}
	if o.Accessibility != nil {
		accessibility = *o.Accessibility
	}
	if o.Bitrate != nil {
		bitrate = *o.Bitrate
	}
	switch {
	case !source.known():
		return teamspeak.Request{}, fmt.Errorf("%w: unknown source %v", ErrInvalidOptions, source)
	case !accessibility.known():
		return teamspeak.Request{}, fmt.Errorf("%w: unknown accessibility %v", ErrInvalidOptions, accessibility)
	case bitrate < 0 || bitrate > 2_147_483_647:
		return teamspeak.Request{}, fmt.Errorf("%w: the bitrate must be from 0 to 2147483647", ErrInvalidOptions)
	case o.ViewerLimit < 0 || o.ViewerLimit > 65_535:
		return teamspeak.Request{}, fmt.Errorf("%w: the viewer limit must be from 0 to 65535", ErrInvalidOptions)
	}
	req := setupRequest(o.Name, source, bitrate, accessibility, o.ViewerLimit, o.Audio)

	return req, assertFits(req)
}

var errNoStream = errors.New("stream: the server answered setupstream with no stream")

// watch is a join request that has been sent and not yet answered, or the view
// it became.
type watch struct {
	err  error
	view *View
	// done is closed when the outcome is settled.
	done     chan struct{}
	early    []string
	streamer teamspeak.ClientID
	// owner is this client's id on the connection that asked.
	owner teamspeak.ClientID
	// overflowed is whether the overflow of early was reported.
	overflowed bool
	settled    bool
	// closing is set while the view's leave is out, so that the stream still
	// counts as watched until the server has answered.
	closing bool
}

func (w *watch) settleLocked(view *View, err error) {
	if w.settled {
		return
	}
	w.settled, w.view, w.err = true, view, err
	close(w.done)
}

// Supported reports whether the connected server can do streams: a TeamSpeak 6
// server. It is false before the client has connected.
func (s *Streams) Supported() bool {
	return s.host.ServerCapabilities().Family == client.ServerFamilyTS6
}

// List returns the streams known now, in the order they became known. What it
// holds is what this client has heard of: a stream that ends while its
// publisher is out of the channel is reported to nobody there, and stays until
// the connection ends.
func (s *Streams) List() []Info {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Info, len(s.infos))
	for i, info := range s.infos {
		out[i] = info.clone()
	}

	return out
}

// Get returns the stream with this id, if known.
func (s *Streams) Get(id ID) (Info, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if info := s.known(id); info != nil {
		return info.clone(), true
	}

	return Info{}, false
}

// OnStarted registers a handler for a stream becoming known: it started while
// this client could see it, or discovery found it. It returns a function that
// removes the handler.
func (s *Streams) OnStarted(handler func(Info)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.started.on(handler)
}

// OnUpdated registers a handler for what is known of a stream changing. It
// returns a function that removes the handler.
func (s *Streams) OnUpdated(handler func(Info)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.updated.on(handler)
}

// OnStopped registers a handler for a stream ending. It returns a function that
// removes the handler.
func (s *Streams) OnStopped(handler func(StoppedEvent)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.stopped.on(handler)
}

// OnViewerJoined registers a handler for a viewer being accepted into a
// stream. It returns a function that removes the handler.
func (s *Streams) OnViewerJoined(handler func(ViewerEvent)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.viewerJoined.on(handler)
}

// OnViewerLeft registers a handler for a viewer leaving a stream. It returns a
// function that removes the handler.
func (s *Streams) OnViewerLeft(handler func(ViewerEvent)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.viewerLeft.on(handler)
}

// OnError registers a handler for a failure nobody awaits, such as a discovery
// request the server refused. Errors that happen before the first handler is
// registered are kept, up to 256, and delivered to it; until then they are
// logged. It returns a function that removes the handler.
func (s *Streams) OnError(handler func(error)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.errs.on(handler)
}

// OnWarning registers a handler for something the package noticed and let
// through, such as an offer the TeamSpeak 6 client will not answer. Warnings
// are kept for the first handler, as errors are. It returns a function that
// removes the handler.
func (s *Streams) OnWarning(handler func(WarningEvent)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.warnings.on(handler)
}

// Close detaches from the client and ends every session: the streams
// published here, the views and the viewers, each closed once with EndCauseShutdown.
// While the client is connected, each stream published here is stopped
// (stopstream) and each stream watched here is left (joinstreamrequest with
// is_remove=1), as far as the server takes them. Close waits for those commands
// within ctx and returns what failed, joined; a stream or a connection already
// gone is no failure. A Publish still waiting returns ErrClosed, and a stream
// its command started after all is stopped when the server announces it, if the
// client is still connected: Close waits for that too, for as long as the
// command is open (up to the Publish's timeout and five seconds) or ctx lasts,
// and returns the failure of that stop. When the connection is already gone
// nothing is sent, and the server ends the streams itself.
//
// The commands outlive ctx by up to five seconds, so pass a context that is not
// already cancelled, such as context.WithoutCancel(ctx), when closing because a
// context was. Close is idempotent; after it every call returns ErrClosed.
func (s *Streams) Close(ctx context.Context) error {
	connected := s.host.Status() == client.StatusConnected

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return nil
	}
	s.closed = true
	offs := s.offs
	s.offs = nil
	goodbyes := s.resetLocked(EndCauseShutdown, connState{})
	s.denied.clear()
	if connected {
		base := context.WithoutCancel(ctx)
		for _, bye := range goodbyes {
			s.wg.Go(func() {
				byeCtx, cancel := context.WithTimeout(base, goodbyeTimeout)
				defer cancel()
				err := bye(byeCtx)
				if err != nil {
					s.farewell(err)
				}
			})
		}
	}
	s.mu.Unlock()

	for _, off := range offs {
		off()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	var waitErr error
	select {
	case <-done:
	case <-ctx.Done():
		waitErr = fmt.Errorf("stream: closing: %w", ctx.Err())
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeDone = true

	return errors.Join(append(slices.Clone(s.farewellErrs), waitErr)...)
}

// Publish starts a stream and returns it once the server has announced it. The
// call sends setupstream with all seven parameters, in peer to peer mode, the
// only mode the server allows. A client may publish several streams, and
// several calls may be in flight: the server echoes each command's
// return_code on the announcement of the stream it started, so each call
// receives its own, whatever the names.
//
// Publish waits until ctx ends, or ten seconds without a deadline. When it
// gives up, the command is kept open for five seconds after that moment,
// whatever ctx says, and the stream it announces within is stopped; one
// announced later cannot be told from any other of this client's, and is left
// to List. The command is sent even if ctx ends before it leaves the flood
// throttle, and then stopped the same way, so other clients may see the stream
// start and stop.
//
// Publish returns an *UnsupportedError, without sending anything, on a server
// that is not TeamSpeak 6, ErrInvalidOptions for an option that is out of
// range, and the server's refusal as a *teamspeak.ServerError.
func (s *Streams) Publish(ctx context.Context, opts PublishOptions) (*Published, error) {
	err := s.usable()
	if err != nil {
		return nil, err
	}
	req, err := publishRequest(opts)
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err != nil {
		return nil, err
	}

	waitCtx, cancel := withDefaultTimeout(ctx, publishTimeout)
	defer cancel()
	att, err := s.startAttempt(ctx, waitCtx, req)
	if err != nil {
		return nil, err
	}

	return s.await(waitCtx, att)
}

// Watch asks to watch a stream and returns the view once the publisher lets
// this client in, with the SDP offer in it. The stream is one this client has
// heard of, as List and OnStarted report them; for one it has not, set
// WatchOptions.ClientID to the publisher.
//
// Watch waits until ctx ends, or sixty seconds without a deadline. It returns
// a *JoinDeniedError when the publisher refuses, an *EndedError when the id is
// not one this client has heard of and no ClientID was given, or the stream ends
// first (or is gone: error 5635), an *UnsupportedError on a server without
// streams, a *TransportUnsupportedError, before sending anything, for a stream
// whose Info.Transport the server reported and is not TransportP2P (one with no
// reported transport is tried), ErrAlreadyWatching for a stream already asked
// for, and the server's own error otherwise, among them 5638
// (errcode.StreamAlreadyJoined) when this client already asked. When the wait
// ends with ctx, the request is withdrawn.
func (s *Streams) Watch(ctx context.Context, id ID, opts WatchOptions) (*View, error) {
	err := s.usable()
	if err != nil {
		return nil, err
	}
	streamer := opts.ClientID
	s.mu.Lock()
	info := s.known(id)
	var transport *Transport
	if info != nil {
		transport = clonePtr(info.Transport)
		if streamer == 0 {
			streamer = info.ClientID
		}
	}
	s.mu.Unlock()
	if info == nil && streamer == 0 {
		return nil, &EndedError{StreamID: id}
	}
	if transport != nil && *transport != TransportP2P {
		return nil, &TransportUnsupportedError{StreamID: id, Transport: *transport}
	}

	return s.watch(ctx, id, streamer, opts)
}
