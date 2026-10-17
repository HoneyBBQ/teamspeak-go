package serverquery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/eventbus"
	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// The session: everything a connection needs that is not part of the
// public surface — opening the transport, the handshake, reading what the
// server says about itself, and reading a notification into an event.

// buildMiddlewareChains wraps the typed commands in the configured
// middleware. It runs once, in New: the chain is read on every command, so
// changing it afterwards would race with them.
func (c *Client) buildMiddlewareChains() {
	c.executor = teamspeak.ExecutorFunc(c.sendRequest)
	for _, middleware := range slices.Backward(c.cmdMiddlewares) {
		c.executor = middleware(c.executor)
	}
}

// Option configures a Client. Build one with the With functions.
//
// Experimental: this package may change in a minor release.
type Option interface {
	apply(c *Client)
}

type optionFunc func(*Client)

func (f optionFunc) apply(c *Client) { f(c) }

// sendRequest is the executor the command middleware wraps, and the end of the
// chain: it sends the request on the engine. Send calls the chain, so this must
// not call Send back.
func (c *Client) sendRequest(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	eng := c.currentEngine()
	if eng == nil {
		return nil, teamspeak.ErrNotConnected
	}

	return eng.Send(ctx, req)
}

// Send executes a typed command; it is the Executor the typed commands run on,
// through the command middleware.
//
// A channel password goes as it is: ServerQuery takes the password itself and
// hashes it server-side, where the voice protocol wants the hash.
//
// Experimental: this package may change in a minor release.
func (c *Client) Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
	return c.executor.Send(ctx, req)
}

// Exec sends a raw command line and returns the rows that answer it: the
// escape hatch for a command the typed methods do not cover. The line is sent
// as given, so its values must already be escaped (commands.Escape).
//
// Without a deadline on ctx the command gives up after ten seconds.
//
// Experimental: this package may change in a minor release.
func (c *Client) Exec(ctx context.Context, line string) ([]map[string]string, error) {
	eng := c.currentEngine()
	if eng == nil {
		return nil, teamspeak.ErrNotConnected
	}

	return eng.Exec(ctx, line)
}

// Status reports the current connection state.
//
// Experimental: this package may change in a minor release.
func (c *Client) Status() teamspeak.Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.status
}

// ServerFamily reports the server generation, as the version command answered
// it. Before connecting, and when the server names a version this module does
// not recognise, it is ServerFamilyUnknown.
//
// Experimental: this package may change in a minor release.
func (c *Client) ServerFamily() teamspeak.ServerFamily {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.family
}

// String describes the client by its transport and status. It never includes
// a password or an api key: the dialer's own String omits both.
//
// Experimental: this package may change in a minor release.
func (c *Client) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return fmt.Sprintf("serverquery client on %s (%s)", c.dialer, c.status)
}

// GoString is String, so %#v does not reach a password either.
func (c *Client) GoString() string { return c.String() }

// LogValue describes the client to log/slog as String does.
//
// Experimental: this package may change in a minor release.
func (c *Client) LogValue() slog.Value {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slog.GroupValue(
		slog.String("transport", c.dialer.String()),
		slog.String("status", c.status.String()),
	)
}

// currentEngine returns the engine of the current connection, or nil.
func (c *Client) currentEngine() *engine.Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.engine
}

// Connect opens the connection and returns once the session is ready: the
// transport's dial, the query login where the transport needs one, the server
// `use` selects, the nickname, the version, and the notification categories
// this transport can deliver.
//
// A failed attempt returns its cause, such as the server's error for a refused
// login. Connect does not retry; WithReconnect retries a connection that drops
// after it was established.
//
// Called while already connected or connecting, it returns
// teamspeak.ErrAlreadyConnected. Register OnConnected before Connect to be
// sure to hear it: the event is queued as the connection becomes ready.
//
// Experimental: this package may change in a minor release.
func (c *Client) Connect(ctx context.Context) error {
	return c.connect(ctx, connectKind{fromCaller: true})
}

// connectKind is what a Connect call is: the caller's, or a reconnect loop's.
type connectKind struct {
	// fromCaller is true for Connect. A caller's Connect clears an earlier
	// Disconnect; a reconnect attempt gives up when it finds one, rather than
	// undoing it.
	fromCaller bool
}

// connect runs one connection attempt.
func (c *Client) connect(ctx context.Context, kind connectKind) error {
	c.mu.Lock()
	if c.status != teamspeak.StatusDisconnected {
		c.mu.Unlock()

		return teamspeak.ErrAlreadyConnected
	}
	if kind.fromCaller {
		// A caller's Connect undoes an earlier Disconnect and takes the slot
		// back from a retry loop waiting out its delay.
		c.setStoppedLocked(false)
	} else if c.stopped {
		c.mu.Unlock()

		return errStopped
	}
	c.status = teamspeak.StatusConnecting
	dialer, logger := c.dialer, c.logger
	server, nickname := c.server, c.nickname
	categories, registerEvents := c.categories, c.registerEvents
	c.mu.Unlock()

	// A transport that cannot deliver notifications is not asked for them: the
	// server refuses the command there (WebQuery answers 5120, "out of scope"),
	// which would fail a connect that has no use for events in the first place.
	if !dialer.SupportsNotifications() {
		categories, registerEvents = nil, false
	}

	logger.InfoContext(ctx, "connecting",
		slog.String("transport", dialer.String()), slog.Bool("reconnect", !kind.fromCaller))

	eng, err := c.open(ctx, dialer)
	if err != nil {
		return c.failAttempt(dialer, err, !kind.fromCaller)
	}

	err = c.handshake(ctx, eng, handshakeOptions{
		login:          dialer.credentials(),
		server:         server,
		nickname:       nickname,
		categories:     categories,
		registerEvents: registerEvents,
	})
	if err != nil {
		_ = eng.Close()

		return c.failAttempt(dialer, err, !kind.fromCaller)
	}

	c.mu.Lock()
	c.engine = eng
	c.status = teamspeak.StatusConnected
	c.mu.Unlock()

	emit(c, &c.onConnected, "Connected", teamspeak.ConnectedEvent{Reconnected: !kind.fromCaller})

	return nil
}

// guestRefusal says so when a guest connection failed because the server offers
// no guest access: the SSH login of the user "guest" was refused, or WebQuery
// answered a request without an api key with 5124. The server's own error stays
// in the chain. Any other failure, and any other dialer, is returned as it is.
func guestRefusal(dialer Dialer, err error) error {
	switch d := dialer.(type) {
	case sshDialer:
		if d.guest && errors.Is(err, ErrAuth) {
			return fmt.Errorf("%w: %w", ErrNoGuestAccess, err)
		}
	case webDialer:
		if d.guest && errors.Is(err, errcode.APIKeyMissing) {
			return fmt.Errorf("%w: %w", ErrNoGuestAccess, err)
		}
	}

	return err
}

// failAttempt ends a failed connection attempt and returns the error to report,
// which says so when the failure was a guest connection with nothing to be a
// guest of.
func (c *Client) failAttempt(dialer Dialer, err error, reconnect bool) error {
	err = guestRefusal(dialer, err)
	c.finishAttempt(err, reconnect)

	return err
}

// setStoppedLocked records a Disconnect, or its undoing by a caller's Connect,
// and keeps the stop channel in step. The caller holds c.mu.
func (c *Client) setStoppedLocked(stopped bool) {
	if stopped == c.stopped {
		return
	}
	c.stopped = stopped
	if stopped {
		close(c.stop)
	} else {
		c.stop = make(chan struct{})
	}
}

// stopChan returns the channel closed when the client is stopped. A Connect
// that clears the stop replaces it, so a waiter takes it once, when it starts
// to wait.
func (c *Client) stopChan() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.stop
}

// handshakeOptions are what Connect applies once the transport is open.
type handshakeOptions struct {
	login          *login
	server         *serverTarget
	nickname       string
	categories     []Category
	registerEvents bool
}

// open dials and wires a fresh engine to this client.
func (c *Client) open(ctx context.Context, dialer Dialer) (*engine.Client, error) {
	transport, err := dialer.open(ctx)
	if err != nil {
		return nil, err
	}

	eng := engine.New(transport)
	eng.OnNotification = c.handleNotification
	eng.OnClosed = c.handleClosed

	c.mu.Lock()
	c.transport = transport
	c.mu.Unlock()

	return eng, nil
}

// handshake runs everything a query session needs once the transport is open,
// in the order the server requires: the login, then the server, then the
// nickname — which the server refuses before a server is selected — then the
// version, the client list the events draw their extra fields from, and the
// notification categories.
func (c *Client) handshake(ctx context.Context, eng *engine.Client, opts handshakeOptions) error {
	err := c.authenticate(ctx, eng, opts)
	if err != nil {
		return err
	}

	family, err := c.readVersion(ctx, eng)
	if err != nil {
		return c.wrapHandshake("version", err)
	}

	err = c.readSelf(ctx, eng)
	if err != nil {
		return c.wrapHandshake("whoami", err)
	}

	if opts.registerEvents {
		err = c.registerCategories(ctx, eng, opts.categories)
		if err != nil {
			return err
		}
	}

	c.mu.Lock()
	c.family = family
	c.mu.Unlock()

	return nil
}

// authenticate runs the three commands that establish who this session is, in
// the order the server requires: the login, the server, then the nickname —
// which the server refuses before a server is selected.
func (c *Client) authenticate(ctx context.Context, eng *engine.Client, opts handshakeOptions) error {
	if opts.login != nil {
		_, err := eng.Exec(ctx, wire.BuildCommandOrdered("login", [][2]string{
			{"client_login_name", opts.login.name},
			{"client_login_password", opts.login.password},
		}))
		if err != nil {
			return c.wrapHandshake("login", err)
		}
	}

	if opts.server != nil {
		params := [][2]string{{"sid", strconv.FormatUint(uint64(opts.server.id), 10)}}
		if opts.server.port != 0 {
			params = [][2]string{{"port", strconv.FormatUint(uint64(opts.server.port), 10)}}
		}
		_, err := eng.Exec(ctx, wire.BuildCommandOrdered("use", params))
		if err != nil {
			return c.wrapHandshake("use", err)
		}
	}

	if opts.nickname != "" {
		_, err := eng.Exec(ctx, wire.BuildCommandOrdered("clientupdate",
			[][2]string{{"client_nickname", opts.nickname}}))
		if err != nil {
			return c.wrapHandshake("clientupdate", err)
		}
	}

	return nil
}

// registerCategories asks for each category in turn, then reads the client
// list once. Reading it after registering means a client that arrives while it
// is read is not missed: its notification is already queued.
func (c *Client) registerCategories(ctx context.Context, eng *engine.Client, categories []Category) error {
	for _, category := range categories {
		err := c.registerCategory(ctx, eng, category)
		if err != nil {
			return c.wrapHandshake("servernotifyregister", err)
		}
	}
	if len(categories) > 0 {
		c.readClientList(ctx, eng)
	}

	return nil
}

// wrapHandshake names the step that failed, so a failed Connect says which
// part of the session the server refused.
func (c *Client) wrapHandshake(step string, err error) error {
	return fmt.Errorf("%s: %w", step, err)
}

// readVersion asks the server what it is and returns the family its version
// names.
func (c *Client) readVersion(ctx context.Context, eng *engine.Client) (teamspeak.ServerFamily, error) {
	rows, err := eng.Exec(ctx, "version")
	if err != nil {
		return teamspeak.ServerFamilyUnknown, err
	}
	if len(rows) == 0 {
		return teamspeak.ServerFamilyUnknown, nil
	}

	return teamspeak.ServerFamilyForVersion(rows[0]["version"]), nil
}

// readSelf records which client this connection is. The self-move
// notification names no invoker, so without this the client could not tell a
// move of its own from any other.
func (c *Client) readSelf(ctx context.Context, eng *engine.Client) error {
	rows, err := eng.Exec(ctx, "whoami")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	c.mu.Lock()
	c.selfID = servernotify.ParseClientID(rows[0]["client_id"])
	c.mu.Unlock()

	return nil
}

// registerCategory asks the server for one notification category. Only the
// channel category takes a channel, and 0 means every channel.
func (c *Client) registerCategory(ctx context.Context, eng *engine.Client, category Category) error {
	params := [][2]string{{"event", string(category)}}
	if category == CategoryChannel {
		params = append(params, [2]string{"id", "0"})
	}
	_, err := eng.Exec(ctx, wire.BuildCommandOrdered("servernotifyregister", params))

	return err
}

// readClientList fills what the client knows of the others on the server, once
// the notifications are registered. A text message carries the sender's id but
// not its groups, and a self-move carries no invoker at all, so both are
// filled from here.
//
// Failing to read it is not fatal: the session works, and a missing group list
// only leaves a field empty.
func (c *Client) readClientList(ctx context.Context, eng *engine.Client) {
	rows, err := eng.Exec(ctx, wire.BuildCommandOrdered("clientlist",
		[][2]string{{"-uid", ""}, {"-groups", ""}}))
	if err != nil {
		c.logger.WarnContext(ctx, "could not read the client list, so event fields it fills will be empty",
			slog.Any("error", err))

		return
	}

	clients := make(map[teamspeak.ClientID]teamspeak.ClientEntry, len(rows))
	for _, row := range rows {
		entry := servernotify.ClientEnter(row)
		if entry.ID == 0 {
			continue
		}
		clients[entry.ID] = entry
	}

	c.mu.Lock()
	c.clients = clients
	c.mu.Unlock()
}

// finishAttempt puts the client back to disconnected after a failed Connect
// and reports the cause. A deliberate Disconnect is reported as such rather
// than as a failure.
func (c *Client) finishAttempt(err error, reconnect bool) {
	c.mu.Lock()
	if c.stopped {
		// A Disconnect landed during the attempt; its own event is the one to
		// report.
		c.mu.Unlock()

		return
	}
	c.status = teamspeak.StatusDisconnected
	c.engine, c.transport = nil, nil
	c.mu.Unlock()

	c.logger.Debug("connection attempt failed", slog.Any("error", err))
	emit(c, &c.onDisconnected, "Disconnected", teamspeak.DisconnectedEvent{
		Err:           err,
		WillReconnect: reconnect,
	})
}

// handleClosed runs when the connection ends on its own. A close this client
// asked for is Disconnect's to report; a close it did not is an outage, which
// the reconnect loop may retry.
func (c *Client) handleClosed(cause error) {
	c.mu.Lock()
	if c.stopped || c.status == teamspeak.StatusDisconnected {
		c.mu.Unlock()

		return
	}
	if c.status == teamspeak.StatusConnecting {
		// The transport died mid-handshake: the attempt is failing, and
		// Connect reports it.
		c.mu.Unlock()

		return
	}
	c.status = teamspeak.StatusDisconnected
	c.engine, c.transport = nil, nil
	options := c.reconnectOptions
	reconnect := options != nil
	c.mu.Unlock()

	if cause == nil {
		cause = teamspeak.ErrNotConnected
	}
	c.logger.Warn("the query connection ended", slog.Any("error", cause))

	emit(c, &c.onDisconnected, "Disconnected", teamspeak.DisconnectedEvent{
		Err:           cause,
		WillReconnect: reconnect,
	})
	if reconnect {
		c.scheduleReconnect(cause)
	}
}

// Disconnect closes the connection and returns once it is closed.
//
// A clean session is told to quit first, where the transport has a session to
// end; WebQuery has none. Disconnect on a client that is not connected does
// nothing. A running reconnect loop is stopped: a deliberate Disconnect is
// never undone by a retry.
//
// Experimental: this package may change in a minor release.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	c.setStoppedLocked(true)
	status := c.status
	eng := c.engine
	c.status = teamspeak.StatusDisconnected
	c.engine = nil
	c.mu.Unlock()

	if status == teamspeak.StatusDisconnected || eng == nil {
		return nil
	}

	c.logger.InfoContext(ctx, "disconnecting")
	if c.dialer.needsQuit() {
		// Best effort: the connection is closed either way, and the server
		// answers quit by closing it, which is not a failure.
		_, _ = eng.Exec(ctx, "quit")
	}

	err := eng.Close()
	emit(c, &c.onDisconnected, "Disconnected", teamspeak.DisconnectedEvent{})
	if err != nil && !errors.Is(err, teamspeak.ErrNotConnected) {
		return err
	}

	return nil
}

// emit queues a lifecycle event, which no middleware sees. Generic methods are
// not a thing in Go, so it takes the client rather than being one.
func emit[E any](c *Client, subs *eventbus.Subscribers[E], name string, evt E) {
	c.events.Push(func() { subs.Deliver(c.logger, name, evt, nil) })
}

// handleNotification reads one notification and dispatches the event it
// carries. It runs on the engine's read loop, so the state it changes is
// updated inline and only the delivery is queued.
func (c *Client) handleNotification(cmd *wire.Command) {
	switch cmd.Name {
	case "notifycliententerview":
		c.handleClientEnter(cmd)
	case "notifyclientleftview":
		c.handleClientLeave(cmd)
	case "notifyclientmoved":
		c.handleClientMoved(cmd)
	case "notifytextmessage":
		c.handleTextMessage(cmd)
	default:
		c.handleChannelNotification(cmd)
	}

	c.dispatchNotification(cmd)
}

// handleChannelNotification reads the channel and server notifications, which
// keep no state here.
func (c *Client) handleChannelNotification(cmd *wire.Command) {
	switch cmd.Name {
	case "notifychannelcreated":
		if evt, ok := servernotify.ChannelCreated(cmd.Params); ok {
			c.events.Push(func() {
				c.subs.channelCreated.Deliver(c.logger, "ChannelCreatedEvent", evt, cloneChannelCreated)
			})
		}
	case "notifychanneledited":
		// Not the answer to channelgetdescription, which is no edit; see
		// servernotify.ChannelEdited.
		if evt, ok := servernotify.ChannelEdited(cmd.Params); ok {
			c.events.Push(func() {
				c.subs.channelEdited.Deliver(c.logger, "ChannelEditedEvent", evt, cloneChannelEdited)
			})
		}
	case "notifychannelmoved":
		if evt, ok := servernotify.ChannelMoved(cmd.Params); ok {
			c.events.Push(func() { c.subs.channelMoved.Deliver(c.logger, "ChannelMovedEvent", evt, nil) })
		}
	case "notifychanneldeleted":
		if evt, ok := servernotify.ChannelDeleted(cmd.Params); ok {
			c.events.Push(func() { c.subs.channelDeleted.Deliver(c.logger, "ChannelDeletedEvent", evt, nil) })
		}
	case "notifychanneldescriptionchanged":
		if id := servernotify.ParseChannelID(cmd.Params["cid"]); id != 0 {
			evt := teamspeak.ChannelDescriptionChangedEvent{ChannelID: id}
			c.events.Push(func() {
				c.subs.channelDesc.Deliver(c.logger, "ChannelDescriptionChangedEvent", evt, nil)
			})
		}
	case "notifychannelpasswordchanged":
		if id := servernotify.ParseChannelID(cmd.Params["cid"]); id != 0 {
			evt := teamspeak.ChannelPasswordChangedEvent{ChannelID: id}
			c.events.Push(func() {
				c.subs.channelPassword.Deliver(c.logger, "ChannelPasswordChangedEvent", evt, nil)
			})
		}
	case "notifyserveredited":
		evt := servernotify.ServerEdited(cmd.Params)
		c.events.Push(func() {
			c.subs.serverEdited.Deliver(c.logger, "ServerEditedEvent", evt, cloneServerEdited)
		})
	}
}

// dispatchNotification hands every notification, modelled or not, to the
// OnNotification handlers as the server sent it: after the typed event, if
// any, so a handler of both sees the typed one first.
func (c *Client) dispatchNotification(cmd *wire.Command) {
	if !c.subs.notification.Any() {
		return
	}
	evt := teamspeak.NotificationEvent{Name: cmd.Name, Params: maps.Clone(cmd.Params)}
	c.events.Push(func() {
		c.subs.notification.Deliver(c.logger, "NotificationEvent", evt, nil)
	})
}

// cloneEnterEvent and cloneTextMessage give each handler but the last its own
// copy of what the event carries, so a handler changing it cannot change what
// the next one sees.
func cloneEnterEvent(e teamspeak.ClientEnterEvent) teamspeak.ClientEnterEvent {
	return e.Clone()
}

func cloneTextMessage(m teamspeak.TextMessageEvent) teamspeak.TextMessageEvent {
	m.InvokerGroups = slices.Clone(m.InvokerGroups)

	return m
}

func cloneChannelCreated(e teamspeak.ChannelCreatedEvent) teamspeak.ChannelCreatedEvent {
	e.Changes = servernotify.CloneChannelChanges(e.Changes)

	return e
}

func cloneChannelEdited(e teamspeak.ChannelEditedEvent) teamspeak.ChannelEditedEvent {
	e.Changes = servernotify.CloneChannelChanges(e.Changes)

	return e
}

func cloneServerEdited(e teamspeak.ServerEditedEvent) teamspeak.ServerEditedEvent {
	e.Changes = maps.Clone(e.Changes)

	return e
}

func (c *Client) handleClientEnter(cmd *wire.Command) {
	entry := servernotify.ClientEnter(cmd.Params)
	if entry.ID == 0 {
		return
	}

	c.mu.Lock()
	if entry.ID == c.selfID {
		// A taken nickname is renamed by the server, and this notification
		// carries the name it chose.
		c.selfNickname = entry.Nickname
	}
	c.clients[entry.ID] = entry
	c.mu.Unlock()

	// The event's record is its own: the last handler gets the event itself, and
	// must not be able to edit the client list through it.
	evt := teamspeak.ClientEnterEvent{ClientEntry: entry.Clone()}
	c.events.Push(func() {
		c.subs.clientEnter.Deliver(c.logger, "ClientEnterEvent", evt, cloneEnterEvent)
	})
}

func (c *Client) handleClientLeave(cmd *wire.Command) {
	evt := servernotify.ClientLeave(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	delete(c.clients, evt.ClientID)
	isSelf := evt.ClientID == c.selfID
	c.mu.Unlock()

	c.events.Push(func() {
		c.subs.clientLeave.Deliver(c.logger, "ClientLeaveEvent", evt, nil)
	})
	// A query client cannot be kicked from the server — the server refuses
	// that with 516 — but a ban or a shutdown still arrives as a leave, and
	// the client reports it either way.
	if isSelf && (evt.Reason == teamspeak.ReasonKickServer || evt.Reason == teamspeak.ReasonKickServerBan) {
		emit(c, &c.onKicked, "KickedEvent", servernotify.Kicked(evt.Reason, cmd.Params))
	}
}

func (c *Client) handleClientMoved(cmd *wire.Command) {
	evt := servernotify.ClientMoved(cmd.Params)
	if evt.ClientID == 0 {
		return
	}

	c.mu.Lock()
	if entry, ok := c.clients[evt.ClientID]; ok {
		entry.ChannelID = evt.TargetChannelID
		c.clients[evt.ClientID] = entry
	}
	// A move of the client's own names no invoker; the notification is filled
	// from what the client knows of itself, as the voice client does.
	if evt.ClientID == c.selfID && c.selfID != 0 && evt.InvokerID == 0 {
		evt.InvokerID = c.selfID
		evt.InvokerName = c.selfNickname
	}
	c.mu.Unlock()

	c.events.Push(func() {
		c.subs.clientMoved.Deliver(c.logger, "ClientMovedEvent", evt, nil)
	})
	// A channel kick arrives as a move, not as a leave.
	if evt.ClientID == c.selfID && evt.Reason == teamspeak.ReasonKickChannel {
		emit(c, &c.onKicked, "KickedEvent", servernotify.Kicked(evt.Reason, cmd.Params))
	}
}

func (c *Client) handleTextMessage(cmd *wire.Command) {
	evt := servernotify.TextMessage(cmd.Params)

	c.mu.Lock()
	if entry, ok := c.clients[evt.InvokerID]; ok {
		if evt.InvokerUID == "" {
			evt.InvokerUID = entry.UID
		}
		evt.InvokerGroups = slices.Clone(entry.ServerGroups)
	}
	c.mu.Unlock()

	c.logger.Debug("text message received",
		slog.String("target_mode", evt.TargetMode.String()),
		slog.Uint64("invoker_id", uint64(evt.InvokerID)))
	c.events.Push(func() {
		c.subs.textMessage.Deliver(c.logger, "TextMessageEvent", evt, cloneTextMessage)
	})
}
