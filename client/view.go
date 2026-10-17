package client

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ViewStatus says how far a ServerView is from describing a live connection.
// Later versions may add states; a switch over them should have a default case.
//
// Experimental: this may change in a minor release.
type ViewStatus int

const (
	// ViewEmpty is a view of nothing: the client has not connected yet.
	ViewEmpty ViewStatus = iota
	// ViewLoading is a view while Connect is under way and the server has not
	// finished sending the channel list. It holds nothing.
	ViewLoading
	// ViewLive is a view the connection keeps current.
	ViewLive
	// ViewStale is the last view of a connection that has ended, kept readable
	// and no longer kept current. It stays until the next Connect starts. A
	// connection attempt that failed before the channel list arrived leaves a
	// stale view that is empty.
	ViewStale
)

var viewStatusNames = [...]string{
	ViewEmpty:   "empty",
	ViewLoading: "loading",
	ViewLive:    "live",
	ViewStale:   "stale",
}

// String names the status, such as "live".
func (s ViewStatus) String() string {
	if s >= 0 && int(s) < len(viewStatusNames) {
		return viewStatusNames[s]
	}

	return fmt.Sprintf("view status %d", int(s))
}

// ViewReadyEvent is emitted when the view turns live: the server has sent the
// channel list and the clients of the client's own channel. It is emitted again
// after every reconnection.
//
// Experimental: this may change in a minor release.
type ViewReadyEvent struct {
	// Revision is the view's Revision at the moment it turned live.
	Revision uint64
}

// OnViewReady registers a handler for the view turning live, on Connect and on
// every reconnection. It returns a function that removes the handler.
//
// The event is queued as the server finishes the channel list, and delivered
// on the event goroutine: register the handler before Connect to be sure to
// hear it, or use WaitView.
//
// Experimental: this may change in a minor release.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnViewReady(handler func(ViewReadyEvent)) func() {
	return c.onViewReady.Add(handler)
}

// viewState is what the client keeps of the server beyond the client list, which the
// view shares with the roster. Every field is guarded by the client's lock.
type viewState struct {
	tree teamspeak.ChannelTree
	// err is why the last session ended, which WaitView returns when it ends.
	err error
	// changed is closed, and replaced, whenever the status changes, so that
	// WaitView can wait on it.
	changed chan struct{}
	// rows are the channels of the welcome sequence, held until it ends.
	rows     []teamspeak.Channel
	revision uint64
	// ends counts the sessions and attempts that ended.
	ends uint64
	// waiting is how many WaitView calls are blocked.
	waiting int
	status  ViewStatus
}

// resetViewLocked clears the view for a new connection. The revision goes on
// from where it was.
func (c *Client) resetViewLocked() {
	c.view.tree = teamspeak.ChannelTree{}
	c.view.rows = nil
	c.setViewStatusLocked(ViewLoading)
}

// endViewLocked keeps what the view held as the last view, stale, because the
// session ended with cause. A view that was never begun stays empty.
func (c *Client) endViewLocked(cause error) {
	if c.view.status != ViewLoading && c.view.status != ViewLive {
		return
	}
	c.view.rows = nil
	c.view.ends++
	c.view.err = teamspeak.ErrNotConnected
	if cause != nil {
		c.view.err = fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, cause)
	}
	c.setViewStatusLocked(ViewStale)
}

func (c *Client) setViewStatusLocked(status ViewStatus) {
	c.view.status = status
	c.view.revision++
	if c.view.changed != nil {
		close(c.view.changed)
	}
	c.view.changed = make(chan struct{})
}

// collectViewChannel holds a channel row of the welcome sequence until the
// channel list is finished: the rows are not in the order of the tree, so they
// cannot be placed one by one.
func (c *Client) collectViewChannel(h *transport.PacketHandler, params map[string]string) {
	id := servernotify.ParseChannelID(params["cid"])
	if id == 0 {
		return
	}
	row := viewChannel(servernotify.ChannelChanges(params).Apply(teamspeak.Channel{ID: id}))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handler == h && c.view.status == ViewLoading {
		c.view.rows = append(c.view.rows, row)
	}
}

// finishViewWelcome turns the view live at the end of the channel list, which
// is also where the clients of the client's own channel, sent between its
// rows, are complete.
func (c *Client) finishViewWelcome(h *transport.PacketHandler) {
	c.mu.Lock()
	if c.handler != h || c.view.status != ViewLoading {
		c.mu.Unlock()

		return
	}
	c.view.tree = teamspeak.NewChannelTree(c.view.rows)
	c.view.rows = nil
	if !c.view.tree.Consistent() {
		c.logger.Debug("the channel list does not form a tree")
	}
	c.setViewStatusLocked(ViewLive)
	ready := ViewReadyEvent{Revision: c.view.revision}
	c.mu.Unlock()

	emit(c, &c.onViewReady, "ViewReadyEvent", ready)
}

// applyChannelEvent changes the tree by one channel event, under the lock and
// before the typed event is queued. apply returns the tree the event makes;
// name is the notification, for the log. Only a live view of the connection h
// runs changes: the tree is not built until the channel list is finished, and
// a stale view is kept as it was.
func (c *Client) applyChannelEvent(h *transport.PacketHandler, name string,
	apply func(teamspeak.ChannelTree) teamspeak.ChannelTree,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handler != h || c.view.status != ViewLive {
		return
	}
	next := apply(c.view.tree)
	if c.view.tree.Consistent() && !next.Consistent() {
		c.logger.Debug("a channel notification does not fit the channel tree", slog.String("name", name))
	}
	c.view.tree = next
	c.view.revision++
}

// viewChannel is a channel as the view holds it. A channel list carries
// TotalClients and TotalFamilyClients as they were when the client connected,
// and nothing updates them, so a record that kept them would state a count
// that was true once. The view leaves them nil.
func viewChannel(ch teamspeak.Channel) teamspeak.Channel {
	ch.TotalClients = nil
	ch.TotalFamilyClients = nil

	return ch
}

// viewChanges is changes without the client counts, for viewChannel's reason.
func viewChanges(changes teamspeak.ChannelChanges) teamspeak.ChannelChanges {
	changes.TotalClients = nil
	changes.TotalFamilyClients = nil

	return changes
}

// forgetChannelClients drops the clients the client knows to be in a channel it
// is no longer subscribed to. The server does not say they left, and tells
// nothing of them from then on, so what is known of them can only be stale. The
// client itself stays: it always knows where it is.
func (c *Client) forgetChannelClients(h *transport.PacketHandler, channel teamspeak.ChannelID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handler != h {
		return
	}
	for id, info := range c.clients {
		if info.ChannelID == channel && id != c.clid {
			delete(c.clients, id)
			c.view.revision++
		}
	}
}

// WaitView returns once the view is live: at once if it is, and otherwise when
// the server has finished sending the channel list. It returns an error when
// the connection ends first, or was already over, wrapping ErrNotConnected and
// the cause, and ctx's error when ctx ends first. Called before Connect it
// waits for the connection that Connect makes.
//
// Experimental: this may change in a minor release.
func (c *Client) WaitView(ctx context.Context) error {
	c.mu.Lock()
	ends := c.view.ends
	for {
		switch {
		case c.view.status == ViewLive:
			c.mu.Unlock()

			return nil
		case c.view.status == ViewStale, c.view.ends != ends:
			err := c.view.err
			c.mu.Unlock()

			return err
		}
		changed := c.view.changed
		if changed == nil {
			changed = make(chan struct{})
			c.view.changed = changed
		}
		c.view.waiting++
		c.mu.Unlock()

		var err error
		select {
		case <-changed:
		case <-ctx.Done():
			err = ctx.Err()
		}
		c.mu.Lock()
		c.view.waiting--
		if err != nil {
			c.mu.Unlock()

			return err
		}
	}
}

// ServerView is what a voice client knows of the server it is connected to: the
// channel tree in the order the server shows it, the clients it has been told
// about and where they are, and itself. Read it with Client.View.
//
// It is a copy. Nothing the caller does to it, or to a record it returns,
// reaches the client or another view, and it does not change when the client
// does: read View again for the current state.
//
// Each part says how far it can be trusted:
//
//   - The channel tree is exact, in parents and in sibling order, for the
//     channels the server shows this client. The server reports a change to
//     the order of siblings only for the channel that moved, and the view
//     works out the rest, so a channel's Order is its place in the tree and
//     not the value an event carried.
//   - The clients are those the server has announced, in channels the client
//     is subscribed to, and not since dropped. A client in a channel the
//     client is not subscribed to is not here, and the server does not say
//     when a subscription ends; see ChannelUnsubscribedEvent. SubscribeAllChannels
//     subscribes to all of them. Which channels are subscribed to cannot be
//     read.
//   - A channel's TotalClients and TotalFamilyClients are always nil: the
//     server sends them when the client connects and never again.
//   - A channel's Description is empty, as in a channel list; GetChannelInfo
//     has it.
//
// The view shares its clients with the record of the clients that
// TextMessageEvent.InvokerGroups reads, so the two never disagree. A change is
// made to the view when the notification is handled, before the event is
// queued, so a handler sees a view at least as new as its event: if two
// notifications arrive together, the first handler already sees both.
//
// Experimental: this may change in a minor release.
type ServerView struct {
	// Self is the client's own record, nil until the server has sent it.
	Self *teamspeak.ClientEntry
	// byChannel lists the clients of each channel, by id.
	byChannel map[teamspeak.ChannelID][]teamspeak.ClientEntry
	tree      teamspeak.ChannelTree
	// clients are all the known clients, by id.
	clients []teamspeak.ClientEntry
	// Revision increases by one for every change to the view, to a client's
	// record as much as to the tree, so a program can tell whether anything
	// changed since it last looked. It goes on from one connection to the next.
	Revision uint64
	// Status says whether the view is live; see ViewStatus.
	Status ViewStatus
}

// View returns the client's view of the server: a copy, as the records of
// ClientEntry.Clone are, taken at one moment. It costs a pass over the known
// clients, so read it when it is needed, not for every frame; the view is
// empty until Connect.
//
// Experimental: this may change in a minor release.
func (c *Client) View() ServerView {
	c.mu.Lock()
	defer c.mu.Unlock()

	// The tree never changes once built and hands out copies, so it is shared.
	v := ServerView{
		Status:    c.view.status,
		Revision:  c.view.revision,
		tree:      c.view.tree,
		clients:   make([]teamspeak.ClientEntry, 0, len(c.clients)),
		byChannel: make(map[teamspeak.ChannelID][]teamspeak.ClientEntry),
	}
	for _, info := range c.clients {
		v.clients = append(v.clients, info.Clone())
	}
	slices.SortFunc(v.clients, func(a, b teamspeak.ClientEntry) int { return compareIDs(a.ID, b.ID) })
	for _, info := range v.clients {
		v.byChannel[info.ChannelID] = append(v.byChannel[info.ChannelID], info)
	}
	if self, ok := c.clients[c.clid]; ok && c.clid != 0 {
		v.Self = new(self.Clone())
	}

	return v
}

func compareIDs(a, b teamspeak.ClientID) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// Channels returns every channel in the order of the tree: a channel, then its
// subchannels, then the next channel under the same parent.
func (v ServerView) Channels() []teamspeak.Channel {
	out := make([]teamspeak.Channel, 0, v.tree.Len())
	var walk func(parent teamspeak.ChannelID)
	walk = func(parent teamspeak.ChannelID) {
		for _, ch := range v.tree.Children(parent) {
			out = append(out, ch)
			walk(ch.ID)
		}
	}
	walk(0)

	return out
}

// Channel returns the channel, or false when the view does not hold it.
func (v ServerView) Channel(id teamspeak.ChannelID) (teamspeak.Channel, bool) {
	return v.tree.Get(id)
}

// Children returns the channels directly under parent, in order. 0 is the top
// level.
func (v ServerView) Children(parent teamspeak.ChannelID) []teamspeak.Channel {
	return v.tree.Children(parent)
}

// Path returns the channel and its ancestors, the one under the top level
// first and the channel last. It is empty for a channel the view does not hold.
func (v ServerView) Path(id teamspeak.ChannelID) []teamspeak.Channel {
	return v.tree.Path(id)
}

// Clients returns every known client, by id.
func (v ServerView) Clients() []teamspeak.ClientEntry {
	return cloneEntries(v.clients)
}

// Client returns the client, or false when the view does not know it.
func (v ServerView) Client(id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	i, found := slices.BinarySearchFunc(v.clients, id, func(e teamspeak.ClientEntry, id teamspeak.ClientID) int {
		return compareIDs(e.ID, id)
	})
	if !found {
		return teamspeak.ClientEntry{}, false
	}

	return v.clients[i].Clone(), true
}

// ClientsIn returns the known clients in the channel, by id. It is every client
// in the channel only if the client is subscribed to it.
func (v ServerView) ClientsIn(id teamspeak.ChannelID) []teamspeak.ClientEntry {
	return cloneEntries(v.byChannel[id])
}

func cloneEntries(entries []teamspeak.ClientEntry) []teamspeak.ClientEntry {
	out := make([]teamspeak.ClientEntry, len(entries))
	for i, e := range entries {
		out[i] = e.Clone()
	}

	return out
}
