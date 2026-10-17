package client

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
	"github.com/honeybbq/teamspeak-go/notify"
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

// ViewChangedEvent is emitted when the view is newer than the last time a
// handler was told: it follows the typed events of the notifications that
// changed it, and says nothing of what changed. It is for a program that draws
// from the view and does not care which part moved; it replaces no typed event.
//
// It is not emitted while the view is loading, which ViewReadyEvent ends, nor
// when nothing changed since the last ViewReadyEvent or ViewChangedEvent. It
// is emitted once more when the view goes stale. It is also how a program
// learns that the group lists have arrived after ViewReadyEvent.
//
// Experimental: this may change in a minor release.
type ViewChangedEvent struct {
	// Revision is the view's Revision at the moment of delivery. It can be
	// ahead of the event that caused it: a later notification may have changed
	// the view before the handler ran.
	Revision uint64
}

// OnViewChanged registers a handler for the view changing; see
// ViewChangedEvent. It returns a function that removes the handler.
//
// The handlers run one after another with the other events, in the order the
// notifications arrived, and a handler that is slow holds back the events
// behind it. Changes that arrive while one runs are announced by one event
// after the last of them, with the latest revision.
//
// Experimental: this may change in a minor release.
//
// A panic in handler is recovered and logged at Error with the event type;
// the other handlers and later events are still delivered.
func (c *Client) OnViewChanged(handler func(ViewChangedEvent)) func() {
	return c.onViewChanged.Add(handler)
}

// maxSkippedViewMarkers is how many markers in a row may do nothing because a
// later one is queued. It is a guard so that a flood of notifications cannot
// hold ViewChangedEvent back for ever, not a measured value: the queue was
// read, and not run under load, when it was chosen.
const maxSkippedViewMarkers = 63

// serverPropertyPrefix starts the name of every server setting the view holds.
const serverPropertyPrefix = "virtualserver_"

// viewState is what the client keeps of the server beyond the client list, which the
// view shares with the roster. Every field is guarded by the client's lock.
type viewState struct {
	tree teamspeak.ChannelTree
	// err is why the last session ended, which WaitView returns when it ends.
	err error
	// changed is closed, and replaced, whenever the status changes, so that
	// WaitView can wait on it.
	changed chan struct{}
	// server holds the virtualserver_ settings the view keeps.
	server teamspeak.Properties
	// listRows are the rows of the group lists of the command line being
	// handled, by notification name, until the line ends.
	listRows map[string][]map[string]string
	// rows are the channels of the welcome sequence, held until it ends.
	rows          []teamspeak.Channel
	serverGroups  []teamspeak.ServerGroup
	channelGroups []teamspeak.ChannelGroup
	revision      uint64
	// announced is the revision of the last ViewReadyEvent or ViewChangedEvent
	// queued.
	announced uint64
	// ends counts the sessions and attempts that ended.
	ends uint64
	// epoch counts the connections begun, so that a marker queued for one does
	// not announce another.
	epoch uint64
	// waiting is how many WaitView calls are blocked.
	waiting int
	// markers is how many ViewChangedEvent markers are queued, and skipped how
	// many in a row did nothing; see deliverViewChanged.
	markers int
	skipped int
	status  ViewStatus
	// serverGroupsSeen and channelGroupsSeen say that a list of that kind has
	// arrived since the connection began.
	serverGroupsSeen  bool
	channelGroupsSeen bool
	groupsLoaded      bool
}

// resetViewLocked clears the view for a new connection. The revision goes on
// from where it was.
func (c *Client) resetViewLocked() {
	c.view.tree = teamspeak.ChannelTree{}
	c.view.rows = nil
	c.view.server = nil
	c.view.listRows = nil
	c.view.serverGroups = nil
	c.view.channelGroups = nil
	c.view.serverGroupsSeen = false
	c.view.channelGroupsSeen = false
	c.view.groupsLoaded = false
	c.view.epoch++
	c.setViewStatusLocked(ViewLoading)
}

// endViewLocked keeps what the view held as the last view, stale, because the
// session ended with cause. A view that was never begun stays empty.
func (c *Client) endViewLocked(cause error) {
	if c.view.status != ViewLoading && c.view.status != ViewLive {
		return
	}
	c.view.rows = nil
	c.view.listRows = nil
	c.view.ends++
	c.view.err = teamspeak.ErrNotConnected
	if cause != nil {
		c.view.err = fmt.Errorf("%w: %w", teamspeak.ErrNotConnected, cause)
	}
	c.setViewStatusLocked(ViewStale)
	c.queueViewChangedLocked()
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
	c.view.announced = c.view.revision
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

// viewRevision is the view's revision now.
func (c *Client) viewRevision() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.view.revision
}

// announceViewChange queues the marker that becomes a ViewChangedEvent, when
// the packet just handled moved the view on from revision before. It runs
// after the packet's typed events are queued, so the marker follows them.
func (c *Client) announceViewChange(before uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.view.revision == before || c.view.status != ViewLive {
		return
	}
	c.queueViewChangedLocked()
}

// queueViewChangedLocked queues a marker behind the events already queued.
func (c *Client) queueViewChangedLocked() {
	c.view.markers++
	epoch := c.view.epoch
	c.events.Push(func() { c.deliverViewChanged(epoch) })
}

// deliverViewChanged runs when a marker's turn comes, on the event goroutine.
// A marker with another marker queued behind it does nothing, because that one
// will announce the same change and what came after it; so the event goes out
// after the last typed event queued before the last marker, and carries the
// latest revision. At most maxSkippedViewMarkers do nothing in a row.
func (c *Client) deliverViewChanged(epoch uint64) {
	c.mu.Lock()
	c.view.markers--
	if c.view.markers > 0 && c.view.skipped < maxSkippedViewMarkers {
		c.view.skipped++
		c.mu.Unlock()

		return
	}
	c.view.skipped = 0
	if epoch != c.view.epoch || c.view.status == ViewLoading || c.view.revision == c.view.announced {
		c.mu.Unlock()

		return
	}
	c.view.announced = c.view.revision
	evt := ViewChangedEvent{Revision: c.view.revision}
	c.mu.Unlock()

	c.onViewChanged.Deliver(c.logger, "ViewChangedEvent", evt, nil)
}

// takesViewChangesLocked reports whether the view of the connection h is one
// that group lists and server settings reach: not before the connection began,
// and not once it is over.
func (c *Client) takesViewChangesLocked(h *transport.PacketHandler) bool {
	return c.handler == h && (c.view.status == ViewLoading || c.view.status == ViewLive)
}

// collectGroupRow holds a row of a group list until its command line ends: the
// rows of one line are the whole list.
func (c *Client) collectGroupRow(h *transport.PacketHandler, cmd *wire.Command) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.takesViewChangesLocked(h) {
		return
	}
	if c.view.listRows == nil {
		c.view.listRows = make(map[string][]map[string]string)
	}
	c.view.listRows[cmd.Name] = append(c.view.listRows[cmd.Name], cmd.Params)
}

// applyGroupLists replaces the group definitions the view holds by the lists
// the command line just handled carried. The set is replaced, so a group
// missing from the list is gone; a list that equals the set changes nothing.
// The server sends the whole list each time, in one line.
func (c *Client) applyGroupLists(h *transport.PacketHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lists := c.view.listRows
	c.view.listRows = nil
	if len(lists) == 0 || !c.takesViewChangesLocked(h) {
		return
	}
	changed := false
	if rows, ok := lists[notify.ServerGroupList]; ok {
		changed = c.replaceServerGroupsLocked(rows)
	}
	if rows, ok := lists[notify.ChannelGroupList]; ok && c.replaceChannelGroupsLocked(rows) {
		changed = true
	}
	if loaded := c.view.serverGroupsSeen && c.view.channelGroupsSeen; loaded != c.view.groupsLoaded {
		c.view.groupsLoaded = loaded
		changed = true
	}
	if changed {
		c.view.revision++
	}
}

// replaceServerGroupsLocked makes the server groups the rows describe the view's
// set, and reports whether that changed it.
func (c *Client) replaceServerGroupsLocked(rows []map[string]string) bool {
	groups, err := answeredBy(rows).ListServerGroups(context.Background(), teamspeak.ServerGroupListOptions{})
	if err != nil {
		c.logger.Debug("the server group list could not be read", slog.Any("error", err))

		return false
	}
	next := orderedGroups(groups, func(g teamspeak.ServerGroup) teamspeak.ServerGroupID { return g.ID })
	c.view.serverGroupsSeen = true
	if slices.Equal(next, c.view.serverGroups) {
		return false
	}
	c.view.serverGroups = next

	return true
}

// replaceChannelGroupsLocked is replaceServerGroupsLocked for channel groups.
func (c *Client) replaceChannelGroupsLocked(rows []map[string]string) bool {
	groups, err := answeredBy(rows).ListChannelGroups(context.Background(), teamspeak.ChannelGroupListOptions{})
	if err != nil {
		c.logger.Debug("the channel group list could not be read", slog.Any("error", err))

		return false
	}
	next := orderedGroups(groups, func(g teamspeak.ChannelGroup) teamspeak.ChannelGroupID { return g.ID })
	c.view.channelGroupsSeen = true
	if slices.Equal(next, c.view.channelGroups) {
		return false
	}
	c.view.channelGroups = next

	return true
}

// answeredBy is the typed commands as if the server had answered every command
// with rows, so that the view reads a group row with the parser that
// ListServerGroups and ListChannelGroups use, and the two cannot differ.
func answeredBy(rows []map[string]string) *teamspeak.Commands {
	return teamspeak.NewCommands(teamspeak.ExecutorFunc(
		func(context.Context, teamspeak.Request) ([]map[string]string, error) { return rows, nil }))
}

// orderedGroups puts groups in ascending id, as the server lists them. A group
// without an id is dropped, and of two with the same id the later one is kept.
func orderedGroups[G any, ID cmp.Ordered](groups []G, id func(G) ID) []G {
	var zero ID
	out := make([]G, 0, len(groups))
	for _, g := range groups {
		if id(g) != zero {
			out = append(out, g)
		}
	}
	slices.SortStableFunc(out, func(a, b G) int { return cmp.Compare(id(a), id(b)) })

	kept := out[:0]
	for _, g := range out {
		if len(kept) > 0 && id(kept[len(kept)-1]) == id(g) {
			kept[len(kept)-1] = g

			continue
		}
		kept = append(kept, g)
	}

	return kept
}

// seedViewServerLocked takes the server's own settings from initserver, which
// arrives before the channel list: the virtualserver_ parameters only. The
// others are the client's own, and four of them are secrets.
func (c *Client) seedViewServerLocked(params map[string]string) {
	c.view.server = make(teamspeak.Properties)
	for name, value := range params {
		if strings.HasPrefix(name, serverPropertyPrefix) {
			c.view.server[name] = value
		}
	}
	c.view.revision++
}

// mergeViewServer sets the virtualserver_ settings in changes in the view's
// copy of the server, and leaves the others as they were. counters leaves out
// the counters and statistics that the server changes by itself (see
// serverCounter), which only servergetvariables carries: nothing keeps them
// current, so the view does not hold them.
func (c *Client) mergeViewServer(h *transport.PacketHandler, changes map[string]string, counters bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.takesViewChangesLocked(h) {
		return
	}
	changed := false
	for name, value := range changes {
		if !strings.HasPrefix(name, serverPropertyPrefix) || counters && serverCounter(name) {
			continue
		}
		if old, held := c.view.server[name]; !held || old != value {
			if c.view.server == nil {
				c.view.server = make(teamspeak.Properties)
			}
			c.view.server[name] = value
			changed = true
		}
	}
	if changed {
		c.view.revision++
	}
}

// serverCounter reports whether the setting is a count or statistic that the
// server changes by itself.
func serverCounter(name string) bool {
	switch strings.TrimPrefix(name, serverPropertyPrefix) {
	case "clientsonline", "queryclientsonline", "channelsonline", "uptime",
		"client_connections", "query_client_connections",
		"month_bytes_downloaded", "month_bytes_uploaded",
		"total_bytes_downloaded", "total_bytes_uploaded",
		"total_packetloss_speech", "total_packetloss_keepalive",
		"total_packetloss_control", "total_packetloss_total", "total_ping":
		return true
	default:
		return false
	}
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
//   - The group lists are what the server last described, in full: it sends
//     the whole list after every change to a group, and nothing about a
//     group's permissions or members, which the view does not hold.
//     GroupsLoaded says they have arrived. A client's ServerGroups can name a
//     group not in them for a moment; see ServerView.ServerGroup.
//   - Server is exact for the settings the server announces when they change,
//     such as the name, and as of the last Client.GetServerVariables for the
//     others, such as the welcome message and the client limit: the server
//     announces an edit of those without naming them. The view merges every
//     answer to GetServerVariables, whoever asked, and keeps none of the
//     counters and statistics in it, such as the clients online and the
//     uptime, which nothing keeps current; GetServerInfo has them.
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
	// Server holds the settings of the virtual server that the view keeps, by
	// their wire names, such as "virtualserver_name"; Client.GetServerInfo
	// returns the same names and values. See ServerView for how far to trust
	// them.
	Server teamspeak.Properties
	// byChannel lists the clients of each channel, by id.
	byChannel map[teamspeak.ChannelID][]teamspeak.ClientEntry
	tree      teamspeak.ChannelTree
	// clients are all the known clients, by id.
	clients []teamspeak.ClientEntry
	// ServerGroups are the server groups the server has described to the
	// client, in ascending id. See ServerView.
	ServerGroups []teamspeak.ServerGroup
	// ChannelGroups are the channel groups the server has described to the
	// client, in ascending id.
	ChannelGroups []teamspeak.ChannelGroup
	// Revision increases by one for every change to the view, to a client's
	// record as much as to the tree, so a program can tell whether anything
	// changed since it last looked. It goes on from one connection to the next.
	Revision uint64
	// Status says whether the view is live; see ViewStatus.
	Status ViewStatus
	// GroupsLoaded is true once both group lists of this connection have
	// arrived, so that empty ServerGroups and ChannelGroups mean none, and not
	// yet. The server sends them right after the channel list, so a handler of
	// ViewReadyEvent can run before they are here; ViewChangedEvent follows
	// them.
	GroupsLoaded bool
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
		Status:        c.view.status,
		Revision:      c.view.revision,
		tree:          c.view.tree,
		clients:       make([]teamspeak.ClientEntry, 0, len(c.clients)),
		byChannel:     make(map[teamspeak.ChannelID][]teamspeak.ClientEntry),
		ServerGroups:  slices.Clone(c.view.serverGroups),
		ChannelGroups: slices.Clone(c.view.channelGroups),
		Server:        maps.Clone(c.view.server),
		GroupsLoaded:  c.view.groupsLoaded,
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

// ServerGroup returns the server group, or false when the view does not hold
// it. A client's server groups can name one the view does not hold, for a
// moment after the group is deleted, or if the list is late.
func (v ServerView) ServerGroup(id teamspeak.ServerGroupID) (teamspeak.ServerGroup, bool) {
	i := slices.IndexFunc(v.ServerGroups, func(g teamspeak.ServerGroup) bool { return g.ID == id })
	if i < 0 {
		return teamspeak.ServerGroup{}, false
	}

	return v.ServerGroups[i], true
}

// ChannelGroup returns the channel group, or false when the view does not hold
// it.
func (v ServerView) ChannelGroup(id teamspeak.ChannelGroupID) (teamspeak.ChannelGroup, bool) {
	i := slices.IndexFunc(v.ChannelGroups, func(g teamspeak.ChannelGroup) bool { return g.ID == id })
	if i < 0 {
		return teamspeak.ChannelGroup{}, false
	}

	return v.ChannelGroups[i], true
}

func cloneEntries(entries []teamspeak.ClientEntry) []teamspeak.ClientEntry {
	out := make([]teamspeak.ClientEntry, len(entries))
	for i, e := range entries {
		out[i] = e.Clone()
	}

	return out
}
