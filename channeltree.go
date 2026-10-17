package teamspeak

import (
	"maps"
	"slices"
)

// ChannelTree is the channels of a server in the order the server shows them:
// each channel under its parent, and the siblings in sequence.
//
// It is built from a channel list with NewChannelTree and kept current with the
// channel events by ApplyCreated, ApplyEdited, ApplyMoved and ApplyDeleted. It
// is the way to keep a tree from a ServerQuery connection, which delivers the
// channel events; the voice client keeps one of its own.
//
// A ChannelTree is a value that never changes: every method that would change
// it returns a new tree and leaves the receiver as it was, so a tree that was
// handed out can be read from any goroutine. The records it returns are copies
// that share no memory with it. The zero value is an empty tree.
//
// The position of a channel is its place in its parent's list, and the Order of
// a record the tree returns follows from that place: the id of the sibling
// before it, or 0 for the first. It is not the value an earlier record or
// event carried. The server rewrites the Order of the sibling after a channel
// that was created, moved or deleted, and does not say so, so a stored Order
// is wrong after the first such change.
//
// An event the tree cannot place, because it names a channel, a parent or a
// sibling the tree does not hold, puts the channel at the end of its parent
// (the top level when the parent is unknown) and makes Consistent report false
// from then on. A channel whose parent is not in the tree is never kept: every
// channel can be reached from the top level.
//
// Experimental: this may change in a minor release.
type ChannelTree struct {
	// nodes holds every channel by id. The records are never edited once they
	// are in a tree; a change puts a new record in a new map.
	nodes map[ChannelID]Channel
	// kids holds the children of each channel, and of the top level under 0, in
	// order. The slices are never edited once they are in a tree.
	kids         map[ChannelID][]ChannelID
	inconsistent bool
}

// NewChannelTree builds a tree from channel records in any order, such as the
// rows the server sends when a client connects, which name an ancestor of the
// client's channel before the rest. The siblings are put in sequence by the
// Order of each record: the channel after which it sits, or 0 for the first.
//
// The records are copied. Rows that do not fit — a repeated id, a parent that
// is not among them, a channel its own ancestor, a sibling named as the
// predecessor that is not one — are placed at the end of their parent, or
// under the top level for a parent that is missing, and make Consistent report
// false. A record with the id 0 is dropped.
func NewChannelTree(channels []Channel) ChannelTree {
	t := ChannelTree{
		nodes: make(map[ChannelID]Channel, len(channels)),
		kids:  make(map[ChannelID][]ChannelID),
	}
	ids := make([]ChannelID, 0, len(channels))
	for _, ch := range channels {
		if ch.ID == 0 {
			t.inconsistent = true

			continue
		}
		if _, repeated := t.nodes[ch.ID]; repeated {
			t.inconsistent = true
		} else {
			ids = append(ids, ch.ID)
		}
		t.nodes[ch.ID] = ch.Clone()
	}

	under := make(map[ChannelID][]ChannelID)
	for _, id := range ids {
		rec := t.nodes[id]
		if rec.ParentID == id || (rec.ParentID != 0 && !t.has(rec.ParentID)) {
			rec.ParentID = 0
			t.nodes[id] = rec
			t.inconsistent = true
		}
		under[rec.ParentID] = append(under[rec.ParentID], id)
	}

	reached := make(map[ChannelID]bool, len(ids))
	treeBuild(&t, under, 0, reached)
	treeBreakLoops(&t, ids, under, reached)

	return t
}

// treeBreakLoops places what treeBuild did not reach, which hangs on a loop of
// parents: it breaks each loop where it is met first, by putting that channel
// at the top level.
func treeBreakLoops(t *ChannelTree, ids []ChannelID, under map[ChannelID][]ChannelID, reached map[ChannelID]bool) {
	for _, id := range ids {
		if reached[id] {
			continue
		}
		t.inconsistent = true
		parent := t.nodes[id].ParentID
		under[parent] = slices.DeleteFunc(under[parent], func(other ChannelID) bool { return other == id })
		rec := t.nodes[id]
		rec.ParentID = 0
		t.nodes[id] = rec
		t.kids[0] = append(t.kids[0], id)
		treeDerive(t, 0)
		reached[id] = true
		treeBuild(t, under, id, reached)
	}
}

// build puts the children of root, and theirs, in sequence.
func treeBuild(t *ChannelTree, under map[ChannelID][]ChannelID, root ChannelID, reached map[ChannelID]bool) {
	queue := []ChannelID{root}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		list := treeSequence(t, under[parent])
		t.kids[parent] = list
		treeDerive(t, parent)
		for _, id := range list {
			reached[id] = true
			queue = append(queue, id)
		}
	}
}

// sequence puts siblings in the order their records name: each after the one
// whose id is its Order, and the first with Order 0.
func treeSequence(t *ChannelTree, siblings []ChannelID) []ChannelID {
	after := make(map[ChannelID][]ChannelID, len(siblings))
	for _, id := range siblings {
		pred := t.nodes[id].Order
		if pred == id {
			pred = 0
			t.inconsistent = true
		}
		after[pred] = append(after[pred], id)
		if len(after[pred]) > 1 {
			// Two channels after the same one: the server never sends it.
			t.inconsistent = true
		}
	}

	out := make([]ChannelID, 0, len(siblings))
	placed := make(map[ChannelID]bool, len(siblings))
	pending := slices.Clone(after[0])
	slices.Reverse(pending)
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if placed[id] {
			continue
		}
		placed[id] = true
		out = append(out, id)
		next := slices.Clone(after[id])
		slices.Reverse(next)
		pending = append(pending, next...)
	}
	for _, id := range siblings {
		if !placed[id] {
			// After a channel that is not among them, or in a loop.
			t.inconsistent = true
			out = append(out, id)
		}
	}

	return out
}

// Len is how many channels the tree holds.
func (t ChannelTree) Len() int { return len(t.nodes) }

// Consistent reports whether every channel was placed where the server said.
// It is false once an event or a row named something the tree did not hold, and
// stays false: the tree may then differ from the server's.
func (t ChannelTree) Consistent() bool { return !t.inconsistent }

// Get returns a copy of the channel, or false when the tree does not hold it.
func (t ChannelTree) Get(id ChannelID) (Channel, bool) {
	ch, ok := t.nodes[id]
	if !ok {
		return Channel{}, false
	}

	return ch.Clone(), true
}

// Children returns copies of the channels directly under parent, in order. 0
// is the top level. It is empty for a channel with none and for one the tree
// does not hold.
func (t ChannelTree) Children(parent ChannelID) []Channel {
	ids := t.kids[parent]
	out := make([]Channel, 0, len(ids))
	for _, id := range ids {
		out = append(out, t.nodes[id].Clone())
	}

	return out
}

// Path returns copies of the channel and its ancestors, the one under the top
// level first and the channel last. It is empty for a channel the tree does not
// hold.
func (t ChannelTree) Path(id ChannelID) []Channel {
	var up []Channel
	for cur, ok := t.nodes[id]; ok; cur, ok = t.nodes[cur.ParentID] {
		up = append(up, cur.Clone())
		if len(up) > len(t.nodes) {
			// Cannot happen in a tree that was built here; a loop would never
			// end.
			break
		}
	}
	slices.Reverse(up)

	return up
}

// ApplyCreated returns the tree with the channel a ChannelCreatedEvent names
// added under its parent, after the sibling the event's Order names. A channel
// the tree already holds is replaced.
func (t ChannelTree) ApplyCreated(evt ChannelCreatedEvent) ChannelTree {
	w := t.edit()
	if evt.ChannelID == 0 {
		return w.reject()
	}
	if _, held := w.nodes[evt.ChannelID]; held {
		w.inconsistent = true
		treeDetach(&w, evt.ChannelID)
	}
	ch := evt.Changes.Apply(Channel{ID: evt.ChannelID, ParentID: evt.ParentID})
	ch.ParentID = evt.ParentID
	var pred ChannelID
	if evt.Changes.Order != nil {
		pred = *evt.Changes.Order
	}
	treeInsert(&w, ch, pred)

	return w
}

// ApplyEdited returns the tree with the changes of a ChannelEditedEvent made.
// An Order among them moves the channel within its parent, to after that
// sibling. The event does not move a channel to another parent, whatever
// ParentID its changes carry.
func (t ChannelTree) ApplyEdited(evt ChannelEditedEvent) ChannelTree {
	w := t.edit()
	if evt.ChannelID == 0 {
		return w.reject()
	}
	rec, held := w.nodes[evt.ChannelID]
	if !held {
		w.inconsistent = true
		rec = Channel{ID: evt.ChannelID}
		if evt.Changes.ParentID != nil {
			rec.ParentID = *evt.Changes.ParentID
		}
	}
	changed := evt.Changes.Apply(rec)
	changed.ParentID = rec.ParentID
	if held && evt.Changes.Order == nil {
		w.nodes[changed.ID] = changed

		return w
	}
	var pred ChannelID
	switch {
	case evt.Changes.Order != nil:
		pred = *evt.Changes.Order
	case !held:
		pred = w.endMarker(changed.ParentID)
	}
	if held {
		treeDetach(&w, changed.ID)
	}
	treeInsert(&w, changed, pred)

	return w
}

// ApplyMoved returns the tree with the channel a ChannelMovedEvent names moved
// under its new parent, after the sibling the event's Order names, and its
// subchannels with it.
func (t ChannelTree) ApplyMoved(evt ChannelMovedEvent) ChannelTree {
	w := t.edit()
	if evt.ChannelID == 0 {
		return w.reject()
	}
	rec, held := w.nodes[evt.ChannelID]
	if held {
		treeDetach(&w, evt.ChannelID)
	} else {
		w.inconsistent = true
		rec = Channel{ID: evt.ChannelID}
	}
	rec.ParentID = evt.ParentID
	treeInsert(&w, rec, evt.Order)

	return w
}

// ApplyDeleted returns the tree without the channel a ChannelDeletedEvent
// names. The server deletes the subchannels first and says so; one that is
// still there goes with it.
func (t ChannelTree) ApplyDeleted(evt ChannelDeletedEvent) ChannelTree {
	w := t.edit()
	if evt.ChannelID == 0 {
		return w.reject()
	}
	if !w.has(evt.ChannelID) {
		w.inconsistent = true

		return w
	}
	treeRemove(&w, evt.ChannelID)

	return w
}

// edit returns a tree to change that shares nothing it may edit with t: the
// maps are new, and the records and lists in them are replaced, never edited.
func (t ChannelTree) edit() ChannelTree {
	w := ChannelTree{nodes: maps.Clone(t.nodes), kids: maps.Clone(t.kids), inconsistent: t.inconsistent}
	if w.nodes == nil {
		w.nodes = make(map[ChannelID]Channel)
	}
	if w.kids == nil {
		w.kids = make(map[ChannelID][]ChannelID)
	}

	return w
}

// reject is the tree an event that names no channel leaves: the same, and no
// longer known to match the server.
func (t ChannelTree) reject() ChannelTree {
	t.inconsistent = true

	return t
}

func (t ChannelTree) has(id ChannelID) bool {
	_, ok := t.nodes[id]

	return ok
}

// within reports whether id is ancestor or lies under it.
func (t ChannelTree) within(id, ancestor ChannelID) bool {
	for steps := 0; id != 0 && steps <= len(t.nodes); steps++ {
		if id == ancestor {
			return true
		}
		id = t.nodes[id].ParentID
	}

	return false
}

// detach takes the channel out of its parent's list and leaves its record in
// place, for insert to put back.
func treeDetach(t *ChannelTree, id ChannelID) {
	parent := t.nodes[id].ParentID
	t.kids[parent] = slices.DeleteFunc(slices.Clone(t.kids[parent]), func(other ChannelID) bool { return other == id })
	treeDerive(t, parent)
}

// remove deletes the channel and everything under it.
func treeRemove(t *ChannelTree, id ChannelID) {
	treeDetach(t, id)
	if len(t.kids[id]) > 0 {
		t.inconsistent = true
	}
	for _, child := range t.kids[id] {
		treeRemoveBelow(t, child)
	}
	delete(t.kids, id)
	delete(t.nodes, id)
}

func treeRemoveBelow(t *ChannelTree, id ChannelID) {
	for _, child := range t.kids[id] {
		treeRemoveBelow(t, child)
	}
	delete(t.kids, id)
	delete(t.nodes, id)
}

// insert puts ch, whose ParentID is the parent it goes under, into that
// parent's list after pred, or first for 0. A parent the tree does not hold, or
// that is the channel or lies under it, is the top level instead; a pred that
// is not a child of the parent means the end of the list.
func treeInsert(t *ChannelTree, ch Channel, pred ChannelID) {
	if ch.ParentID != 0 && (!t.has(ch.ParentID) || t.within(ch.ParentID, ch.ID)) {
		ch.ParentID = 0
		pred = t.endMarker(0)
		t.inconsistent = true
	}
	list := t.kids[ch.ParentID]
	at := 0
	if pred != 0 {
		at = slices.Index(list, pred) + 1
		if at == 0 || pred == ch.ID {
			// Not a sibling: at the end.
			t.inconsistent = true
			at = len(list)
		}
	}
	t.nodes[ch.ID] = ch
	t.kids[ch.ParentID] = slices.Insert(slices.Clone(list), at, ch.ID)
	treeDerive(t, ch.ParentID)
}

// endMarker is the id of the last child of parent, which a channel inserted
// after it goes last; 0 when there is none, which puts it first of none.
func (t ChannelTree) endMarker(parent ChannelID) ChannelID {
	list := t.kids[parent]
	if len(list) == 0 {
		return 0
	}

	return list[len(list)-1]
}

// derive sets the Order of each child of parent from its place in the list: the
// sibling before it, 0 for the first.
func treeDerive(t *ChannelTree, parent ChannelID) {
	var prev ChannelID
	for _, id := range t.kids[parent] {
		if rec := t.nodes[id]; rec.Order != prev {
			rec.Order = prev
			t.nodes[id] = rec
		}
		prev = id
	}
}
