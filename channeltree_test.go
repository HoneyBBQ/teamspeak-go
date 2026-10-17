package teamspeak

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

func channelIDs(channels []Channel) []ChannelID {
	ids := make([]ChannelID, len(channels))
	for i, ch := range channels {
		ids[i] = ch.ID
	}

	return ids
}

func row(id, parent, order ChannelID) Channel {
	return Channel{ID: id, ParentID: parent, Order: order, Name: fmt.Sprintf("c%d", id)}
}

func created(id, parent, order ChannelID) ChannelCreatedEvent {
	return ChannelCreatedEvent{
		ChannelID: id, ParentID: parent,
		Changes: ChannelChanges{Order: &order, Name: new(fmt.Sprintf("c%d", id))},
	}
}

func editedOrder(id, order ChannelID) ChannelEditedEvent {
	return ChannelEditedEvent{ChannelID: id, Changes: ChannelChanges{Order: &order}}
}

func moved(id, parent, order ChannelID) ChannelMovedEvent {
	return ChannelMovedEvent{ChannelID: id, ParentID: parent, Order: order}
}

func deleted(id ChannelID) ChannelDeletedEvent { return ChannelDeletedEvent{ChannelID: id} }

// preorder lists the ids in the order of the tree.
func preorder(t ChannelTree) []ChannelID {
	var out []ChannelID
	var walk func(parent ChannelID)
	walk = func(parent ChannelID) {
		for _, ch := range t.Children(parent) {
			out = append(out, ch.ID)
			walk(ch.ID)
		}
	}
	walk(0)

	return out
}

// baseTree is 1, 2, 3, 4 at the top level, with 5 and 6 under 2.
func baseTree() ChannelTree {
	return NewChannelTree([]Channel{
		row(1, 0, 0), row(2, 0, 1), row(3, 0, 2), row(4, 0, 3), row(5, 2, 0), row(6, 2, 5),
	})
}

//nolint:funlen // one table, a row for each way the server changes the order
func TestChannelTreeFollowsTheOrderOfEachEvent(t *testing.T) {
	for _, c := range []struct {
		name         string
		apply        func(ChannelTree) ChannelTree
		top          []ChannelID
		underTwo     []ChannelID
		inconsistent bool
	}{
		{"create appended, as the server answers a create with no order", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 0, 4))
		}, []ChannelID{1, 2, 3, 4, 9}, []ChannelID{5, 6}, false},
		{"create after a channel", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 0, 1))
		}, []ChannelID{1, 9, 2, 3, 4}, []ChannelID{5, 6}, false},
		{"create first", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 0, 0))
		}, []ChannelID{9, 1, 2, 3, 4}, []ChannelID{5, 6}, false},
		{"create under a parent", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 2, 6))
		}, []ChannelID{1, 2, 3, 4}, []ChannelID{5, 6, 9}, false},
		{"move to another parent", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(5, 0, 3))
		}, []ChannelID{1, 2, 3, 5, 4}, []ChannelID{6}, false},
		{"move inside a parent", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(4, 0, 1))
		}, []ChannelID{1, 4, 2, 3}, []ChannelID{5, 6}, false},
		{"edit the order", func(t ChannelTree) ChannelTree {
			return t.ApplyEdited(editedOrder(3, 1))
		}, []ChannelID{1, 3, 2, 4}, []ChannelID{5, 6}, false},
		{"edit the order to first", func(t ChannelTree) ChannelTree {
			return t.ApplyEdited(editedOrder(4, 0))
		}, []ChannelID{4, 1, 2, 3}, []ChannelID{5, 6}, false},
		{"edit the name only", func(t ChannelTree) ChannelTree {
			return t.ApplyEdited(ChannelEditedEvent{ChannelID: 3, Changes: ChannelChanges{Name: new("Renamed")}})
		}, []ChannelID{1, 2, 3, 4}, []ChannelID{5, 6}, false},
		{"delete a middle sibling", func(t ChannelTree) ChannelTree {
			return t.ApplyDeleted(deleted(3))
		}, []ChannelID{1, 2, 4}, []ChannelID{5, 6}, false},
		{"delete a parent before its children", func(t ChannelTree) ChannelTree {
			return t.ApplyDeleted(deleted(2)).ApplyDeleted(deleted(5)).ApplyDeleted(deleted(6))
		}, []ChannelID{1, 3, 4}, nil, true},
		{"delete the children, then the parent", func(t ChannelTree) ChannelTree {
			return t.ApplyDeleted(deleted(5)).ApplyDeleted(deleted(6)).ApplyDeleted(deleted(2))
		}, []ChannelID{1, 3, 4}, nil, false},
		{"delete a parent whose children were not announced", func(t ChannelTree) ChannelTree {
			return t.ApplyDeleted(deleted(2))
		}, []ChannelID{1, 3, 4}, nil, true},
		{"create after a channel that is not a sibling", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 0, 5))
		}, []ChannelID{1, 2, 3, 4, 9}, []ChannelID{5, 6}, true},
		{"create under a parent that is not known", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(9, 77, 0))
		}, []ChannelID{1, 2, 3, 4, 9}, []ChannelID{5, 6}, true},
		{"move after a channel that is not a sibling", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(1, 0, 6))
		}, []ChannelID{2, 3, 4, 1}, []ChannelID{5, 6}, true},
		{"move under itself", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(2, 2, 0))
		}, []ChannelID{1, 3, 4, 2}, []ChannelID{5, 6}, true},
		{"move under its own subchannel", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(2, 6, 0))
		}, []ChannelID{1, 3, 4, 2}, []ChannelID{5, 6}, true},
		{"edit the order after a channel that is not a sibling", func(t ChannelTree) ChannelTree {
			return t.ApplyEdited(editedOrder(1, 6))
		}, []ChannelID{2, 3, 4, 1}, []ChannelID{5, 6}, true},
		{"edit a channel that is not known", func(t ChannelTree) ChannelTree {
			return t.ApplyEdited(ChannelEditedEvent{ChannelID: 9, Changes: ChannelChanges{Name: new("x")}})
		}, []ChannelID{1, 2, 3, 4, 9}, []ChannelID{5, 6}, true},
		{"move a channel that is not known", func(t ChannelTree) ChannelTree {
			return t.ApplyMoved(moved(9, 0, 1))
		}, []ChannelID{1, 9, 2, 3, 4}, []ChannelID{5, 6}, true},
		{"an event that names no channel", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(0, 0, 0)).ApplyMoved(moved(0, 2, 0)).ApplyDeleted(deleted(0))
		}, []ChannelID{1, 2, 3, 4}, []ChannelID{5, 6}, true},
		{"delete a channel that is not known", func(t ChannelTree) ChannelTree {
			return t.ApplyDeleted(deleted(9))
		}, []ChannelID{1, 2, 3, 4}, []ChannelID{5, 6}, true},
		{"create a channel that is already known", func(t ChannelTree) ChannelTree {
			return t.ApplyCreated(created(3, 0, 0))
		}, []ChannelID{3, 1, 2, 4}, []ChannelID{5, 6}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree := c.apply(baseTree())
			if got := channelIDs(tree.Children(0)); !slices.Equal(got, c.top) {
				t.Errorf("top level = %v, want %v", got, c.top)
			}
			if got := channelIDs(tree.Children(2)); !slices.Equal(got, c.underTwo) && (len(got) > 0 || len(c.underTwo) > 0) {
				t.Errorf("under 2 = %v, want %v", got, c.underTwo)
			}
			if tree.Consistent() == c.inconsistent {
				t.Errorf("Consistent() = %v", tree.Consistent())
			}
			requireWellFormed(t, tree)
		})
	}
}

// requireWellFormed checks what every tree must hold whatever it was fed: each
// channel is under a parent the tree has, can be reached from the top, and has
// the Order its place gives it.
func requireWellFormed(t *testing.T, tree ChannelTree) {
	t.Helper()
	seen := map[ChannelID]bool{}
	var walk func(parent ChannelID)
	walk = func(parent ChannelID) {
		var prev ChannelID
		for _, ch := range tree.Children(parent) {
			if seen[ch.ID] {
				t.Fatalf("channel %d is listed twice", ch.ID)
			}
			seen[ch.ID] = true
			if ch.ParentID != parent {
				t.Errorf("channel %d lists under %d and says its parent is %d", ch.ID, parent, ch.ParentID)
			}
			if ch.Order != prev {
				t.Errorf("channel %d: Order = %d, want %d", ch.ID, ch.Order, prev)
			}
			prev = ch.ID
			walk(ch.ID)
		}
	}
	walk(0)
	if len(seen) != tree.Len() {
		t.Errorf("%d channels can be reached of %d", len(seen), tree.Len())
	}
	for id := range seen {
		path := tree.Path(id)
		if len(path) == 0 || path[len(path)-1].ID != id || path[0].ParentID != 0 {
			t.Errorf("Path(%d) = %v", id, channelIDs(path))
		}
	}
}

func TestChannelTreeDerivesTheOrderOfTheNextSibling(t *testing.T) {
	// The server rewrites the order of the sibling after a new channel and says
	// nothing, so the record it sent earlier is wrong.
	tree := baseTree()
	if two, _ := tree.Get(2); two.Order != 1 {
		t.Fatalf("channel 2 starts with Order %d", two.Order)
	}
	tree = tree.ApplyCreated(created(9, 0, 1))
	if two, _ := tree.Get(2); two.Order != 9 {
		t.Errorf("channel 2 after a create after 1: Order = %d, want 9", two.Order)
	}
	tree = tree.ApplyDeleted(deleted(9))
	if two, _ := tree.Get(2); two.Order != 1 {
		t.Errorf("channel 2 after the delete: Order = %d, want 1", two.Order)
	}
	tree = tree.ApplyCreated(created(9, 0, 0))
	if one, _ := tree.Get(1); one.Order != 9 {
		t.Errorf("channel 1 after a create first: Order = %d, want 9", one.Order)
	}
}

func TestChannelTreeIgnoresTheOrderOfRows(t *testing.T) {
	// The welcome names an ancestor first, so the rows are not in sibling order.
	rows := []Channel{
		row(2, 0, 1), row(1, 0, 0), row(5, 2, 0), row(6, 2, 5), row(7, 2, 6), row(3, 0, 2), row(4, 0, 3),
	}
	want := []ChannelID{1, 2, 5, 6, 7, 3, 4}
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // a fixed seed, so a failure repeats
	for range 50 {
		shuffled := slices.Clone(rows)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		tree := NewChannelTree(shuffled)
		if got := preorder(tree); !slices.Equal(got, want) {
			t.Fatalf("rows %v: tree = %v, want %v", channelIDs(shuffled), got, want)
		}
		if !tree.Consistent() {
			t.Fatalf("rows %v are a tree and were not taken for one", channelIDs(shuffled))
		}
		requireWellFormed(t, tree)
	}
}

func TestChannelTreeKeepsEveryChannelOfRowsThatDoNotFit(t *testing.T) {
	for _, c := range []struct {
		name string
		rows []Channel
		want []ChannelID
	}{
		{"a parent that is not there", []Channel{row(1, 0, 0), row(2, 9, 0)}, []ChannelID{1, 2}},
		{"a loop of parents", []Channel{row(1, 2, 0), row(2, 1, 0), row(3, 0, 0)}, []ChannelID{3, 1, 2}},
		{"its own parent", []Channel{row(1, 1, 0)}, []ChannelID{1}},
		{"a predecessor that is not a sibling", []Channel{row(1, 0, 0), row(2, 0, 7)}, []ChannelID{1, 2}},
		{"two after the same channel", []Channel{row(1, 0, 0), row(2, 0, 1), row(3, 0, 1)}, []ChannelID{1, 2, 3}},
		{"a loop of siblings", []Channel{row(1, 0, 2), row(2, 0, 1)}, []ChannelID{1, 2}},
		{"a repeated id", []Channel{row(1, 0, 0), row(1, 0, 0)}, []ChannelID{1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree := NewChannelTree(c.rows)
			if got := preorder(tree); !slices.Equal(got, c.want) {
				t.Errorf("tree = %v, want %v", got, c.want)
			}
			if tree.Consistent() {
				t.Error("Consistent() = true")
			}
			requireWellFormed(t, tree)
		})
	}
	if tree := NewChannelTree([]Channel{{ID: 0, Name: "no id"}}); tree.Len() != 0 || tree.Consistent() {
		t.Errorf("a row with no id: Len %d, Consistent %v", tree.Len(), tree.Consistent())
	}
}

func TestChannelTreeNeverChanges(t *testing.T) {
	rows := []Channel{row(1, 0, 0), row(2, 0, 1)}
	tree := NewChannelTree(rows)
	rows[0].Name = "edited after"
	if one, _ := tree.Get(1); one.Name != "c1" {
		t.Errorf("the tree follows the rows it was built from: %q", one.Name)
	}

	before := preorder(tree)
	next := tree.ApplyCreated(created(9, 0, 0)).ApplyMoved(moved(2, 9, 0)).ApplyDeleted(deleted(1))
	if got := preorder(tree); !slices.Equal(got, before) {
		t.Errorf("a change altered the tree it was made to: %v, was %v", got, before)
	}
	if got := preorder(next); !slices.Equal(got, []ChannelID{9, 2}) {
		t.Errorf("next = %v", got)
	}

	// What a caller gets is its own.
	got, _ := tree.Get(1)
	scribble(&got)
	children := tree.Children(0)
	children[0].Name = "mine"
	children[1], children[0] = children[0], children[1]
	if one, _ := tree.Get(1); one.Name != "c1" || one.TotalClients != nil {
		t.Errorf("a returned record reached the tree: %+v", one)
	}
	if got := preorder(tree); !slices.Equal(got, before) {
		t.Errorf("a returned list reached the tree: %v", got)
	}
}

// scribble edits a record as a caller may.
func scribble(ch *Channel) {
	ch.Name = "mine"
	ch.TotalClients = new(int32(5))
}

func TestChannelTreeZeroValueIsEmpty(t *testing.T) {
	var tree ChannelTree
	if tree.Len() != 0 || !tree.Consistent() || len(tree.Children(0)) != 0 || len(tree.Path(1)) != 0 {
		t.Errorf("zero tree: %+v", tree)
	}
	if _, ok := tree.Get(1); ok {
		t.Error("the zero tree holds a channel")
	}
	next := tree.ApplyCreated(created(1, 0, 0))
	if got := preorder(next); !slices.Equal(got, []ChannelID{1}) || tree.Len() != 0 {
		t.Errorf("after a create: %v, and the zero tree has %d", got, tree.Len())
	}
}

func TestChannelTreePathIsRootFirst(t *testing.T) {
	tree := baseTree().ApplyMoved(moved(2, 3, 0))
	if got := channelIDs(tree.Path(6)); !slices.Equal(got, []ChannelID{3, 2, 6}) {
		t.Errorf("Path(6) = %v", got)
	}
	if got := tree.Path(99); len(got) != 0 {
		t.Errorf("Path(99) = %v", got)
	}
}

// server is a model of the server's rules for the order of channels, kept as
// the server keeps it: each channel stores the id of the sibling it sits after,
// and a change to one stored value rewrites that of the sibling next to it
// without a word.
type server struct {
	parent map[ChannelID]ChannelID
	order  map[ChannelID]ChannelID
	next   ChannelID
}

func newServer() *server {
	s := &server{parent: map[ChannelID]ChannelID{}, order: map[ChannelID]ChannelID{}, next: 1}
	for range 3 {
		s.create(0, s.last(0))
	}

	return s
}

// chain lists the children of parent from the first, by following the stored
// orders.
func (s *server) chain(parent ChannelID) []ChannelID {
	out := make([]ChannelID, 0, len(s.parent))
	prev := ChannelID(0)
	for {
		found := ChannelID(0)
		for id, p := range s.parent {
			if p == parent && s.order[id] == prev {
				found = id
			}
		}
		if found == 0 {
			return out
		}
		out = append(out, found)
		prev = found
	}
}

func (s *server) last(parent ChannelID) ChannelID {
	c := s.chain(parent)
	if len(c) == 0 {
		return 0
	}

	return c[len(c)-1]
}

func (s *server) link(id, parent, pred ChannelID) {
	for other, p := range s.parent {
		if p == parent && other != id && s.order[other] == pred {
			s.order[other] = id
		}
	}
	s.parent[id] = parent
	s.order[id] = pred
}

func (s *server) unlink(id ChannelID) {
	for other, p := range s.parent {
		if p == s.parent[id] && other != id && s.order[other] == id {
			s.order[other] = s.order[id]
		}
	}
}

func (s *server) create(parent, pred ChannelID) ChannelID {
	id := s.next
	s.next++
	s.link(id, parent, pred)

	return id
}

func (s *server) move(id, parent, pred ChannelID) {
	s.unlink(id)
	s.link(id, parent, pred)
}

func (s *server) within(id, ancestor ChannelID) bool {
	for ; id != 0; id = s.parent[id] {
		if id == ancestor {
			return true
		}
	}

	return false
}

func (s *server) below(id ChannelID) []ChannelID {
	out := make([]ChannelID, 0, len(s.parent))
	for _, c := range s.chain(id) {
		out = append(out, s.below(c)...)
		out = append(out, c)
	}

	return out
}

func (s *server) all() []ChannelID {
	ids := make([]ChannelID, 0, len(s.parent))
	for id := range s.parent {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	return ids
}

// rows is the channellist the server would send now.
func (s *server) rows() []Channel {
	out := make([]Channel, 0, len(s.parent))
	for _, id := range s.all() {
		out = append(out, row(id, s.parent[id], s.order[id]))
	}

	return out
}

func (s *server) pick(r *rand.Rand, ids []ChannelID) ChannelID {
	return ids[r.IntN(len(ids))]
}

// predFor picks where a channel under parent may go: first, or after a sibling
// that is not the channel itself.
func (s *server) predFor(r *rand.Rand, parent, self ChannelID) ChannelID {
	options := []ChannelID{0}
	for _, c := range s.chain(parent) {
		if c != self {
			options = append(options, c)
		}
	}

	return s.pick(r, options)
}

func (s *server) parentFor(r *rand.Rand, self ChannelID) ChannelID {
	options := []ChannelID{0}
	for _, id := range s.all() {
		if self == 0 || !s.within(id, self) {
			options = append(options, id)
		}
	}

	return s.pick(r, options)
}

// step makes one change the server could, and returns the tree after the event
// it would send.
func (s *server) step(r *rand.Rand, tree ChannelTree) ChannelTree {
	ids := s.all()
	switch op := r.IntN(10); {
	case op < 3 || len(ids) < 2:
		parent := s.parentFor(r, 0)
		pred := s.predFor(r, parent, 0)
		id := s.create(parent, pred)

		return tree.ApplyCreated(created(id, parent, pred))
	case op < 6:
		id := s.pick(r, ids)
		parent := s.parentFor(r, id)
		pred := s.predFor(r, parent, id)
		s.move(id, parent, pred)

		return tree.ApplyMoved(moved(id, parent, pred))
	case op < 8:
		id := s.pick(r, ids)
		parent := s.parent[id]
		pred := s.predFor(r, parent, id)
		s.move(id, parent, pred)

		return tree.ApplyEdited(editedOrder(id, pred))
	default:
		id := s.pick(r, ids)
		// Subchannels first, each with an event, then the channel.
		for _, gone := range append(s.below(id), id) {
			s.unlink(gone)
			delete(s.parent, gone)
			delete(s.order, gone)
			tree = tree.ApplyDeleted(deleted(gone))
		}

		return tree
	}
}

func TestChannelTreeMatchesTheServersRulesOverRandomChanges(t *testing.T) {
	for seed := range uint64(60) {
		r := rand.New(rand.NewPCG(seed, 7)) //nolint:gosec // a fixed seed, so a failure repeats
		s := newServer()
		tree := NewChannelTree(s.rows())
		for step := range 120 {
			tree = s.step(r, tree)

			// The tree is what the server would send now.
			if !tree.Consistent() {
				t.Fatalf("seed %d step %d: an event the server sends was not placed", seed, step)
			}
			if tree.Len() != len(s.parent) {
				t.Fatalf("seed %d step %d: %d channels, server has %d", seed, step, tree.Len(), len(s.parent))
			}
			for _, parent := range append([]ChannelID{0}, s.all()...) {
				want := s.chain(parent)
				got := channelIDs(tree.Children(parent))
				if len(want) != len(got) || (len(want) > 0 && !slices.Equal(got, want)) {
					t.Fatalf("seed %d step %d: children of %d = %v, server has %v", seed, step, parent, got, want)
				}
			}
			for _, ch := range s.rows() {
				got, _ := tree.Get(ch.ID)
				if got.ParentID != ch.ParentID || got.Order != ch.Order {
					t.Fatalf("seed %d step %d: channel %d is under %d after %d, server has %d after %d",
						seed, step, ch.ID, got.ParentID, got.Order, ch.ParentID, ch.Order)
				}
			}
			// A client that connects now sees the same tree.
			fresh := NewChannelTree(s.rows())
			if !slices.Equal(preorder(fresh), preorder(tree)) {
				t.Fatalf("seed %d step %d: a fresh list gives %v, the events %v",
					seed, step, preorder(fresh), preorder(tree))
			}
			requireWellFormed(t, tree)
		}
	}
}

// Whatever sequence of events a server might send, or a stream might garble
// into, the tree holds every channel under a parent it has.
func FuzzChannelTree(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 1, 2, 1, 2, 1, 3, 1, 0, 2, 2, 0, 3, 4, 0, 0})
	f.Add([]byte{1, 2, 3, 1, 3, 2, 1, 2, 2, 1, 2, 1, 0, 0, 0, 1, 1, 1})
	f.Add([]byte{3, 1, 0, 0, 3, 2, 0, 0, 2, 1, 2, 0, 2, 2, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		tree := baseTree()
		for len(data) >= 4 {
			op, id, parent, order := data[0], ChannelID(data[1]%12), ChannelID(data[2]%12), ChannelID(data[3]%12)
			data = data[4:]
			switch op % 4 {
			case 0:
				tree = tree.ApplyCreated(created(id, parent, order))
			case 1:
				tree = tree.ApplyEdited(editedOrder(id, order))
			case 2:
				tree = tree.ApplyMoved(moved(id, parent, order))
			default:
				tree = tree.ApplyDeleted(deleted(id))
			}
			requireWellFormed(t, tree)
		}
	})
}
