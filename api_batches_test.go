package teamspeak

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

func TestKickClients_SendsARowPerClient(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.KickClients(t.Context(), []ClientID{4, 9, 12}, ReasonKickServer,
			KickClientsOptions{ReasonMessage: "bye now"})
	})
	if want := `clientkick reasonid=5 reasonmsg=bye\snow clid=4|clid=9|clid=12`; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	line = encoded(t, func(c *Commands) error {
		return c.KickClients(t.Context(), []ClientID{4, 9}, ReasonKickChannel, KickClientsOptions{ContinueOnError: true})
	})
	if want := "clientkick -continueonerror reasonid=4 clid=4|clid=9"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}
}

func TestKickClients_RefusesAReasonItCannotSend_AndSendsNothingForNone(t *testing.T) {
	refused(t, func(c *Commands) error {
		return c.KickClients(t.Context(), []ClientID{1}, ReasonKickServerBan, KickClientsOptions{})
	})

	s := &script{}
	err := NewCommands(s).KickClients(t.Context(), nil, ReasonKickServer, KickClientsOptions{})
	if err != nil || len(s.sent) != 0 {
		t.Errorf("none: err = %v, sent %q, want nothing", err, s.sent)
	}
}

// The server's own error is the result, whole.
func TestKickClients_ReturnsTheServersError(t *testing.T) {
	s := &script{replies: []reply{{err: &ServerError{Code: errcode.ClientInvalidID}}}}
	err := NewCommands(s).KickClients(t.Context(), []ClientID{1, 9999}, ReasonKickServer, KickClientsOptions{})
	if !errors.Is(err, errcode.ClientInvalidID) {
		t.Errorf("err = %v, want InvalidClientID", err)
	}
}

func TestMoveClients(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.MoveClients(t.Context(), []ClientID{4, 9}, 7, MoveClientsOptions{ContinueOnError: true, Password: "pw"})
	})
	if want := "clientmove -continueonerror cid=7 cpw=pw clid=4|clid=9"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	line = encoded(t, func(c *Commands) error {
		return c.MoveClients(t.Context(), []ClientID{4}, 7, MoveClientsOptions{})
	})
	if want := "clientmove cid=7 clid=4"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	s := &script{}
	err := NewCommands(s).MoveClients(t.Context(), nil, 7, MoveClientsOptions{})
	if err != nil || len(s.sent) != 0 {
		t.Errorf("none: err = %v, sent %q", err, s.sent)
	}
}

func TestBanClients_ReturnsEveryIDTheServerReports(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"banid": "3"}, {"banid": "4"}, {"banid": "5"}}}}}
	got, err := NewCommands(s).BanClients(t.Context(), []ClientID{4, 9}, BanClientsOptions{
		Reason: "spam", Duration: time.Minute, ContinueOnError: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []BanID{3, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
	if want := "banclient -continueonerror time=60 banreason=spam clid=4|clid=9"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
}

// Over the voice protocol the server answers nothing, and the bans are made.
func TestBanClients_NoIDsIsNotNoBans(t *testing.T) {
	got, err := NewCommands(&script{}).BanClients(t.Context(), []ClientID{4}, BanClientsOptions{})
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v, want none and no error", got, err)
	}

	s := &script{replies: []reply{{err: &ServerError{Code: errcode.ClientInvalidID}}}}
	got, err = NewCommands(s).BanClients(t.Context(), []ClientID{4, 9999}, BanClientsOptions{})
	if !errors.Is(err, errcode.ClientInvalidID) || got != nil {
		t.Errorf("got %v, %v, want the server's error", got, err)
	}

	s = &script{}
	got, err = NewCommands(s).BanClients(t.Context(), nil, BanClientsOptions{})
	if err != nil || got != nil || len(s.sent) != 0 {
		t.Errorf("none: %v, %v, sent %q", got, err, s.sent)
	}
}

func TestServerGroupMembers(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.AddClientsToServerGroup(t.Context(), 9, []ClientDBID{3, 4, 5},
			ServerGroupMembersOptions{ContinueOnError: true})
	})
	if want := "servergroupaddclient -continueonerror sgid=9 cldbid=3|cldbid=4|cldbid=5"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	line = encoded(t, func(c *Commands) error {
		return c.RemoveClientsFromServerGroup(t.Context(), 9, []ClientDBID{3}, ServerGroupMembersOptions{})
	})
	if want := "servergroupdelclient sgid=9 cldbid=3"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	s := &script{}
	c := NewCommands(s)
	err := c.AddClientsToServerGroup(t.Context(), 9, nil, ServerGroupMembersOptions{})
	if err != nil {
		t.Error(err)
	}
	err = c.RemoveClientsFromServerGroup(t.Context(), 9, nil, ServerGroupMembersOptions{})
	if err != nil {
		t.Error(err)
	}
	if len(s.sent) != 0 {
		t.Errorf("none sent %q", s.sent)
	}
}

func TestPermissionBatches_Lines(t *testing.T) {
	flag := PermissionBatchOptions{ContinueOnError: true}
	entries := []PermissionEntry{
		{Permission: PermissionByName("i_a"), Value: 5},
		{Permission: PermissionByID(77), Value: -1},
	}
	skipped := []PermissionEntry{
		{Permission: PermissionByName("i_a"), Value: 5, Skip: true},
		{Permission: PermissionByName("i_b"), Value: 6},
	}
	both := []PermissionEntry{
		{Permission: PermissionByName("b_a"), Value: 1, Negated: true},
		{Permission: PermissionByName("b_b"), Value: 0, Skip: true},
	}
	names := []Permission{PermissionByName("i_a"), PermissionByID(77)}

	for _, tc := range []struct {
		run  func(c *Commands) error
		want string
	}{
		{func(c *Commands) error { return c.AddChannelPermissions(t.Context(), 3, entries, flag) },
			"channeladdperm -continueonerror cid=3 permsid=i_a permvalue=5|permid=77 permvalue=-1"},
		{func(c *Commands) error {
			return c.AddChannelPermissions(t.Context(), 3, entries, PermissionBatchOptions{})
		},
			"channeladdperm cid=3 permsid=i_a permvalue=5|permid=77 permvalue=-1"},
		{func(c *Commands) error { return c.DeleteChannelPermissions(t.Context(), 3, names) },
			"channeldelperm cid=3 permsid=i_a|permid=77"},
		{func(c *Commands) error { return c.AddChannelGroupPermissions(t.Context(), 8, entries, flag) },
			"channelgroupaddperm -continueonerror cgid=8 permsid=i_a permvalue=5|permid=77 permvalue=-1"},
		{func(c *Commands) error { return c.DeleteChannelGroupPermissions(t.Context(), 8, names, flag) },
			"channelgroupdelperm -continueonerror cgid=8 permsid=i_a|permid=77"},
		{func(c *Commands) error { return c.AddChannelClientPermissions(t.Context(), 3, 12, entries, flag) },
			"channelclientaddperm -continueonerror cid=3 cldbid=12 permsid=i_a permvalue=5|permid=77 permvalue=-1"},
		{func(c *Commands) error { return c.DeleteChannelClientPermissions(t.Context(), 3, 12, names) },
			"channelclientdelperm cid=3 cldbid=12 permsid=i_a|permid=77"},
		{func(c *Commands) error { return c.AddClientPermissions(t.Context(), 12, skipped, flag) },
			"clientaddperm -continueonerror cldbid=12 permsid=i_a permvalue=5 permskip=1|permsid=i_b permvalue=6 permskip=0"},
		{func(c *Commands) error { return c.DeleteClientPermissions(t.Context(), 12, names) },
			"clientdelperm cldbid=12 permsid=i_a|permid=77"},
		{func(c *Commands) error { return c.AddServerGroupPermissions(t.Context(), 9, both, flag) },
			"servergroupaddperm -continueonerror sgid=9 permsid=b_a permvalue=1 permnegated=1 permskip=0|" +
				"permsid=b_b permvalue=0 permnegated=0 permskip=1"},
		{func(c *Commands) error { return c.DeleteServerGroupPermissions(t.Context(), 9, names, flag) },
			"servergroupdelperm -continueonerror sgid=9 permsid=i_a|permid=77"},
		{func(c *Commands) error {
			return c.AddServerGroupPermissionsByType(t.Context(), GroupAutoUpdateServerAdmin, both)
		},
			"servergroupautoaddperm sgtype=45 permsid=b_a permvalue=1 permnegated=1 permskip=0|" +
				"permsid=b_b permvalue=0 permnegated=0 permskip=1"},
		{func(c *Commands) error {
			return c.DeleteServerGroupPermissionsByType(t.Context(), GroupAutoUpdateServerAdmin, names)
		}, "servergroupautodelperm sgtype=45 permsid=i_a|permid=77"},
	} {
		if got := encoded(t, tc.run); got != tc.want {
			t.Errorf("line = %q, want %q", got, tc.want)
		}
	}
}

// A flag the command does not take is refused rather than dropped, and so is
// an entry naming no permission.
func TestPermissionBatches_RefuseWhatTheyCannotSend(t *testing.T) {
	negated := []PermissionEntry{{Permission: PermissionByName("i_a"), Value: 1, Negated: true}}
	skipped := []PermissionEntry{{Permission: PermissionByName("i_a"), Value: 1, Skip: true}}
	none := []PermissionEntry{{Value: 1}}
	noName := []Permission{{}}
	flag := PermissionBatchOptions{}

	for name, run := range map[string]func(c *Commands) error{
		"channel negated": func(c *Commands) error { return c.AddChannelPermissions(t.Context(), 1, negated, flag) },
		"channel skip":    func(c *Commands) error { return c.AddChannelPermissions(t.Context(), 1, skipped, flag) },
		"channel group negated": func(c *Commands) error {
			return c.AddChannelGroupPermissions(t.Context(), 1, negated, flag)
		},
		"channel client skip": func(c *Commands) error {
			return c.AddChannelClientPermissions(t.Context(), 1, 2, skipped, flag)
		},
		"client negated":        func(c *Commands) error { return c.AddClientPermissions(t.Context(), 1, negated, flag) },
		"no permission":         func(c *Commands) error { return c.AddServerGroupPermissions(t.Context(), 1, none, flag) },
		"no permission by type": func(c *Commands) error { return c.AddServerGroupPermissionsByType(t.Context(), 45, none) },
		"delete no permission":  func(c *Commands) error { return c.DeleteChannelPermissions(t.Context(), 1, noName) },
		"delete client none":    func(c *Commands) error { return c.DeleteClientPermissions(t.Context(), 1, noName) },
		"delete by type no perm": func(c *Commands) error {
			return c.DeleteServerGroupPermissionsByType(t.Context(), 45, noName)
		},
	} {
		t.Run(name, func(t *testing.T) { refused(t, run) })
	}
}

func TestPermissionBatches_NoneSendsNothing(t *testing.T) {
	s := &script{}
	c := NewCommands(s)
	ctx := t.Context()
	flag := PermissionBatchOptions{ContinueOnError: true}
	errs := []error{
		c.AddChannelPermissions(ctx, 1, nil, flag),
		c.DeleteChannelPermissions(ctx, 1, nil),
		c.AddChannelGroupPermissions(ctx, 1, nil, flag),
		c.DeleteChannelGroupPermissions(ctx, 1, nil, flag),
		c.AddChannelClientPermissions(ctx, 1, 2, nil, flag),
		c.DeleteChannelClientPermissions(ctx, 1, 2, nil),
		c.AddClientPermissions(ctx, 1, nil, flag),
		c.DeleteClientPermissions(ctx, 1, nil),
		c.AddServerGroupPermissions(ctx, 1, nil, flag),
		c.DeleteServerGroupPermissions(ctx, 1, nil, flag),
		c.AddServerGroupPermissionsByType(ctx, 45, nil),
		c.DeleteServerGroupPermissionsByType(ctx, 45, nil),
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
	if len(s.sent) != 0 {
		t.Errorf("sent %q, want nothing", s.sent)
	}
}

// An unknown name is the server's refusal, not a false result: the lookup
// documents it so.
func TestGetPermissionIDByName_AnUnknownNameIsTheServersError(t *testing.T) {
	s := &script{replies: []reply{{err: &ServerError{Code: errcode.PermissionInvalidPermID}}}}
	id, found, err := NewCommands(s).GetPermissionIDByName(t.Context(), "b_nonexist")
	if !errors.Is(err, errcode.PermissionInvalidPermID) || found || id != 0 {
		t.Errorf("got %v, %v, %v, want the server's 2562", id, found, err)
	}
}
