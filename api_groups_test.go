package teamspeak

import (
	"errors"
	"testing"
	"time"
)

// Measured on both servers: the answer names the permission and its value.
func TestGetOwnPermission(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"permid": "204", "permsid": "i_client_move_power", "permvalue": "100"},
	}}}}
	got, err := NewCommands(s).GetOwnPermission(t.Context(), PermissionByName("i_client_move_power"))
	if want := (OwnPermission{Name: "i_client_move_power", ID: 204, Value: 100}); err != nil || got != want {
		t.Errorf("got %+v, %v, want %+v", got, err, want)
	}
	if want := "permget permsid=i_client_move_power"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.GetOwnPermission(t.Context(), PermissionByID(211))

		return err
	})
	if line != "permget permid=211" {
		t.Errorf("line = %q", line)
	}

	refused(t, func(c *Commands) error {
		_, err := c.GetOwnPermission(t.Context(), Permission{})

		return err
	})
}

// A value of 0 is an answer, and no answer at all is not one.
func TestGetOwnPermission_ZeroAndNothing(t *testing.T) {
	zero := &script{replies: []reply{{rows: []map[string]string{{"permid": "221", "permvalue": "0"}}}}}
	got, err := NewCommands(zero).GetOwnPermission(t.Context(), PermissionByID(221))
	if want := (OwnPermission{ID: 221}); err != nil || got != want {
		t.Errorf("zero value = %+v, %v, want %+v", got, err, want)
	}

	_, err = NewCommands(&script{}).GetOwnPermission(t.Context(), PermissionByID(1))
	if !errors.Is(err, ErrNoData) {
		t.Errorf("no answer: err = %v, want ErrNoData", err)
	}
}

func TestServerGroupPermissionByType(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.AddServerGroupPermissionByType(t.Context(), GroupAutoUpdateServerAdmin,
			PermissionByName("i_client_poke_power"), 33, ServerGroupPermissionOptions{Skip: true})
	})
	want := "servergroupautoaddperm sgtype=45 permsid=i_client_poke_power permvalue=33 permnegated=0 permskip=1"
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	line = encoded(t, func(c *Commands) error {
		return c.DeleteServerGroupPermissionByType(t.Context(), GroupAutoUpdateChannelOperator, PermissionByID(211))
	})
	if line != "servergroupautodelperm sgtype=35 permid=211" {
		t.Errorf("line = %q", line)
	}

	refused(t, func(c *Commands) error {
		return c.AddServerGroupPermissionByType(t.Context(), GroupAutoUpdateServerAdmin, Permission{}, 1,
			ServerGroupPermissionOptions{})
	})
	refused(t, func(c *Commands) error {
		return c.DeleteServerGroupPermissionByType(t.Context(), GroupAutoUpdateServerAdmin, Permission{})
	})
}

func TestGroupAutoUpdateType_String(t *testing.T) {
	for _, tc := range []struct {
		want string
		in   GroupAutoUpdateType
	}{
		{"server admin", GroupAutoUpdateServerAdmin},
		{"channel guest", GroupAutoUpdateChannelGuest},
		{"query admin", GroupAutoUpdateQueryAdmin},
		{"group auto update type 99", 99},
		{"group auto update type 11", 11},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
}

func TestAddPrivilegeKey_SendsTheCustomSet(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"token": "jN0590MIBqRGPZPaEqzZmbT7JvzoUJOkdYR9knqu"}}}}}
	token, err := NewCommands(s).AddPrivilegeKey(t.Context(), PrivilegeKeyOptions{
		ServerGroupID: 9, Description: "cs",
		CustomSet: []CustomProperty{{Ident: "a", Value: "b"}, {Ident: "c", Value: "d e"}},
	})
	if err != nil || token != "jN0590MIBqRGPZPaEqzZmbT7JvzoUJOkdYR9knqu" {
		t.Fatalf("got %q, %v", token, err)
	}
	// Each value is escaped inside the set, and the set again as the parameter:
	// the space of "d e" is \\s on the wire, and the pipe between properties \p.
	want := `privilegekeyadd tokentype=0 tokenid1=9 tokenid2=0 tokendescription=cs ` +
		`tokencustomset=ident=a\svalue=b\pident=c\svalue=d\\se`
	if s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.AddPrivilegeKey(t.Context(), PrivilegeKeyOptions{ServerGroupID: 9})

		return err
	})
	if line != "privilegekeyadd tokentype=0 tokenid1=9 tokenid2=0" {
		t.Errorf("a key with no custom set sent %q", line)
	}
}

// Measured: tokenlist carries the custom set as the pipe-separated pairs.
func TestListPrivilegeKeys_ReadsTheCustomSet(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{
			"token": "kn+2Z", "token_created": "1792225305", "token_customset": `ident=a value=b|ident=c value=d\se`,
			"token_description": "", "token_id1": "9", "token_id2": "0", "token_type": "0",
		},
		{"token": "u5oU1", "token_created": "1792225253", "token_customset": "", "token_id1": "9", "token_type": "0"},
	}}}}
	got, err := NewCommands(s).ListPrivilegeKeys(t.Context())
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	want := []CustomProperty{{Ident: "a", Value: "b"}, {Ident: "c", Value: "d e"}}
	if len(got[0].CustomSet) != 2 || got[0].CustomSet[1] != want[1] || got[0].CustomSet[0] != want[0] {
		t.Errorf("custom set = %+v, want %+v", got[0].CustomSet, want)
	}
	if got[1].CustomSet != nil {
		t.Errorf("a key with none: custom set = %+v, want nil", got[1].CustomSet)
	}
	if !got[0].Created.Equal(time.Unix(1792225305, 0)) {
		t.Errorf("created = %v", got[0].Created)
	}
}
