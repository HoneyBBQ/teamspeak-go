package teamspeak

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Measured on TeamSpeak 3.13.8 and 6.0.0-beta13.1, which both send mytsid.
func TestListBans_ReadsTheMyTSIDAndPages(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"banid": "3", "created": "1792225115", "duration": "0", "enforcements": "7", "invokercldbid": "1",
		"invokername": "serveradmin", "invokeruid": "serveradmin", "ip": "", "lastnickname": "",
		"mytsid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "name": "", "reason": "x", "uid": "",
	}}}}}
	got, err := NewCommands(s).ListBans(t.Context(), BanListOptions{Start: 200, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if want := "banlist start=200 duration=100"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := BanEntry{
		ID: 3, Created: time.Unix(1792225115, 0), InvokerDatabaseID: 1, InvokerName: "serveradmin",
		InvokerUID: "serveradmin", Reason: "x", Enforcements: 7, MyTSID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("bans = %+v, want %+v", got, want)
	}
}

// A page past the last ban is answered 1281, which is an empty page.
func TestListBans_PagingEdges(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.ListBans(t.Context(), BanListOptions{})

		return err
	})
	if line != "banlist" {
		t.Errorf("an unpaged list sent %q, want the plain command", line)
	}

	past := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err := NewCommands(past).ListBans(t.Context(), BanListOptions{Start: 500})
	if err != nil || len(got) != 0 {
		t.Errorf("past the end = %v, %v, want none", got, err)
	}

	refused(t, func(c *Commands) error {
		_, err := c.ListBans(t.Context(), BanListOptions{Limit: -1})

		return err
	})
	refused(t, func(c *Commands) error {
		_, err := c.ListBans(t.Context(), BanListOptions{Start: -1})

		return err
	})
}

func TestAddBan_MyTSIDAndLastNickname(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, _, err := c.AddBan(t.Context(), BanOptions{
			IP: "5.5.5.6", MyTSID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", LastNickname: "Nick Name", Reason: "x",
		})

		return err
	})
	want := `banadd ip=5.5.5.6 mytsid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= banreason=x lastnickname=Nick\sName`
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	// A MyTeamSpeak id alone is a ban's whole target.
	line = encoded(t, func(c *Commands) error {
		_, _, err := c.AddBan(t.Context(), BanOptions{MyTSID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})

		return err
	})
	if line != `banadd mytsid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=` {
		t.Errorf("line = %q", line)
	}

	// A last nickname is no target.
	refused(t, func(c *Commands) error {
		_, _, err := c.AddBan(t.Context(), BanOptions{LastNickname: "x"})

		return err
	})
}

// Measured on TeamSpeak 6 over SSH.
func TestFindBans(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"banid": "2", "created": "1792225064", "duration": "0", "enforcements": "0", "invokercldbid": "1",
		"invokername": "serveradmin", "invokeruid": "serveradmin", "ip": "", "lastnickname": "Eve", "mytsid": "",
		"name": "", "reason": "r2", "uid": "oDWuWzuwALuLR6VXhEXF4AOpfm8=",
	}}}}}
	got, err := NewCommands(s).FindBans(t.Context(), BanCriteria{UID: "oDWuWzuwALuLR6VXhEXF4AOpfm8="})
	if err != nil {
		t.Fatal(err)
	}
	if want := `banfind uid=oDWuWzuwALuLR6VXhEXF4AOpfm8=`; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if len(got) != 1 || got[0].ID != 2 || got[0].LastNickname != "Eve" || got[0].UID != "oDWuWzuwALuLR6VXhEXF4AOpfm8=" {
		t.Errorf("bans = %+v", got)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.FindBans(t.Context(), BanCriteria{IP: "1.2.3.4", Name: "bad", MyTSID: "empty"})

		return err
	})
	if line != "banfind ip=1.2.3.4 name=bad mytsid=empty" {
		t.Errorf("line = %q", line)
	}

	// A search for nothing is refused before it is sent.
	refused(t, func(c *Commands) error {
		_, err := c.FindBans(t.Context(), BanCriteria{})

		return err
	})
}

func TestFindBans_NoneIsNotAnError(t *testing.T) {
	// The server answers none with 1281.
	none := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err := NewCommands(none).FindBans(t.Context(), BanCriteria{IP: "9.9.9.9"})
	if err != nil || len(got) != 0 {
		t.Errorf("no match = %v, %v, want none", got, err)
	}
}

func TestSendOfflineMessage(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.SendOfflineMessage(t.Context(), "oHhi9WzXLNEFQOwAu4JYKGU+C+c=", "Hi!", "Where are you?!?")
	})
	want := `messageadd cluid=oHhi9WzXLNEFQOwAu4JYKGU+C+c= subject=Hi! message=Where\sare\syou?!?`
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	// A recipient the server does not know is 512.
	unknown := &script{replies: []reply{{err: &ServerError{Code: errcode.ClientInvalidID}}}}
	err := NewCommands(unknown).SendOfflineMessage(t.Context(), "nobody", "s", "m")
	if !errors.Is(err, errcode.ClientInvalidID) {
		t.Errorf("err = %v, want the server's 512", err)
	}
}

// Measured on TeamSpeak 3.13.8 and 6.0.0-beta13.1: the list names who made the
// password under nickname and uid.
func TestListTempPasswords_ReadsTheCreator(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"nickname": "serveradmin", "uid": "serveradmin", "desc": "guest", "pw_clear": "s3cret",
		"start": "1792225115", "end": "1792228715", "tcid": "2", "tcpw": "",
	}}}}}
	got, err := NewCommands(s).ListTempPasswords(t.Context())
	if err != nil || len(got) != 1 {
		t.Fatalf("ListTempPasswords = %v, %v", got, err)
	}
	if got[0].CreatorNickname != "serveradmin" || got[0].CreatorUID != "serveradmin" || got[0].TargetChannelID != 2 {
		t.Errorf("password = %+v", got[0])
	}
}
