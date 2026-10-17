package teamspeak

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Measured on TeamSpeak 3.13.8: the key is in the answer to apikeyadd, and
// only there.
func TestAddAPIKey_SendsTheScopeAndReadsTheKey(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"apikey": "AQBBYaL4keWjtRLE9XxcJMh_Q3mZWrEMRit1UpD", "cldbid": "1", "created_at": "1792224770",
		"expires_at": "1792311170", "id": "2", "scope": "read", "sid": "1", "time_left": "86399",
	}}}}}
	lifetime := 24 * time.Hour
	got, err := NewCommands(s).AddAPIKey(t.Context(), APIKeyOptions{
		Scope: APIKeyScopeRead, Lifetime: &lifetime, OwnerDatabaseID: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "apikeyadd scope=read lifetime=1 cldbid=3"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := APIKeyCreated{
		Key: "AQBBYaL4keWjtRLE9XxcJMh_Q3mZWrEMRit1UpD",
		APIKey: APIKey{
			ID: 2, ServerID: 1, OwnerDatabaseID: 1, Scope: APIKeyScopeRead,
			Created: time.Unix(1792224770, 0), Expires: time.Unix(1792311170, 0), TimeLeft: 86399 * time.Second,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("key = %+v, want %+v", got, want)
	}
}

// A lifetime of 0 means no expiry, and the server then answers
// time_left=unlimited and an expires_at equal to created_at. TeamSpeak 6 adds
// custom_id.
func TestAddAPIKey_ReadsAKeyThatNeverExpires(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"apikey": "AgAUttfReJydCvd2NTqPJuHS6MFA5ySuMM6YKQa", "cldbid": "1", "created_at": "1792224770", "custom_id": "",
		"expires_at": "1792224770", "id": "4", "scope": "write", "sid": "1", "time_left": "unlimited",
	}}}}}
	never := time.Duration(0)
	got, err := NewCommands(s).AddAPIKey(t.Context(), APIKeyOptions{Scope: APIKeyScopeWrite, Lifetime: &never})
	if err != nil {
		t.Fatal(err)
	}
	if want := "apikeyadd scope=write lifetime=0"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if !got.Unlimited || !got.Expires.IsZero() || got.TimeLeft != 0 || got.Scope != APIKeyScopeWrite {
		t.Errorf("key = %+v, want an unlimited one with no expiry", got)
	}
}

func TestAddAPIKey_LeavesTheLifetimeToTheServer(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.AddAPIKey(t.Context(), APIKeyOptions{Scope: APIKeyScopeManage})

		return err
	})
	if line != "apikeyadd scope=manage" {
		t.Errorf("line = %q", line)
	}
	refused(t, func(c *Commands) error {
		_, err := c.AddAPIKey(t.Context(), APIKeyOptions{})

		return err
	})
	// Rounding a positive lifetime down to 0 would make the key permanent.
	short := time.Hour
	line = encoded(t, func(c *Commands) error {
		_, err := c.AddAPIKey(t.Context(), APIKeyOptions{Scope: APIKeyScopeRead, Lifetime: &short})

		return err
	})
	if line != "apikeyadd scope=read lifetime=1" {
		t.Errorf("line = %q, want a one-hour lifetime sent as one day", line)
	}
}

func TestListAPIKeys(t *testing.T) {
	rows := []map[string]string{
		{"cldbid": "1", "created_at": "1792224770", "custom_id": "", "expires_at": "1792311170", "id": "2",
			"scope": "read", "sid": "1", "time_left": "86371"},
		{"cldbid": "1", "created_at": "1792224770", "custom_id": "", "expires_at": "1792224770", "id": "4",
			"scope": "write", "sid": "1", "time_left": "unlimited"},
	}
	s := &script{replies: []reply{{rows: rows}}}
	got, err := NewCommands(s).ListAPIKeys(t.Context(), APIKeyListOptions{Start: 1, Limit: 2, AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := "apikeylist start=1 duration=2 cldbid=*"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if len(got) != 2 || got[0].ID != 2 || got[0].TimeLeft != 86371*time.Second || !got[1].Unlimited {
		t.Errorf("keys = %+v", got)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.ListAPIKeys(t.Context(), APIKeyListOptions{OwnerDatabaseID: 5})

		return err
	})
	if line != "apikeylist cldbid=5" {
		t.Errorf("line = %q", line)
	}
	refused(t, func(c *Commands) error {
		_, err := c.ListAPIKeys(t.Context(), APIKeyListOptions{OwnerDatabaseID: 5, AllOwners: true})

		return err
	})
	refused(t, func(c *Commands) error {
		_, err := c.ListAPIKeys(t.Context(), APIKeyListOptions{Start: -1})

		return err
	})
}

// A server with no keys answers 1281, which is none, not a failure.
func TestListAPIKeys_NoneIsNotAnError(t *testing.T) {
	s := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err := NewCommands(s).ListAPIKeys(t.Context(), APIKeyListOptions{})
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v, want none", got, err)
	}
}

func TestDeleteAPIKey(t *testing.T) {
	line := encoded(t, func(c *Commands) error { return c.DeleteAPIKey(t.Context(), 4) })
	if line != "apikeydel id=4" {
		t.Errorf("line = %q", line)
	}
}

// Measured on both servers: with no server selected the answer carries the
// sid of 0, with one it carries that server's.
func TestAddQueryLogin(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"cldbid": "3", "client_login_name": "ctwuser", "client_login_password": "Z5s6xSMT", "sid": "1",
	}}}}}
	got, err := NewCommands(s).AddQueryLogin(t.Context(), "ctwuser", QueryLoginOptions{DatabaseID: 3})
	if err != nil {
		t.Fatal(err)
	}
	if want := "queryloginadd client_login_name=ctwuser cldbid=3"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := QueryLoginCreated{
		Password:   "Z5s6xSMT",
		QueryLogin: QueryLogin{Name: "ctwuser", DatabaseID: 3, ServerID: 1},
	}
	if got != want {
		t.Errorf("login = %+v, want %+v", got, want)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.AddQueryLogin(t.Context(), "global one", QueryLoginOptions{})

		return err
	})
	if line != `queryloginadd client_login_name=global\sone` {
		t.Errorf("line = %q", line)
	}
}

func TestListQueryLogins(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"cldbid": "1", "client_login_name": "serveradmin", "sid": "0"},
		{"cldbid": "7", "client_login_name": "ctwglobal", "sid": "0"},
	}}}}
	got, err := NewCommands(s).ListQueryLogins(t.Context(), QueryLoginListOptions{Pattern: "ctw%", Start: 1, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := "queryloginlist start=1 duration=1 pattern=ctw%"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := []QueryLogin{{Name: "serveradmin", DatabaseID: 1}, {Name: "ctwglobal", DatabaseID: 7}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logins = %+v, want %+v", got, want)
	}

	none := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err = NewCommands(none).ListQueryLogins(t.Context(), QueryLoginListOptions{})
	if err != nil || len(got) != 0 {
		t.Errorf("empty = %v, %v", got, err)
	}
}

func TestDeleteQueryLogin(t *testing.T) {
	line := encoded(t, func(c *Commands) error { return c.DeleteQueryLogin(t.Context(), 7) })
	if line != "querylogindel cldbid=7" {
		t.Errorf("line = %q", line)
	}
}

// The answer holds only the password, so the name is the one asked for.
func TestSetQueryLogin(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"client_login_password": "jD0xrrLY"}}}}}
	got, err := NewCommands(s).SetQueryLogin(t.Context(), "ctwsrv2")
	if err != nil {
		t.Fatal(err)
	}
	if want := "clientsetserverquerylogin client_login_name=ctwsrv2"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if want := (QueryLoginCreated{Password: "jD0xrrLY", QueryLogin: QueryLogin{Name: "ctwsrv2"}}); got != want {
		t.Errorf("login = %+v, want %+v", got, want)
	}

	empty := &script{}
	_, err = NewCommands(empty).SetQueryLogin(t.Context(), "x")
	if !errors.Is(err, ErrNoData) {
		t.Errorf("an answer with no password: err = %v, want ErrNoData", err)
	}
}
