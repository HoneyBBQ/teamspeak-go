package teamspeak

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// script is an Executor that answers each request with the next of its
// replies, and records what it was asked.
type script struct {
	replies []reply
	sent    []string
}

type reply struct {
	err  error
	rows []map[string]string
}

func (s *script) Send(_ context.Context, req Request) ([]map[string]string, error) {
	s.sent = append(s.sent, req.encode(func(pw string) string { return pw }))
	if len(s.replies) == 0 {
		return nil, nil
	}
	next := s.replies[0]
	s.replies = s.replies[1:]

	return next.rows, next.err
}

// encoded runs one command on a script and returns the line it sent.
func encoded(t *testing.T, run func(c *Commands) error) string {
	t.Helper()
	s := &script{}
	err := run(NewCommands(s))
	// The script answers nothing, which a command defined to answer with a
	// row reports; only the line it sent matters here.
	if err != nil && !errors.Is(err, ErrNoData) {
		t.Fatalf("command failed: %v", err)
	}
	if len(s.sent) != 1 {
		t.Fatalf("sent %d commands, want 1", len(s.sent))
	}

	return s.sent[0]
}

// refused runs one command that must be refused before anything is sent.
func refused(t *testing.T, run func(c *Commands) error) {
	t.Helper()
	s := &script{}
	err := run(NewCommands(s))
	if !errors.Is(err, ErrInvalidCommand) {
		t.Errorf("err = %v, want ErrInvalidCommand", err)
	}
	if len(s.sent) != 0 {
		t.Errorf("sent %q, want nothing", s.sent)
	}
}

func TestDurationArg_RoundsToTheUnit(t *testing.T) {
	for _, tc := range []struct {
		want string
		in   time.Duration
	}{
		{"0", 0},
		{"1", time.Second},
		{"1", 1499 * time.Millisecond},
		{"2", 1500 * time.Millisecond},
		{"5400", 90 * time.Minute},
		// Rounding down would send 0, which a ban reads as permanent.
		{"1", 400 * time.Millisecond},
		{"1", time.Nanosecond},
	} {
		got := durationArg("time", tc.in, time.Second)
		if got.err != nil || got.Value == nil || *got.Value != tc.want {
			t.Errorf("durationArg(%v) = %+v, want %s", tc.in, got, tc.want)
		}
	}

	if got := durationArg("time", -time.Second, time.Second); !errors.Is(got.err, ErrInvalidCommand) {
		t.Errorf("negative duration: err = %v, want ErrInvalidCommand", got.err)
	}
}

func TestBanDurations(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.BanClient(t.Context(), 7, BanClientOptions{Duration: 1500 * time.Millisecond})

		return err
	})
	if line != "banclient clid=7 time=2" {
		t.Errorf("timed ban = %q", line)
	}

	line = encoded(t, func(c *Commands) error {
		_, err := c.AddBan(t.Context(), BanOptions{Name: "spammer.*", Reason: "spam"})

		return err
	})
	if line != `banadd name=spammer.* banreason=spam` {
		t.Errorf("permanent ban = %q", line)
	}

	refused(t, func(c *Commands) error {
		_, err := c.AddBan(t.Context(), BanOptions{Reason: "matches nobody"})

		return err
	})
	refused(t, func(c *Commands) error {
		_, err := c.BanClient(t.Context(), 7, BanClientOptions{Duration: -time.Second})

		return err
	})
}

func TestFieldTime(t *testing.T) {
	want := time.Unix(1791774643, 0)
	for _, tc := range []struct {
		want time.Time
		raw  string
	}{
		{time.Time{}, ""},
		{time.Time{}, "0"},
		{time.Time{}, "-1"},
		{want, "1791774643"},
		// TS6 sends ftgetfilelist's datetime in milliseconds and
		// ftgetfileinfo's in nanoseconds.
		{want, "1791774643000"},
		{want, "1791774643000000"},
		{want, "1791774643000000000"},
	} {
		got := fieldTime(map[string]string{"t": tc.raw}, "t")
		if !got.Equal(tc.want) || got.IsZero() != tc.want.IsZero() {
			t.Errorf("fieldTime(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestFieldDuration(t *testing.T) {
	row := map[string]string{"client_idle_time": "2245", "duration": "600", "huge": "18446744073709551615"}
	if got := fieldDuration(row, "client_idle_time", time.Millisecond); got != 2245*time.Millisecond {
		t.Errorf("idle time = %v", got)
	}
	if got := fieldDuration(row, "duration", time.Second); got != 10*time.Minute {
		t.Errorf("ban duration = %v", got)
	}
	if got := fieldDuration(row, "huge", time.Second); got <= 0 {
		t.Errorf("overflowing duration = %v, want it clamped", got)
	}
}

// The server sends an icon's CRC32 either unsigned or reinterpreted as a
// signed 32-bit number.
func TestFieldIconID(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want IconID
	}{
		{"", 0},
		{"0", 0},
		{"300", 300},
		{"2290254978", 2290254978},
		{"-2004712318", 2290254978},
		{"-1", 0xFFFFFFFF},
		{"4294967296", 0},
		{"garbage", 0},
	} {
		if got := fieldIconID(map[string]string{"iconid": tc.raw}, "iconid"); got != tc.want {
			t.Errorf("fieldIconID(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestPermission_EncodesAsIDOrName(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.AddChannelPermission(t.Context(), 3, PermissionByName("i_channel_needed_join_power"), 50)
	})
	if line != "channeladdperm cid=3 permsid=i_channel_needed_join_power permvalue=50" {
		t.Errorf("by name = %q", line)
	}

	line = encoded(t, func(c *Commands) error {
		return c.DeleteServerGroupPermission(t.Context(), 6, PermissionByID(42))
	})
	if line != "servergroupdelperm sgid=6 permid=42" {
		t.Errorf("by id = %q", line)
	}
}

// A zero Permission names nothing, so it is refused rather than sent.
func TestPermission_ZeroIsRefused(t *testing.T) {
	refused(t, func(c *Commands) error {
		return c.AddClientPermission(t.Context(), 9, Permission{}, 1, ClientPermissionOptions{})
	})
	refused(t, func(c *Commands) error {
		_, err := c.FindPermission(t.Context(), PermissionByName(""))

		return err
	})
	refused(t, func(c *Commands) error {
		return c.AddServerGroupPermission(t.Context(), 6, Permission{}, 1, ServerGroupPermissionOptions{})
	})
}

func TestParsePermission_NamesTheEntryAsSent(t *testing.T) {
	byID := parsePermission(map[string]string{"permid": "42", "permvalue": "-1", "permskip": "1"})
	if byID.Permission != PermissionByID(42) || byID.Value != -1 || !byID.Skip {
		t.Errorf("by id = %+v", byID)
	}
	byName := parsePermission(map[string]string{"permsid": "b_client_ignore_bans", "permvalue": "1"})
	if byName.Permission != PermissionByName("b_client_ignore_bans") {
		t.Errorf("by name = %+v", byName)
	}
}

func TestKickClient(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.KickClient(t.Context(), 5, ReasonKickServer, ClientKickOptions{ReasonMessage: "bye now"})
	})
	if line != `clientkick clid=5 reasonid=5 reasonmsg=bye\snow` {
		t.Errorf("kick = %q", line)
	}

	line = encoded(t, func(c *Commands) error {
		return c.KickClient(t.Context(), 5, ReasonKickChannel, ClientKickOptions{})
	})
	if line != "clientkick clid=5 reasonid=4" {
		t.Errorf("kick without a message = %q", line)
	}

	refused(t, func(c *Commands) error {
		return c.KickClient(t.Context(), 5, ReasonKickServerBan, ClientKickOptions{})
	})
}

func TestPrivilegeKeyOptions(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.AddPrivilegeKey(t.Context(), PrivilegeKeyOptions{ChannelGroupID: 5, ChannelID: 2})

		return err
	})
	if line != "privilegekeyadd tokentype=1 tokenid1=5 tokenid2=2" {
		t.Errorf("channel group key = %q", line)
	}

	refused(t, func(c *Commands) error {
		_, err := c.AddPrivilegeKey(t.Context(), PrivilegeKeyOptions{ServerGroupID: 6, ChannelID: 2})

		return err
	})
	refused(t, func(c *Commands) error {
		_, err := c.AddPrivilegeKey(t.Context(), PrivilegeKeyOptions{ChannelGroupID: 5})

		return err
	})
}

func TestViewLog_ReadsOneLinePerRow(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"last_pos": "4096", "file_size": "8192", "l": "first"},
		{"l": "second"},
	}}}}
	page, err := NewCommands(s).ViewLog(t.Context(), LogViewOptions{Lines: 2, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) != 2 || page.Lines[1] != "second" || page.LastPosition != 4096 {
		t.Errorf("page = %+v", page)
	}
	if s.sent[0] != "logview reverse=1 instance=0 lines=2" {
		t.Errorf("request = %q", s.sent[0])
	}
}

func TestEnumStrings(t *testing.T) {
	for _, tc := range []struct {
		value interface{ String() string }
		want  string
	}{
		{GroupRegular, "regular"},
		{GroupType(9), "group type 9"},
		{TextMessageTargetChannel, "channel"},
		{TextMessageTarget(0), "text message target 0"},
		{LogLevelWarning, "warning"},
		{CodecOpusMusic, "Opus music"},
		{PrivilegeKeyChannelGroup, "channel group"},
		{PermissionTargetChannelClient, "channel client"},
		{PermissionByName("i_client_talk_power"), "i_client_talk_power"},
		{Permission{}, "no permission"},
	} {
		if got := tc.value.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func dbPage(start, n int) []map[string]string {
	rows := make([]map[string]string, n)
	for i := range rows {
		rows[i] = map[string]string{"cldbid": strconv.Itoa(start + i + 1), "client_created": "1791774523"}
	}

	return rows
}

func collect(t *testing.T, s *script, limit int) ([]ClientDatabaseEntry, error) {
	t.Helper()
	var entries []ClientDatabaseEntry
	for entry, err := range NewCommands(s).ClientDatabase(t.Context()) {
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
		if len(entries) == limit {
			break
		}
	}

	return entries, nil
}

// The server ends the database with 1281 rather than an empty page.
func TestClientDatabase_StopsOnEmptyResult(t *testing.T) {
	s := &script{replies: []reply{
		{rows: dbPage(0, clientDatabasePageSize)},
		{rows: dbPage(clientDatabasePageSize, clientDatabasePageSize)},
		{err: &ServerError{Code: errcode.DatabaseEmptyResult}},
	}}
	entries, err := collect(t, s, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*clientDatabasePageSize || entries[150].DatabaseID != 151 {
		t.Errorf("got %d entries", len(entries))
	}
	if entries[0].Created.Unix() != 1791774523 {
		t.Errorf("Created = %v", entries[0].Created)
	}
	want := []string{
		"clientdblist start=0 duration=100",
		"clientdblist start=100 duration=100",
		"clientdblist start=200 duration=100",
	}
	if len(s.sent) != len(want) || s.sent[1] != want[1] || s.sent[2] != want[2] {
		t.Errorf("requests = %q, want %q", s.sent, want)
	}
}

// A short page after a full one is the last; a short first page might be the
// server's cap, so it is followed up.
func TestClientDatabase_StopsOnAShortPage(t *testing.T) {
	s := &script{replies: []reply{
		{rows: dbPage(0, 25)},
		{rows: dbPage(25, 25)},
		{rows: dbPage(50, 3)},
	}}
	entries, err := collect(t, s, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 53 || len(s.sent) != 3 {
		t.Errorf("got %d entries in %d requests, want 53 in 3", len(entries), len(s.sent))
	}
	if s.sent[1] != "clientdblist start=25 duration=100" {
		t.Errorf("second request = %q", s.sent[1])
	}
}

func TestClientDatabase_YieldsAnErrorAndStops(t *testing.T) {
	refusal := &ServerError{Code: errcode.PermissionsClientInsufficient}
	s := &script{replies: []reply{
		{rows: dbPage(0, clientDatabasePageSize)},
		{err: refusal},
		{rows: dbPage(clientDatabasePageSize, 1)},
	}}
	entries, err := collect(t, s, -1)
	if !errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Errorf("err = %v, want the refusal", err)
	}
	if len(entries) != clientDatabasePageSize || len(s.sent) != 2 {
		t.Errorf("got %d entries in %d requests", len(entries), len(s.sent))
	}
}

func TestClientDatabase_StopsWhenTheLoopDoes(t *testing.T) {
	s := &script{replies: []reply{
		{rows: dbPage(0, clientDatabasePageSize)},
		{rows: dbPage(clientDatabasePageSize, clientDatabasePageSize)},
	}}
	entries, err := collect(t, s, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 || len(s.sent) != 1 {
		t.Errorf("got %d entries in %d requests, want 10 in 1", len(entries), len(s.sent))
	}
}

// The server reports an empty list as error 1281 rather than as no rows, which
// made every list method fail where it should have returned nothing.
func TestLists_AnEmptyResultIsNoRowsNotAnError(t *testing.T) {
	empty := &ServerError{Code: errcode.DatabaseEmptyResult, Message: "database empty result set"}
	c := NewCommands(&script{replies: []reply{{err: empty}, {err: empty}}})

	bans, err := c.ListBans(t.Context())
	if err != nil || len(bans) != 0 {
		t.Errorf("ListBans = %v, %v; want no bans and no error", bans, err)
	}
	ids, err := c.FindClientDatabase(t.Context(), "nobody")
	if err != nil || len(ids) != 0 {
		t.Errorf("FindClientDatabase = %v, %v; want no ids and no error", ids, err)
	}

	other := &ServerError{Code: errcode.PermissionsClientInsufficient}
	_, err = NewCommands(&script{replies: []reply{{err: other}}}).ListBans(t.Context())
	if !errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Errorf("ListBans = %v, want the refusal passed through", err)
	}
}

// AddTempPassword used to send an empty pw, believing the server generates
// the password; it does not.
func TestAddTempPassword_SendsThePasswordAndRefusesNone(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.AddTempPassword(t.Context(), TempPasswordOptions{Password: "letmein", Duration: time.Hour})
	})
	if !strings.Contains(line, "pw=letmein") || !strings.Contains(line, "duration=3600") {
		t.Errorf("sent %q", line)
	}
	refused(t, func(c *Commands) error {
		return c.AddTempPassword(t.Context(), TempPasswordOptions{Duration: time.Hour})
	})
}

// Several files are a row group, name=…|name=…, as the server takes a list.
// One parameter joining the names escaped each pipe, and the server read it
// as a single file.
func TestDeleteFile_SendsARowGroup(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.DeleteFile(t.Context(), 3, []string{"/a b", "c"}, FileOptions{})
	})
	if want := `ftdeletefile cid=3 cpw= name=\/a\sb|name=\/c`; line != want {
		t.Errorf("DeleteFile sent %q, want %q", line, want)
	}
}

// A command defined to answer with a row fails with ErrNoData when the server
// acknowledges it without one, or without the field that row must hold.
func TestRequiredRowsFailWithErrNoData(t *testing.T) {
	calls := map[string]func(c *Commands) error{
		"CreateChannel": func(c *Commands) error {
			return errOf(c.CreateChannel(t.Context(), ChannelCreateOptions{Name: "x"}))
		},
		"GetChannelInfo": func(c *Commands) error {
			return errOf(c.GetChannelInfo(t.Context(), 1))
		},
		"GetClientInfo": func(c *Commands) error {
			return errOf(c.GetClientInfo(t.Context(), 1))
		},
		"GetClientDBIDByUID": func(c *Commands) error {
			return errOf(c.GetClientDBIDByUID(t.Context(), "u"))
		},
		"GetClientUIDByID": func(c *Commands) error {
			return errOf(c.GetClientUIDByID(t.Context(), 1))
		},
		"GetClientNameByDBID": func(c *Commands) error {
			return errOf(c.GetClientNameByDBID(t.Context(), 1))
		},
		"GetClientNameByUID": func(c *Commands) error {
			_, _, err := c.GetClientNameByUID(t.Context(), "u")

			return err
		},
		"GetServerIDByPort": func(c *Commands) error {
			return errOf(c.GetServerIDByPort(t.Context(), 9987))
		},
		"GetMessage": func(c *Commands) error {
			return errOf(c.GetMessage(t.Context(), 1))
		},
		"AddBan": func(c *Commands) error {
			return errOf(c.AddBan(t.Context(), BanOptions{IP: "1.2.3.4"}))
		},
		"InitFileUpload": func(c *Commands) error {
			return errOf(c.InitFileUpload(t.Context(), 1, "/a", 1, FileUploadOptions{}))
		},
		"InitFileDownload": func(c *Commands) error {
			return errOf(c.InitFileDownload(t.Context(), 1, "/a", FileDownloadOptions{}))
		},
		"GetServerInfo": func(c *Commands) error {
			return errOf(c.GetServerInfo(t.Context()))
		},
		"LogView": func(c *Commands) error {
			return errOf(c.ViewLog(t.Context(), LogViewOptions{}))
		},
	}
	for name, call := range calls {
		for _, rows := range [][]map[string]string{nil, {{"unrelated": "1"}}} {
			if name == "GetChannelInfo" || name == "GetClientInfo" || name == "GetMessage" ||
				name == "GetServerInfo" || name == "LogView" || name == "GetClientNameByDBID" {
				if rows != nil {
					continue // any row will do for these
				}
			}
			err := call(NewCommands(&script{replies: []reply{{rows: rows}}}))
			if !errors.Is(err, ErrNoData) {
				t.Errorf("%s answered with %v: %v, want ErrNoData", name, rows, err)
			}
		}
	}
}

// errOf is the error of a call that also returns a value.
func errOf[T any](_ T, err error) error { return err }

// The server answers banclient with one banid per ban it created, two or
// three; BanClient returns them all.
func TestBanClientReturnsEveryBan(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"banid": "12"}, {"banid": "13"}, {"banid": "14"}}}}}
	ids, err := NewCommands(s).BanClient(t.Context(), 7, BanClientOptions{})
	if err != nil || !slices.Equal(ids, []BanID{12, 13, 14}) {
		t.Fatalf("BanClient = %v, %v; want [12 13 14]", ids, err)
	}
}

// Every list answers 1281 with an empty result, the permission lists among
// them.
func TestEveryListTreatsAnEmptyResultAsEmpty(t *testing.T) {
	empty := &ServerError{Code: errcode.DatabaseEmptyResult}
	lists := map[string]func(c *Commands) error{
		"ListChannelPermissions": func(c *Commands) error {
			return errOf(c.ListChannelPermissions(t.Context(), 1))
		},
		"ListChannelClientPermissions": func(c *Commands) error {
			return errOf(c.ListChannelClientPermissions(t.Context(), 1, 2))
		},
		"ListClientPermissions": func(c *Commands) error {
			return errOf(c.ListClientPermissions(t.Context(), 1))
		},
		"ListChannelGroupPermissions": func(c *Commands) error {
			return errOf(c.ListChannelGroupPermissions(t.Context(), 1))
		},
		"ListServerGroupPermissions": func(c *Commands) error {
			return errOf(c.ListServerGroupPermissions(t.Context(), 1))
		},
		"ListFiles": func(c *Commands) error {
			return errOf(c.ListFiles(t.Context(), 1, "/", FileOptions{}))
		},
		"GetClientIDs":            func(c *Commands) error { return errOf(c.GetClientIDs(t.Context(), "u")) },
		"GetServerGroupsByClient": func(c *Commands) error { return errOf(c.GetServerGroupsByClient(t.Context(), 1)) },
		"ListBindings": func(c *Commands) error {
			return errOf(c.ListBindings(t.Context(), BindingListOptions{}))
		},
		"ListChannels":      func(c *Commands) error { return errOf(c.ListChannels(t.Context())) },
		"ListChannelGroups": func(c *Commands) error { return errOf(c.ListChannelGroups(t.Context())) },
		"ListServerGroups":  func(c *Commands) error { return errOf(c.ListServerGroups(t.Context())) },
		"ListPermissions":   func(c *Commands) error { return errOf(c.ListPermissions(t.Context())) },
		"ListClients": func(c *Commands) error {
			return errOf(c.ListClients(t.Context(), ClientListOptions{}))
		},
	}
	for name, call := range lists {
		err := call(NewCommands(&script{replies: []reply{{err: empty}}}))
		if err != nil {
			t.Errorf("%s on 1281 = %v, want an empty result", name, err)
		}
	}
}

// An upload does not replace an existing file unless asked to.
func TestInitFileUploadDoesNotOverwriteByDefault(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return errOf(c.InitFileUpload(t.Context(), 1, "/a.txt", 3, FileUploadOptions{}))
	})
	if !strings.Contains(line, " overwrite=0") {
		t.Errorf("sent %q, want overwrite=0", line)
	}
}
