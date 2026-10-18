package servernotify_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/servernotify"
)

func TestParseUint64_Valid(t *testing.T) {
	v, err := servernotify.ParseUint64("42")
	if err != nil || v != 42 {
		t.Fatalf("ParseUint64(\"42\") = %d, %v; want 42", v, err)
	}
	v, err = servernotify.ParseUint64("0")
	if err != nil || v != 0 {
		t.Fatalf("ParseUint64(\"0\") = %d, %v; want 0", v, err)
	}
}

func TestParseUint64_Invalid_ReturnsError(t *testing.T) {
	for _, raw := range []string{"abc", ""} {
		_, err := servernotify.ParseUint64(raw)
		if err == nil {
			t.Errorf("ParseUint64(%q) accepted what is not a number", raw)
		}
	}
}

// A channel id is 0 to 2^64-1 in plain decimal; a sign, a prefix, a fraction or
// a value that does not fit names no channel, and reads as 0 without an error
// for the caller to forget.
func TestParseChannelID_ReadsOnlyPlainDecimalUint64(t *testing.T) {
	cases := map[string]uint64{
		"0":                          0,
		"42":                         42,
		"18446744073709551615":       18446744073709551615,
		"000000000000000000000042":   42,
		"":                           0,
		"-1":                         0,
		"+5":                         0,
		"0x10":                       0,
		"1e3":                        0,
		"1.5":                        0,
		"1_000":                      0,
		"18446744073709551616":       0,
		"-18446744073709551616":      0,
		"0x1ffffffffffffffff":        0,
		"99999999999999999999999999": 0,
	}
	for raw, want := range cases {
		if got := servernotify.ParseChannelID(raw); uint64(got) != want {
			t.Errorf("ParseChannelID(%q) = %d, want %d", raw, got, want)
		}
	}
	// A leading space is not a number, however a whitespace-trimming parser
	// might read it.
	if got := servernotify.ParseChannelID(" 5"); got != 0 {
		t.Errorf("ParseChannelID(\" 5\") = %d, want 0", got)
	}
}

// A client id is a whole 16-bit number: the server's clid, invokerid and
// client_id fields are all one, and a value that does not fit names no client.
func TestParseClientID(t *testing.T) {
	cases := map[string]teamspeak.ClientID{
		"1":     1,
		"65535": 65535,
		"0":     0,
		"":      0,
		"65536": 0,
		"-1":    0,
		"1.0":   0,
		"abc":   0,
	}
	for raw, want := range cases {
		if got := servernotify.ParseClientID(raw); got != want {
			t.Errorf("ParseClientID(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestParseInt(t *testing.T) {
	got, err := servernotify.ParseInt("4")
	if err != nil || got != 4 {
		t.Errorf("ParseInt(\"4\") = %d, %v; want 4", got, err)
	}
	for _, raw := range []string{"", "x"} {
		_, err = servernotify.ParseInt(raw)
		if err == nil {
			t.Errorf("ParseInt(%q) accepted what is not a number", raw)
		}
	}
}

// An id that does not parse is left out; ending the list there would drop the
// groups after it.
func TestParseIDList(t *testing.T) {
	got := servernotify.ParseIDList[teamspeak.ServerGroupID]("6,7,8")
	if want := []teamspeak.ServerGroupID{6, 7, 8}; !reflect.DeepEqual(got, want) {
		t.Errorf("ParseIDList = %v, want %v", got, want)
	}
	if got := servernotify.ParseIDList[teamspeak.ServerGroupID](""); got != nil {
		t.Errorf("ParseIDList(\"\") = %v, want nil", got)
	}
}

// The fields a notifycliententerview carries; a row the parser is handed has
// already been resolved by wire.SplitRows, so every field is present.
func TestClientEnter(t *testing.T) {
	got := servernotify.ClientEnter(map[string]string{
		"clid":                     "4",
		"client_nickname":          "Ann",
		"client_unique_identifier": "uid=",
		"ctid":                     "9",
		"client_channel_group_id":  "10",
		"client_type":              "0",
		"client_servergroups":      "6,7",
		"client_away":              "1",
		"client_is_recording":      "0",
		"client_is_talker":         "1",
	})

	want := teamspeak.ClientEntry{
		ID:             4,
		Nickname:       "Ann",
		UID:            "uid=",
		ChannelID:      9,
		ChannelGroupID: 10,
		Type:           teamspeak.ClientTypeVoice,
		ServerGroups:   []teamspeak.ServerGroupID{6, 7},
		IsAway:         true,
		IsTalker:       true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientEnter = %+v, want %+v", got, want)
	}
}

func TestClientLeave(t *testing.T) {
	got := servernotify.ClientLeave(map[string]string{
		"clid": "4", "reasonid": "5", "reasonmsg": "bye",
		"invokerid": "7", "invokername": "Bob", "invokeruid": "uid",
	})
	want := teamspeak.ClientLeaveEvent{
		ClientID: 4, Reason: teamspeak.ReasonKickServer, ReasonMessage: "bye",
		InvokerID: 7, InvokerName: "Bob", InvokerUID: "uid",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientLeave = %+v, want %+v", got, want)
	}
}

// A move of the client's own names no invoker, so those fields read as their
// zero values rather than being left out of the event.
func TestClientMoved_ReadsAMoveWithNoInvoker(t *testing.T) {
	got := servernotify.ClientMoved(map[string]string{"clid": "4", "ctid": "9", "reasonid": "0"})
	want := teamspeak.ClientMovedEvent{ClientID: 4, TargetChannelID: 9}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientMoved = %+v, want %+v", got, want)
	}
}

// A channel kick arrives as a move, so the kick is built from the same
// parameters the move was.
func TestKicked_ReadsAChannelKick(t *testing.T) {
	params := map[string]string{
		"clid": "4", "ctid": "9", "reasonid": "4", "reasonmsg": "out",
		"invokerid": "7", "invokername": "Bob", "invokeruid": "uid",
	}
	got := servernotify.Kicked(teamspeak.Reason(4), params)
	want := teamspeak.KickedEvent{
		ReasonMessage: "out", InvokerName: "Bob", InvokerUID: "uid",
		Reason: teamspeak.Reason(4), InvokerID: 7,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Kicked = %+v, want %+v", got, want)
	}
}

// The groups are not in the notification; nil says the client did not know
// them either, which is not the same as the sender holding none.
func TestTextMessage_LeavesInvokerGroupsUnknown(t *testing.T) {
	got := servernotify.TextMessage(map[string]string{
		"targetmode": "2", "target": "9", "invokerid": "4",
		"invokername": "Ann", "invokeruid": "uid", "msg": "hi",
	})
	want := teamspeak.TextMessageEvent{
		TargetMode: 2, TargetID: 9, InvokerID: 4,
		InvokerName: "Ann", InvokerUID: "uid", Message: "hi",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TextMessage = %+v, want %+v", got, want)
	}
}

// The enter notification and a client list describe a client with the same
// keys, so one row reads as the same record by both. The two readers are
// written apart (the list's is in the root package, which this package
// imports), and this keeps them from disagreeing about a key.
func TestClientEnter_ReadsARowAsTheListDoes(t *testing.T) {
	row := map[string]string{
		"clid": "7", "cid": "3", "ctid": "3", "client_database_id": "42", "client_nickname": "Ann",
		"client_type": "0", "client_unique_identifier": "uidAnn=", "client_away": "1",
		"client_away_message": "lunch", "client_is_recording": "0", "client_is_talker": "1",
		"client_servergroups": "6,9", "client_channel_group_id": "8",
		"client_channel_group_inherited_channel_id": "3",
		"client_input_muted":                        "1", "client_output_muted": "0", "client_outputonly_muted": "0",
		"client_input_hardware": "1", "client_output_hardware": "1",
		"client_is_channel_commander": "0", "client_is_priority_speaker": "1", "client_talk_power": "75",
		"client_talk_request": "1700000000", "client_talk_request_msg": "please",
		"client_description": "desc", "client_meta_data": "meta", "client_flag_avatar": "abc123",
		"client_icon_id": "99", "client_nickname_phonetic": "an", "client_unread_messages": "0",
		"client_needed_serverquery_view_power": "75", "client_country": "SE",
		"client_version": "3.6.2", "client_platform": "Windows", "connection_client_ip": "10.0.0.2",
		"client_badges": "overwolf=0", "client_signed_badges": "sb", "client_myteamspeak_id": "mt",
		"client_myteamspeak_avatar": "mta", "client_integrations": "int", "client_user_tag": "tag",
		"client_is_streaming": "1",
	}
	commands := teamspeak.NewCommands(teamspeak.ExecutorFunc(
		func(context.Context, teamspeak.Request) ([]map[string]string, error) {
			return []map[string]string{row}, nil
		}))
	listed, err := commands.ListClients(t.Context(), teamspeak.ClientListOptions{})
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListClients = %v, %v", listed, err)
	}

	if got := servernotify.ClientEnter(row); !reflect.DeepEqual(got, listed[0]) {
		t.Errorf("ClientEnter = %+v\nlist     = %+v", got, listed[0])
	}
}

func TestClientEnter_AbsentFieldsAreUnknown(t *testing.T) {
	got := servernotify.ClientEnter(map[string]string{"clid": "7", "ctid": "3", "client_nickname": "Ann"})
	want := teamspeak.ClientEntry{ID: 7, ChannelID: 3, Nickname: "Ann"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientEnter = %+v, want %+v", got, want)
	}
}

// A change is set exactly when its key was sent.
func TestClientUpdated_SetsOnlyTheKeysSent(t *testing.T) {
	got := servernotify.ClientUpdated(map[string]string{
		"clid": "7", "client_nickname": "Ann2", "client_away": "1", "client_away_message": "",
	})
	want := teamspeak.ClientUpdatedEvent{
		ClientID: 7,
		Changes: teamspeak.ClientChanges{
			Nickname: new("Ann2"), IsAway: new(true), AwayMessage: new(""),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientUpdated = %+v, want %+v", got, want)
	}
}

// A group change sends the complete new list, and an empty one is "none".
func TestClientUpdated_ReadsTheGroupList(t *testing.T) {
	got := servernotify.ClientUpdated(map[string]string{"clid": "7", "client_servergroups": "6,9"})
	if got.Changes.ServerGroups == nil || !reflect.DeepEqual(*got.Changes.ServerGroups, []teamspeak.ServerGroupID{6, 9}) {
		t.Errorf("groups = %v", got.Changes.ServerGroups)
	}

	got = servernotify.ClientUpdated(map[string]string{"clid": "7", "client_servergroups": ""})
	if got.Changes.ServerGroups == nil || len(*got.Changes.ServerGroups) != 0 {
		t.Errorf("empty list = %v, want a pointer to an empty list", got.Changes.ServerGroups)
	}

	got = servernotify.ClientUpdated(map[string]string{"clid": "7", "client_talk_power": "75"})
	if got.Changes.ServerGroups != nil || got.Changes.TalkPower == nil || *got.Changes.TalkPower != 75 {
		t.Errorf("changes = %+v", got.Changes)
	}
}

func TestClientUpdated_NamesAnAdminsEdit(t *testing.T) {
	got := servernotify.ClientUpdated(map[string]string{
		"clid": "7", "client_description": "hello", "invokerid": "2", "invokername": "Admin", "invokeruid": "adm",
	})
	want := teamspeak.ClientUpdatedEvent{
		ClientID: 7, InvokerID: 2, InvokerName: "Admin", InvokerUID: "adm",
		Changes: teamspeak.ClientChanges{Description: new("hello")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClientUpdated = %+v, want %+v", got, want)
	}
}

// What an update names is read under the key, and so the name, a list does.
func TestClientChanges_ReadAKeyAsTheListDoes(t *testing.T) {
	row := map[string]string{
		"clid": "7", "client_nickname": "Ann", "client_unique_identifier": "u", "client_type": "1",
		"client_servergroups": "6", "client_channel_group_id": "8", "client_away": "1", "client_is_recording": "1",
		"client_is_talker": "1", "client_database_id": "42", "client_away_message": "m",
		"client_input_muted": "1", "client_output_muted": "0", "client_outputonly_muted": "1",
		"client_input_hardware": "1", "client_output_hardware": "0", "client_is_channel_commander": "1",
		"client_is_priority_speaker": "1", "client_talk_power": "75", "client_talk_request": "5",
		"client_talk_request_msg": "r", "client_description": "d", "client_meta_data": "md",
		"client_flag_avatar": "av", "client_icon_id": "99", "client_nickname_phonetic": "ph",
		"client_unread_messages": "2", "client_needed_serverquery_view_power": "75",
		"client_channel_group_inherited_channel_id": "3", "client_country": "SE", "client_version": "v",
		"client_platform": "p", "connection_client_ip": "1.2.3.4", "client_badges": "b",
		"client_signed_badges": "sb", "client_myteamspeak_id": "mt", "client_myteamspeak_avatar": "mta",
		"client_integrations": "i", "client_user_tag": "ut", "client_is_streaming": "1",
	}
	commands := teamspeak.NewCommands(teamspeak.ExecutorFunc(
		func(context.Context, teamspeak.Request) ([]map[string]string, error) {
			return []map[string]string{row}, nil
		}))
	listed, err := commands.ListClients(t.Context(), teamspeak.ClientListOptions{})
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListClients = %v, %v", listed, err)
	}

	got := servernotify.ClientChanges(row).Apply(teamspeak.ClientEntry{ID: 7})
	if !reflect.DeepEqual(got, listed[0]) {
		t.Errorf("changes applied = %+v\nlist            = %+v", got, listed[0])
	}
}

func TestClientServerGroup_ReadsTheMeasuredNotification(t *testing.T) {
	got := servernotify.ClientServerGroup(map[string]string{
		"sgid": "9", "clid": "5", "name": "Ann", "cluid": "u5",
		"invokerid": "2", "invokername": "Admin", "invokeruid": "adm",
	})
	want := teamspeak.ClientServerGroupChange{
		GroupID: 9, ClientID: 5, Nickname: "Ann", UID: "u5", InvokerID: 2, InvokerName: "Admin", InvokerUID: "adm",
	}
	if got != want {
		t.Errorf("ClientServerGroup = %+v, want %+v", got, want)
	}
}

// A move sends the group change from the server: invoker 0 and "Server".
func TestClientChannelGroupChanged_ReadsAServerInvokedChange(t *testing.T) {
	got := servernotify.ClientChannelGroupChanged(map[string]string{
		"invokerid": "0", "invokername": "Server", "invokeruid": "", "cgid": "8", "cid": "10", "clid": "5", "cgi": "10",
	})
	want := teamspeak.ClientChannelGroupChangedEvent{
		InvokerName: "Server", ClientID: 5, ChannelID: 10, ChannelGroupID: 8, ChannelGroupInheritedChannelID: 10,
	}
	if got != want {
		t.Errorf("ClientChannelGroupChanged = %+v, want %+v", got, want)
	}
}

// A number outside 32 bits clamps instead of wrapping, and what is not a number
// reads as 0, or as unset where the key is absent.
func TestClientChanges_ClampsNumbersTo32Bits(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int32
	}{
		{"75", 75}, {"-3", -3}, {"2147483647", 2147483647}, {"2147483648", 2147483647},
		{"99999999999999", 2147483647}, {"-2147483648", -2147483648}, {"-2147483649", -2147483648},
		{"-99999999999999", -2147483648}, {"99999999999999999999", 0}, {"abc", 0}, {"", 0},
	} {
		got := servernotify.ClientChanges(map[string]string{"client_talk_power": c.raw}).TalkPower
		if got == nil || *got != c.want {
			t.Errorf("client_talk_power=%q read %v, want %d", c.raw, got, c.want)
		}
	}
}

func TestClientEnter_ClampsAndLeavesOutNumbers(t *testing.T) {
	got := servernotify.ClientEnter(map[string]string{"clid": "1", "client_talk_power": "99999999999999"})
	if got.TalkPower == nil || *got.TalkPower != 2147483647 || got.UnreadMessages != nil {
		t.Errorf("TalkPower = %v, UnreadMessages = %v", got.TalkPower, got.UnreadMessages)
	}
	if got := servernotify.ClientEnter(map[string]string{"clid": "1", "client_talk_power": ""}); got.TalkPower != nil {
		t.Errorf("an empty value read as %d, want unset", *got.TalkPower)
	}
}

// Recorded from TeamSpeak 3.13.8 and 6.0.0-beta13.1.
func TestClientEnterOrigin(t *testing.T) {
	for _, tc := range []struct {
		line   string
		from   teamspeak.ChannelID
		reason teamspeak.Reason
	}{
		// Connecting.
		{"notifycliententerview cfid=0 ctid=1 reasonid=0 clid=34", 0, teamspeak.ReasonNone},
		// Coming into view through a subscribed channel.
		{"notifycliententerview cfid=0 ctid=7 reasonid=2 clid=34", 0, teamspeak.ReasonSubscription},
		{"notifycliententerview cfid=3 ctid=7 reasonid=1 clid=34", 3, teamspeak.ReasonMoved},
		{"notifycliententerview ctid=7 clid=34", 0, teamspeak.ReasonNone},
	} {
		from, reason := servernotify.ClientEnterOrigin(row(tc.line))
		if from != tc.from || reason != tc.reason {
			t.Errorf("%q = %d, %v; want %d, %v", tc.line, from, reason, tc.from, tc.reason)
		}
	}
}

// TeamSpeak 6.0.0-beta13.1 names the channel a move came from; 3.13.8 does not.
func TestClientMoved_ReadsTheChannelItCameFrom(t *testing.T) {
	ts6 := servernotify.ClientMoved(row(
		"notifyclientmoved cfid=6 clid=13 ctid=1 reasonid=4 reasonmsg=probe invokerid=11 invokername=a invokeruid=u"))
	if ts6.FromChannelID != 6 || ts6.TargetChannelID != 1 {
		t.Errorf("TeamSpeak 6 move = %+v", ts6)
	}
	ts3 := servernotify.ClientMoved(row(
		"notifyclientmoved clid=35 ctid=7 invokerid=33 invokername=a invokeruid=u reasonid=1"))
	if ts3.FromChannelID != 0 || ts3.TargetChannelID != 7 {
		t.Errorf("TeamSpeak 3 move = %+v", ts3)
	}
}

// Both servers send cfid on a leave, and ctid 0 for a disconnect.
func TestClientLeave_ReadsTheChannelsItNames(t *testing.T) {
	got := servernotify.ClientLeave(row("notifyclientleftview cfid=7 ctid=0 reasonid=8 reasonmsg=Shutdown clid=35"))
	if got.FromChannelID != 7 || got.TargetChannelID != 0 || got.Reason != teamspeak.ReasonDisconnect {
		t.Errorf("disconnect = %+v", got)
	}
	got = servernotify.ClientLeave(row("notifyclientleftview cfid=1 ctid=9 reasonid=2 clid=35"))
	if got.FromChannelID != 1 || got.TargetChannelID != 9 {
		t.Errorf("out of view = %+v", got)
	}
}

func TestClientEnter_ReadsTheTalkRequestTime(t *testing.T) {
	got := servernotify.ClientEnter(map[string]string{"clid": "4", "client_talk_request": "1792335264"})
	if !got.TalkRequestedAt.Equal(time.Unix(1792335264, 0)) || got.IsRequestingTalk == nil || !*got.IsRequestingTalk {
		t.Errorf("enter = %v %v", got.TalkRequestedAt, got.IsRequestingTalk)
	}
	none := servernotify.ClientEnter(map[string]string{"clid": "4", "client_talk_request": "0"})
	if !none.TalkRequestedAt.IsZero() {
		t.Errorf("a request of 0 = %v, want the zero time", none.TalkRequestedAt)
	}
	update := servernotify.ClientChanges(map[string]string{"client_talk_request": "1792335264"})
	if update.TalkRequestedAt == nil || !update.TalkRequestedAt.Equal(time.Unix(1792335264, 0)) {
		t.Errorf("update = %v", update.TalkRequestedAt)
	}
}
