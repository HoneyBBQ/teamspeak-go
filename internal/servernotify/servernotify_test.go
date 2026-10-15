package servernotify_test

import (
	"reflect"
	"testing"

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
