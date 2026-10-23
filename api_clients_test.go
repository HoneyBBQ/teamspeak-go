package teamspeak

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Measured on TeamSpeak 6: -cid adds cid and -chuid adds chuid. TeamSpeak 3
// takes both flags and answers neither.
func TestFindClientsWith_ReadsTheChannel(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"chuid": "e1eb3716-4257-46d5-aab1-3bd10fcccd88", "cid": "2", "clid": "19", "client_nickname": "vHolder",
	}}}}}
	both := ClientFindOptions{ChannelID: true, ChannelUID: true}
	got, err := NewCommands(s).FindClientsWith(t.Context(), "vHolder", both)
	if err != nil {
		t.Fatal(err)
	}
	if want := "clientfind -cid -chuid pattern=vHolder"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := []ClientMatch{{ID: 19, Nickname: "vHolder", ChannelID: 2, ChannelUID: "e1eb3716-4257-46d5-aab1-3bd10fcccd88"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %+v, want %+v", got, want)
	}

	// TeamSpeak 3 leaves the channel out; so does asking for neither.
	three := &script{replies: []reply{{rows: []map[string]string{{"clid": "17", "client_nickname": "vHolder"}}}}}
	got, err = NewCommands(three).FindClientsWith(t.Context(), "vHolder", ClientFindOptions{ChannelID: true})
	if err != nil || len(got) != 1 || got[0].ChannelID != 0 || got[0].ChannelUID != "" {
		t.Errorf("TeamSpeak 3 answer = %+v, %v", got, err)
	}
	if three.sent[0] != "clientfind -cid pattern=vHolder" {
		t.Errorf("sent %q", three.sent[0])
	}
}

// FindClients is unchanged: it asks for no channel.
func TestFindClients_AsksForNoChannel(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.FindClients(t.Context(), "vHolder")

		return err
	})
	if line != "clientfind pattern=vHolder" {
		t.Errorf("line = %q", line)
	}
}

// clientdbfind -uid searches the unique identifier; the answer is database ids.
func TestFindClientDatabaseByUID_SearchesTheUID(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"cldbid": "9"}, {"cldbid": "12"}}}}}
	got, err := NewCommands(s).FindClientDatabaseByUID(t.Context(), "Q/vfU/I2Vc%")
	if err != nil {
		t.Fatal(err)
	}
	if want := `clientdbfind pattern=Q\/vfU\/I2Vc% -uid`; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if want := []ClientDBID{9, 12}; !reflect.DeepEqual(got, want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
}

// No match is error 1281, which reads as no ids rather than as a failure.
func TestFindClientDatabaseByUID_NoMatchIsNoIDs(t *testing.T) {
	empty := &ServerError{Code: errcode.DatabaseEmptyResult, Message: "database empty result set"}
	ids, err := NewCommands(&script{replies: []reply{{err: empty}}}).FindClientDatabaseByUID(t.Context(), "nobody")
	if err != nil || len(ids) != 0 {
		t.Errorf("FindClientDatabaseByUID = %v, %v; want no ids and no error", ids, err)
	}
}

func TestCustomPropertyLines(t *testing.T) {
	for _, tc := range []struct {
		run  func(c *Commands) error
		want string
	}{
		{
			func(c *Commands) error { return c.SetCustomProperty(t.Context(), 4, "forum_nickname", "John Doe") },
			`customset cldbid=4 ident=forum_nickname value=John\sDoe`,
		},
		{
			func(c *Commands) error { return c.DeleteCustomProperty(t.Context(), 4, "forum_nickname") },
			"customdelete cldbid=4 ident=forum_nickname",
		},
		{
			func(c *Commands) error {
				_, err := c.ListCustomProperties(t.Context(), 3)

				return err
			},
			"custominfo cldbid=3",
		},
		{
			func(c *Commands) error {
				_, err := c.FindCustomProperty(t.Context(), "forum_account", "%teamspeak_user%")

				return err
			},
			"customsearch ident=forum_account pattern=%teamspeak_user%",
		},
	} {
		if got := encoded(t, tc.run); got != tc.want {
			t.Errorf("line = %q, want %q", got, tc.want)
		}
	}
}

// Measured on TeamSpeak 3 and 6: the value holds a space, a pipe and an
// equals sign, none of which the server minds.
func TestListCustomProperties(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"cldbid": "3", "ident": "", "value": "x"},
		{"cldbid": "3", "ident": "has space", "value": "a b|c=d"},
	}}}}
	got, err := NewCommands(s).ListCustomProperties(t.Context(), 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []CustomProperty{{Ident: "", Value: "x"}, {Ident: "has space", Value: "a b|c=d"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("properties = %+v, want %+v", got, want)
	}
}

// A client with no property is answered 512 over ServerQuery and on TeamSpeak
// 3's voice protocol, and 1281 on TeamSpeak 6's: both are none.
func TestListCustomProperties_NoneIsNotAnError(t *testing.T) {
	for _, code := range []errcode.Code{errcode.ClientInvalidID, errcode.DatabaseEmptyResult} {
		s := &script{replies: []reply{{err: &ServerError{Code: code}}}}
		got, err := NewCommands(s).ListCustomProperties(t.Context(), 1)
		if err != nil || len(got) != 0 {
			t.Errorf("%v: got %v, %v, want none", code, got, err)
		}
	}

	denied := &script{replies: []reply{{err: &ServerError{Code: errcode.PermissionsClientInsufficient}}}}
	_, err := NewCommands(denied).ListCustomProperties(t.Context(), 1)
	if !errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Errorf("err = %v, want the permission error", err)
	}
}

func TestFindCustomProperty(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"cldbid": "3", "ident": "tag", "value": "x"},
		{"cldbid": "5", "ident": "tag", "value": "x"},
	}}}}
	got, err := NewCommands(s).FindCustomProperty(t.Context(), "tag", "%")
	if err != nil {
		t.Fatal(err)
	}
	want := []CustomPropertyMatch{
		{DatabaseID: 3, Ident: "tag", Value: "x"},
		{DatabaseID: 5, Ident: "tag", Value: "x"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %+v, want %+v", got, want)
	}

	none := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err = NewCommands(none).FindCustomProperty(t.Context(), "nokey", "%")
	if err != nil || len(got) != 0 {
		t.Errorf("no match = %v, %v", got, err)
	}
}

// Measured on TeamSpeak 3 and 6: tokenlist shows the set with each ident and
// value escaped inside it, and the client that redeems a key gets "d e" only
// when the space was escaped there.
func TestCustomSet_EscapesInsideTheSet(t *testing.T) {
	props := []CustomProperty{{Ident: "a", Value: "d e"}, {Ident: "b", Value: "1"}}
	value := customSetValue(props)
	if want := `ident=a value=d\se|ident=b value=1`; value != want {
		t.Errorf("value = %q, want %q", value, want)
	}
	if got := parseCustomSet(value); !reflect.DeepEqual(got, props) {
		t.Errorf("parsed = %+v, want %+v", got, props)
	}
	if got := parseCustomSet(""); got != nil {
		t.Errorf("empty = %+v, want nil", got)
	}
}

// Anything can be a value: the pipe that separates properties, the space and
// equals sign that structure one, and the backslash that escapes them.
func TestCustomSet_RoundTripsAwkwardText(t *testing.T) {
	props := []CustomProperty{
		{Ident: "has space", Value: "x|y ident=c value=1"},
		{Ident: "a=b|c", Value: `back\slash and = signs`},
		{Ident: "", Value: ""},
	}
	got := parseCustomSet(customSetValue(props))
	if !reflect.DeepEqual(got, props) {
		t.Errorf("round trip = %+v, want %+v", got, props)
	}
}

// A set written without the escape inside — by another party — reads as it
// was written.
func TestParseCustomSet_ReadsAnUnescapedSet(t *testing.T) {
	got := parseCustomSet("ident=a value=b|ident=c value=d e")
	want := []CustomProperty{{Ident: "a", Value: "b"}, {Ident: "c", Value: "d e"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed = %+v, want %+v", got, want)
	}
}

// Measured on both servers: -icon adds client_icon_id to each client.
func TestListClients_Icon(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"cid": "24", "clid": "1", "client_database_id": "1", "client_icon_id": "4294967295",
		"client_nickname": "serveradmin", "client_type": "1",
	}}}}}
	got, err := NewCommands(s).ListClients(t.Context(), ClientListOptions{Icon: true})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if want := "clientlist -uid -icon"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	// The server sends an icon id as an unsigned 32-bit number, or as the same
	// bits signed.
	if got[0].IconID == nil || *got[0].IconID != 4294967295 {
		t.Errorf("IconID = %v, want 4294967295", got[0].IconID)
	}

	line := encoded(t, func(c *Commands) error {
		_, err := c.ListClients(t.Context(), ClientListOptions{})

		return err
	})
	if line != "clientlist -uid" {
		t.Errorf("a list without Icon sent %q", line)
	}
}

func TestGetClientConnectionInfo_AsksAndReadsTheFigures(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"clid": "5", "connection_ping": "12.5000", "connection_ping_deviation": "1.2500",
		"connection_connected_time": "4000", "connection_idle_time": "3000",
		"connection_client_ip": "10.0.0.1", "connection_client_port": "9000",
		"connection_packets_sent_speech": "7", "connection_bytes_received_control": "800",
		"connection_bandwidth_sent_last_minute_keepalive": "3",
		"connection_server2client_packetloss_total":       "0.0500",
		"connection_client2server_packetloss_control":     "0.1000",
		"connection_filetransfer_bandwidth_sent":          "11",
	}}}}}
	info, err := NewCommands(s).GetClientConnectionInfo(t.Context(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.sent) != 1 || s.sent[0] != "getconnectioninfo clid=5" {
		t.Errorf("sent %q", s.sent)
	}
	if info.ID != 5 || info.Ping != 12500*time.Microsecond || info.PingDeviation != 1250*time.Microsecond ||
		info.ConnectedTime != 4*time.Second || info.IdleTime != 3*time.Second ||
		info.IP != "10.0.0.1" || info.Port != 9000 || info.FileTransferBandwidthSent != 11 {
		t.Errorf("info = %+v", info)
	}
	if info.Sent.Speech.Packets != 7 || info.Received.Control.Bytes != 800 ||
		info.Sent.Keepalive.BandwidthLastMinute != 3 ||
		info.ServerToClientLoss.Total != 0.05 || info.ClientToServerLoss.Control != 0.1 {
		t.Errorf("traffic = %+v / %+v", info.Sent, info.Received)
	}
}

func TestGetClientConnectionInfo_LeavesIPAndPortOutWhenAbsent(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"clid": "5"}}}}}
	info, err := NewCommands(s).GetClientConnectionInfo(t.Context(), 5)
	if err != nil || info.IP != "" || info.Port != 0 || info.Ping != 0 {
		t.Errorf("info = %+v, err = %v", info, err)
	}
}

func TestUpdateClient_SendsMetaData(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		return c.UpdateClient(t.Context(), ClientUpdateOptions{MetaData: new("m")})
	})
	if line != "clientupdate client_meta_data=m" {
		t.Errorf("line = %q", line)
	}
}
