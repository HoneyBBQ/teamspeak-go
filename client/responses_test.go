package client

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// The server answers in order, so the rows before error 1 are command 1's,
// whatever order the two were registered in. They used to go to the newest
// pending command instead.
func TestCommandTracker_KeepsTwoInFlightAnswersApart(t *testing.T) {
	tr := newReadyCommandTracker()
	first, firstDone := tr.register(nil, "", false)
	second, secondDone := tr.register(nil, "", false)

	tr.collect(map[string]string{"cid": "1"}, "")
	tr.resolve(first, nil, 0)
	tr.collect(map[string]string{"clid": "7"}, "")
	tr.resolve(second, nil, 0)

	if got := receive(t, firstDone).Data; !reflect.DeepEqual(got, []map[string]string{{"cid": "1"}}) {
		t.Errorf("first = %v", got)
	}
	if got := receive(t, secondDone).Data; !reflect.DeepEqual(got, []map[string]string{{"clid": "7"}}) {
		t.Errorf("second = %v", got)
	}
}

func TestCommandTracker_TakesDeclaredNotificationAsData(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("servergrouplist"), "", false)
	tr.collect(map[string]string{"sgid": "6"}, "notifyservergrouplist")
	tr.resolve(rc, nil, 0)

	if got := receive(t, done).Data; !reflect.DeepEqual(got, []map[string]string{{"sgid": "6"}}) {
		t.Errorf("data = %v", got)
	}
}

// An event that happens to arrive between a command and its answer is not the
// answer.
func TestCommandTracker_LeavesUndeclaredNotificationsOut(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("servergrouplist"), "", false)
	tr.collect(map[string]string{"clid": "3"}, "notifyclientmoved")
	tr.resolve(rc, nil, 0)

	if got := receive(t, done).Data; len(got) != 0 {
		t.Errorf("data = %v, want none", got)
	}
}

func TestCommandTracker_KeepsOwnRowsWhenTheSpecSaysSo(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("channelcreate"), "", false)
	tr.collect(map[string]string{"cid": "8", "invokerid": "9"}, "notifychannelcreated")
	tr.collect(map[string]string{"cid": "9", "invokerid": "5"}, "notifychannelcreated")
	tr.resolve(rc, nil, 5)

	want := []map[string]string{{"cid": "9", "invokerid": "5"}}
	if got := receive(t, done).Data; !reflect.DeepEqual(got, want) {
		t.Errorf("data = %v, want %v", got, want)
	}
}

func TestCommandTracker_WaitsForTheAnswerAfterTheError(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("ftinitupload"), "4", true)
	tr.resolve(rc, nil, 0)

	select {
	case res := <-done:
		t.Fatalf("resolved before the answer arrived: %v", res)
	case <-time.After(20 * time.Millisecond):
	}

	tr.offerCorrelated("notifystartupload", map[string]string{"clientftfid": "5", "ftkey": "other"})
	tr.offerCorrelated("notifystartupload", map[string]string{"clientftfid": "4", "ftkey": "mine"})
	want := []map[string]string{{"clientftfid": "4", "ftkey": "mine"}}
	if got := receive(t, done).Data; !reflect.DeepEqual(got, want) {
		t.Errorf("data = %v, want %v", got, want)
	}
}

func TestCommandTracker_AcceptsAnAnswerThatBeatsTheError(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("ftinitupload"), "4", true)
	tr.offerCorrelated("notifystartupload", map[string]string{"clientftfid": "4", "ftkey": "k"})
	tr.resolve(rc, nil, 0)

	if got := receive(t, done).Data; len(got) != 1 || got[0]["ftkey"] != "k" {
		t.Errorf("data = %v", got)
	}
}

// A command the table has no entry for (whoami, clientlist, anything sent
// through Exec) has no spec. A notification another command in flight declares
// used to be offered to it all the same, which read through the missing spec
// and panicked, and the transport closed the connection.
func TestCommandTracker_OffersANotificationPastACommandWithoutASpec(t *testing.T) {
	tr := newReadyCommandTracker()
	_, bare := tr.register(nil, "", false)
	_, bareCorrelated := tr.register(nil, "4", true)
	rc, upload := tr.register(responseFor("ftinitupload"), "4", true)
	tr.resolve(rc, nil, 0)

	tr.offerCorrelated("notifystartupload", map[string]string{"clientftfid": "4", "ftkey": "mine"})

	if got := receive(t, upload).Data; len(got) != 1 || got[0]["ftkey"] != "mine" {
		t.Errorf("data = %v, want the declared answer", got)
	}
	for name, done := range map[string]<-chan commandResult{"bare": bare, "bare correlated": bareCorrelated} {
		select {
		case res := <-done:
			t.Errorf("%s command settled by a notification it did not declare: %v", name, res)
		default:
		}
	}
}

// The same through the client: whoami and servergrouplist are in flight
// together, and the group list's notification arrives while both are.
func TestHandleCommandLines_NotificationDeclaredByAnotherCommandInFlight(t *testing.T) {
	c := newTestClient(t)
	whoami, whoamiDone := c.cmdTrack.register(responseFor("whoami"), "", false)
	groups, groupsDone := c.cmdTrack.register(responseFor("servergrouplist"), "", false)

	c.handleCommandLines(c.handler, strings.Join([]string{
		"client_id=7 client_nickname=me",
		"error id=0 msg=ok return_code=" + mustUint32Str(whoami),
		"notifyservergrouplist sgid=6 name=Admin",
		"error id=0 msg=ok return_code=" + mustUint32Str(groups),
	}, "\n"))

	if got := receive(t, whoamiDone); got.Err != nil || len(got.Data) != 1 || got.Data[0]["client_id"] != "7" {
		t.Errorf("whoami = %+v", got)
	}
	if got := receive(t, groupsDone); got.Err != nil || len(got.Data) != 1 || got.Data[0]["sgid"] != "6" {
		t.Errorf("servergrouplist = %+v", got)
	}
}

// The voice protocol answers a refused upload with error id=0 and then a status
// notification; reporting that as success with no key is how the refusal used
// to vanish.
func TestCommandTracker_TurnsAFailureStatusIntoAServerError(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("ftinitupload"), "4", true)
	tr.resolve(rc, nil, 0)
	tr.offerCorrelated("notifystatusfiletransfer", map[string]string{
		"clientftfid": "4", "status": "2568", "msg": "insufficient client permissions",
		"extra_msg": "i_ft_file_upload_power",
	})

	err := receive(t, done).Err
	if !errors.Is(err, errcode.PermissionsClientInsufficient) || !errors.Is(err, teamspeak.ErrServer) {
		t.Errorf("err = %v, want the permissions refusal", err)
	}
	se, ok := errors.AsType[*teamspeak.ServerError](err)
	if !ok || se.ExtraMessage != "i_ft_file_upload_power" {
		t.Errorf("err = %#v, want the extra_msg carried", err)
	}
}

func TestExec_RefusesItsOwnReturnCode(t *testing.T) {
	c := newTestClient(t)
	_, err := c.Exec(ctxWithin(t, time.Second), "clientlist return_code=9")
	if !errors.Is(err, teamspeak.ErrInvalidCommand) {
		t.Errorf("err = %v, want ErrInvalidCommand", err)
	}
}

// A message body is escaped into one parameter, so text that merely contains
// "return_code=" is not a return_code. It used to suppress the real one.
func TestExec_IsNotFooledByReturnCodeText(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		_, err := c.Exec(ctxWithin(t, time.Second), `sendtextmessage targetmode=3 msg=see\sreturn_code=9`)

		return err
	})
	if !strings.HasSuffix(sent, " return_code=1") {
		t.Errorf("sent = %q, want the tracker's return_code appended", sent)
	}
}

func TestExec_FailsFastWithoutAConnection(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNew(t, id, "offline")
	_, err = c.Exec(ctxWithin(t, time.Minute), "clientlist")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
}

// -uid is a switch. The voice protocol also accepts -uid=1, but that is not the
// documented form, and ServerQuery is not promised to.
func TestFlags_AreSentBare(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		_, err := c.ListClients(t.Context(), teamspeak.ClientListOptions{Away: true})

		return err
	})
	if !strings.HasPrefix(sent, "clientlist -uid -away") {
		t.Errorf("sent = %q", sent)
	}
}

// The answer arrives after the command returns and is matched only by the
// echoed clientftfid, so two negotiations must not share one.
func TestInitFileUpload_GivesEachNegotiationItsOwnID(t *testing.T) {
	ids := make([]string, 0, 2)
	c := newTestClient(t)
	c.wireHook = func(line string) error {
		ids = append(ids, wire.ParseCommand(line).Params["clientftfid"])

		return errCaptured
	}
	_, _ = c.InitFileUpload(t.Context(), 1, "/a", 3, teamspeak.FileUploadOptions{Overwrite: true})
	_, _ = c.InitFileUpload(t.Context(), 1, "/b", 3, teamspeak.FileUploadOptions{Overwrite: true})

	if len(ids) != 2 || ids[0] == "" || ids[0] == "0" || ids[0] == ids[1] {
		t.Errorf("clientftfid values = %q, want two distinct non-zero ids", ids)
	}
}

// The permanent list used to name codes by number, and got three wrong: a
// wrong server password (1028) was retried while 1029, "deployment active",
// was not.
func TestDefaultShouldRetry_StopsOnTheRealPermanentRefusals(t *testing.T) {
	permanent := []errcode.Code{
		errcode.ConnectFailedBanned, errcode.BanFlooding, errcode.ServerInvalidPassword,
		errcode.ChannelInvalidPassword, errcode.PermissionsClientInsufficient,
	}
	for _, code := range permanent {
		if DefaultShouldRetry(&teamspeak.ServerError{Code: code}, 1) {
			t.Errorf("retries %v (%d)", code, uint32(code))
		}
	}
	if !DefaultShouldRetry(&teamspeak.ServerError{Code: errcode.ClientTooManyClonesConnected}, 1) {
		t.Error("does not retry 521, which clears once the server reaps the dropped session")
	}
}

// voiceAnswer is one command's answer over the voice protocol: the
// notification that carries it, and a row of it.
type voiceAnswer struct {
	row          map[string]string
	command      string
	notification string
}

// voiceAnswers are what the voice protocol answers with a notification, which
// the table pairs with the command: a raw Exec returned no rows for any of
// them before. Each row is one measured on TeamSpeak 3.13.8 or
// 6.0.0-beta13.1.
var voiceAnswers = []voiceAnswer{
	{
		map[string]string{
			"apikey": "AQD80rwelNMqK1MeMoNb9iq2bRtJ0G9PXbsCDe6", "cldbid": "13", "created_at": "1792225961",
			"expires_at": "1792312361", "id": "8", "scope": "read", "sid": "2", "time_left": "86399",
		},
		"apikeyadd", "notifyapikeyadd",
	},
	{
		map[string]string{
			"cldbid": "13", "created_at": "1792225252", "custom_id": "", "expires_at": "1792311652", "id": "6",
			"scope": "read", "sid": "2", "time_left": "85691",
		},
		"apikeylist", "notifyapikeylist",
	},
	{
		map[string]string{"token": "S7ef32Rddh0QPvjjbHVO0+uD0l2m7RWDv0Gq30gz"},
		"tokenadd", "notifytokenadd",
	},
	{
		map[string]string{
			"token": "wYG6rbjcHftdWY8Xtf+z1KScoyh4Whk12N2RKSs1", "token_created": "1792225280",
			"token_customset": "ident=a value=b", "token_description": "x", "token_id1": "9", "token_id2": "0",
			"token_type": "0",
		},
		"tokenlist", "notifytokenlist",
	},
	{
		map[string]string{"permid": "215", "permsid": "b_client_ban_list", "permvalue": "1"},
		"permget", "notifypermget",
	},
	{
		map[string]string{
			"clid": "17", "connection_client_ip": "192.168.215.1", "connection_client_port": "44905",
			"connection_idle_time": "0",
		},
		"getconnectioninfo", "notifyconnectioninfo",
	},
	{
		map[string]string{
			"clid": "17", "client_created": "1792225244", "client_platform": "Windows",
			"client_totalconnections": "4", "client_version": "3.6.2 [Build: 1695203293]",
		},
		"clientgetvariables", "notifyclientupdated",
	},
	{
		map[string]string{"virtualserver_clientsonline": "2", "virtualserver_autostart": "1"},
		"servergetvariables", "notifyserverupdated",
	},
	{
		map[string]string{"client_login_password": "eHkRuwwa"},
		"clientsetserverquerylogin", "notifyclientserverqueryloginpassword",
	},
	{
		map[string]string{
			"banid": "13", "created": "1792225536", "duration": "0", "ip": "10.0.0.5", "mytsid": "",
			"reason": "cap", "return_code": "2",
		},
		"banfind", "notifybanfind",
	},
}

func TestResponseTable_VoiceAnswersCarryTheirRows(t *testing.T) {
	for _, tc := range voiceAnswers {
		tr := newReadyCommandTracker()
		rc, done := tr.register(responseFor(tc.command), "", false)
		tr.collect(tc.row, tc.notification)
		tr.resolve(rc, nil, 0)

		if got := receive(t, done).Data; !reflect.DeepEqual(got, []map[string]string{tc.row}) {
			t.Errorf("%s: data = %v, want the %s row", tc.command, got, tc.notification)
		}
	}
}

// The same notification arriving for someone else's request is not this
// command's answer: only the declared one is taken.
func TestResponseTable_LeavesOtherNotificationsOutOfAPermget(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("permget"), "", false)
	tr.collect(map[string]string{"clid": "3"}, "notifyclientmoved")
	tr.collect(map[string]string{"permid": "215", "permvalue": "1"}, "notifypermget")
	tr.resolve(rc, nil, 0)

	want := []map[string]string{{"permid": "215", "permvalue": "1"}}
	if got := receive(t, done).Data; !reflect.DeepEqual(got, want) {
		t.Errorf("data = %v, want %v", got, want)
	}
}

// notifyclientupdated is sent whenever any client changes, and arrives between
// a clientgetvariables and its error as readily as anywhere: the row for the
// client asked about is the answer, and the others are not.
func TestResponseTable_ClientGetVariablesTakesTheRowForTheClientAsked(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("clientgetvariables"), "", false)
	tr.setEcho(rc, "17")
	tr.collect(map[string]string{"clid": "2", "client_input_muted": "0", "client_output_muted": "0"},
		"notifyclientupdated")
	tr.collect(map[string]string{"clid": "17", "client_version": "3.6.2 [Build: 1695203293]"}, "notifyclientupdated")
	tr.resolve(rc, nil, 0)

	want := []map[string]string{{"clid": "17", "client_version": "3.6.2 [Build: 1695203293]"}}
	if got := receive(t, done).Data; !reflect.DeepEqual(got, want) {
		t.Errorf("data = %v, want %v", got, want)
	}
}

// A row that does not carry the key is taken, as is every row when the request
// named none.
func TestResponseTable_EchoKeyIsLenient(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("getconnectioninfo"), "", false)
	tr.setEcho(rc, "17")
	tr.collect(map[string]string{"connection_client_ip": "192.168.215.1"}, "notifyconnectioninfo")
	tr.resolve(rc, nil, 0)
	if got := receive(t, done).Data; len(got) != 1 {
		t.Errorf("a row with no clid: data = %v, want it taken", got)
	}

	rc, done = tr.register(responseFor("getconnectioninfo"), "", false)
	tr.collect(map[string]string{"clid": "3", "connection_client_ip": "10.0.0.1"}, "notifyconnectioninfo")
	tr.resolve(rc, nil, 0)
	if got := receive(t, done).Data; len(got) != 1 {
		t.Errorf("a request that named no clid: data = %v, want the row taken", got)
	}
}
