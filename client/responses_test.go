package client

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
)

func receive(t *testing.T, ch <-chan commandResult) commandResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(time.Second):
		t.Fatal("command not resolved")

		return commandResult{}
	}
}

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

// The voice protocol answers a refused upload with error id=0 and then a status
// notification; reporting that as success with no key is how the refusal used
// to vanish.
func TestCommandTracker_TurnsAFailureStatusIntoAServerError(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(responseFor("ftinitupload"), "4", true)
	tr.resolve(rc, nil, 0)
	tr.offerCorrelated("notifystatusfiletransfer", map[string]string{
		"clientftfid": "4", "status": "2568", "msg": "insufficient client permissions",
	})

	err := receive(t, done).Err
	if !errors.Is(err, errcode.PermissionsClientInsufficient) || !errors.Is(err, teamspeak.ErrServer) {
		t.Errorf("err = %v, want the permissions refusal", err)
	}
}

// Response rows carry no name. Treating the first field as one copied it onto
// every row, and a batch with no space in it was never split at all.
func TestSplitCommandRows_NamelessBatches(t *testing.T) {
	cases := map[string][]string{
		"clid=1 cid=5|clid=2 cid=6":  {"clid=1 cid=5", "clid=2 cid=6"},
		"cldbid=1|cldbid=2|cldbid=3": {"cldbid=1", "cldbid=2", "cldbid=3"},
		"cid=1 name=a|name=b":        {"cid=1 name=a", "cid=1 name=b"},
	}
	for line, want := range cases {
		if got := splitCommandRows(line); !reflect.DeepEqual(got, want) {
			t.Errorf("splitCommandRows(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestExecCommand_RefusesItsOwnReturnCode(t *testing.T) {
	c := newTestClient(t)
	_, err := c.ExecCommandWithResponse("clientlist return_code=9", time.Second)
	if !errors.Is(err, teamspeak.ErrInvalidCommand) {
		t.Errorf("err = %v, want ErrInvalidCommand", err)
	}
}

// A message body is escaped into one parameter, so text that merely contains
// "return_code=" is not a return_code. It used to suppress the real one.
func TestExecCommand_IsNotFooledByReturnCodeText(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		_, err := c.ExecCommandWithResponse(`sendtextmessage targetmode=3 msg=see\sreturn_code=9`, time.Second)

		return err
	})
	if !strings.HasSuffix(sent, " return_code=1") {
		t.Errorf("sent = %q, want the tracker's return_code appended", sent)
	}
}

func TestExecCommand_FailsFastWithoutAConnection(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNew(t, id, "offline")
	_, err = c.ExecCommandWithResponse("clientlist", time.Minute)
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
	c := newTestClient(t)
	ids := make([]string, 0, 2)
	c.UseCommandMiddleware(func(_ func(string) error) func(string) error {
		return func(cmd string) error {
			ids = append(ids, commands.ParseCommand(cmd).Params["clientftfid"])

			return errCaptured
		}
	})
	_, _ = c.InitFileUpload(t.Context(), 1, "/a", 3, "", true)
	_, _ = c.InitFileUpload(t.Context(), 1, "/b", 3, "", true)

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

func TestParseServerError(t *testing.T) {
	err := parseServerError(map[string]string{
		"id": "2568", "msg": "insufficient client permissions", "failed_permid": "236", "extra_msg": "detail",
	})
	if err.Code != errcode.PermissionsClientInsufficient || err.FailedPermID != 236 || err.ExtraMessage != "detail" {
		t.Errorf("parsed %+v", err)
	}
	if parseServerError(map[string]string{"id": "0", "msg": "ok"}) != nil {
		t.Error("id=0 is success")
	}
	got := parseServerError(map[string]string{"msg": "no id"})
	if got == nil || got.Code != errcode.Undefined {
		t.Errorf("an error line without an id = %v, want errcode.Undefined", got)
	}
}
