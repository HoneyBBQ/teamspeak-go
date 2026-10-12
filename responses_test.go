package teamspeak

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/commands"
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
	rc, done := tr.register(commands.Response("servergrouplist"), "", false)
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
	rc, done := tr.register(commands.Response("servergrouplist"), "", false)
	tr.collect(map[string]string{"clid": "3"}, "notifyclientmoved")
	tr.resolve(rc, nil, 0)

	if got := receive(t, done).Data; len(got) != 0 {
		t.Errorf("data = %v, want none", got)
	}
}

func TestCommandTracker_KeepsOwnRowsWhenTheSpecSaysSo(t *testing.T) {
	tr := newReadyCommandTracker()
	rc, done := tr.register(commands.Response("channelcreate"), "", false)
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
	rc, done := tr.register(commands.Response("ftinitupload"), "4", true)
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
	rc, done := tr.register(commands.Response("ftinitupload"), "4", true)
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
	rc, done := tr.register(commands.Response("ftinitupload"), "4", true)
	tr.resolve(rc, nil, 0)
	tr.offerCorrelated("notifystatusfiletransfer", map[string]string{
		"clientftfid": "4", "status": "2568", "msg": "insufficient client permissions",
	})

	serverErr, ok := errors.AsType[*ServerError](receive(t, done).Err)
	if !ok || serverErr.ID != "2568" {
		t.Errorf("err = %v, want ServerError 2568", serverErr)
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
	if !errors.Is(err, ErrInvalidCommand) {
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
	c := NewClient(nil, "127.0.0.1:9987", "offline")
	_, err := c.ExecCommandWithResponse("clientlist", time.Minute)
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
}

// -uid is a switch. The voice protocol also accepts -uid=1, but that is not the
// documented form, and ServerQuery is not promised to.
func TestFlags_AreSentBare(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		_, err := c.ListClients(t.Context(), ClientListOptions{Away: true})

		return err
	})
	if !strings.HasPrefix(sent, "clientlist -uid -away") {
		t.Errorf("sent = %q", sent)
	}
}

// The parser unescapes once. A second pass turned a real \s into a space.
func TestFieldStr_DoesNotUnescapeTwice(t *testing.T) {
	row := commands.ParseCommand(`name=C:\\stuff`).Params
	if got := fieldStr(row, "name"); got != `C:\stuff` {
		t.Errorf("fieldStr = %q, want %q", got, `C:\stuff`)
	}
}

// The voice protocol answers servergroupadd with the whole list; the first row
// is whatever group the server lists first.
func TestCreatedGroupID(t *testing.T) {
	list := []map[string]string{
		{"sgid": "1", "name": "Guest Server Query"},
		{"sgid": "4", "name": "bots"},
		{"sgid": "12", "name": "bots"},
	}
	id, err := createdGroupID(list, "sgid", "bots")
	if err != nil || id != 12 {
		t.Errorf("full list: id = %d, err = %v, want 12", id, err)
	}
	id, err = createdGroupID([]map[string]string{{"sgid": "12"}}, "sgid", "bots")
	if err != nil || id != 12 {
		t.Errorf("bare id: id = %d, err = %v, want 12", id, err)
	}
	_, err = createdGroupID(list[:1], "sgid", "bots")
	if err == nil {
		t.Error("missing group: want an error rather than another group's id")
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
