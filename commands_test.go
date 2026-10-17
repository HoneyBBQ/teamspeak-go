package teamspeak

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/request"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// recorder is an Executor that records the requests the typed commands make.
type recorder struct {
	requests []Request
	rows     []map[string]string
}

func (r *recorder) Send(_ context.Context, req Request) ([]map[string]string, error) {
	r.requests = append(r.requests, req)

	return r.rows, nil
}

// A request names its password parameters and leaves their encoding to the
// transport: the voice protocol hashes them, ServerQuery sends them as given.
func TestRequest_LeavesPasswordEncodingToTheTransport(t *testing.T) {
	rec := &recorder{}
	err := NewCommands(rec).MoveClient(t.Context(), 7, 42, ClientMoveOptions{Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}

	req := rec.requests[0]
	hashed := req.encode(func(pw string) string { return "hashed(" + pw + ")" })
	if hashed != "clientmove clid=7 cid=42 cpw=hashed(hunter2)" {
		t.Errorf("hashed encoding = %q", hashed)
	}
	plain := req.encode(func(pw string) string { return pw })
	if plain != "clientmove clid=7 cid=42 cpw=hunter2" {
		t.Errorf("plain encoding = %q", plain)
	}
}

func TestRequest_SendsFlagsBare(t *testing.T) {
	rec := &recorder{}
	_, err := NewCommands(rec).ListClients(t.Context(), ClientListOptions{Away: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.requests[0].encode(func(pw string) string { return pw }); got != "clientlist -uid -away" {
		t.Errorf("encoding = %q", got)
	}
}

// The parser unescapes once. A second pass turned a real \s into a space.
func TestFieldStr_DoesNotUnescapeTwice(t *testing.T) {
	row := wire.ParseCommand(`name=C:\\stuff`).Params
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
	id, err := createdGroupID[ServerGroupID](list, "sgid", "bots")
	if err != nil || id != 12 {
		t.Errorf("full list: id = %d, err = %v, want 12", id, err)
	}
	id, err = createdGroupID[ServerGroupID]([]map[string]string{{"sgid": "12"}}, "sgid", "bots")
	if err != nil || id != 12 {
		t.Errorf("bare id: id = %d, err = %v, want 12", id, err)
	}
	_, err = createdGroupID[ServerGroupID](list[:1], "sgid", "bots")
	if err == nil {
		t.Error("missing group: want an error rather than another group's id")
	}
}

// Encoding is the transport's business: a Request offers callers its name and
// nothing that renders it.
func TestRequestHasNoPublicEncode(t *testing.T) {
	if _, ok := reflect.TypeFor[Request]().MethodByName("Encode"); ok {
		t.Error("Request has a public Encode method")
	}
	line := request.Encode(request.New("channelsubscribe", [][2]string{{"cid", "7"}}), nil)
	if line != "channelsubscribe cid=7" {
		t.Errorf("the transports' encoding = %q", line)
	}
}

// The names both SDKs give the same concepts; this fails to compile if one
// drifts.
func TestSharedNames(_ *testing.T) {
	var zero time.Time
	_ = Complaint{Created: zero}
	_ = OfflineMessage{Sent: zero}
	_ = TempPassword{Starts: zero, Ends: zero}
	_ = PermissionLocation{DatabaseID: 1}
	_ = ServerGroupMember{DatabaseID: 1}
	_ = ServerVersion{}
	_ = PrivilegeKey{Created: zero}
	_ = FileEntry{Modified: zero}
	_ = Channel{UID: ChannelUID("")}
	_ = WhoAmI{ServerUID: ""}
	_ = PrivilegeKeyServerGroup
}

func TestSendPluginCommand_AddressesTheChannelTheServerOrOneClient(t *testing.T) {
	rec := &recorder{}
	cmds := NewCommands(rec)
	for _, target := range []PluginCommandTarget{{}, PluginToChannel(), PluginToServer(), PluginToClient(9)} {
		err := cmds.SendPluginCommand(t.Context(), "plug", "hello", target)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := cmds.SendPluginCommand(t.Context(), "b2 plug", "a b|c/d", PluginToChannel())
	if err != nil {
		t.Fatal(err)
	}
	err = cmds.SendPluginCommand(t.Context(), "plug", "", PluginToChannel())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"plugincmd name=plug data=hello targetmode=0",
		"plugincmd name=plug data=hello targetmode=0",
		"plugincmd name=plug data=hello targetmode=1",
		"plugincmd name=plug data=hello targetmode=2 target=9",
		`plugincmd name=b2\splug data=a\sb\pc\/d targetmode=0`,
		"plugincmd name=plug data= targetmode=0",
	}
	for i, req := range rec.requests {
		if got := req.encode(func(pw string) string { return pw }); got != want[i] {
			t.Errorf("request %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestChatComposingAndClose_NameTheClient(t *testing.T) {
	rec := &recorder{}
	cmds := NewCommands(rec)
	err := cmds.SendChatComposing(t.Context(), 9)
	if err != nil {
		t.Fatal(err)
	}
	err = cmds.ClosePrivateChat(t.Context(), 9)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"clientchatcomposing clid=9", "clientchatclosed clid=9"} {
		if got := rec.requests[i].encode(func(pw string) string { return pw }); got != want {
			t.Errorf("request %d = %q, want %q", i, got, want)
		}
	}
}
