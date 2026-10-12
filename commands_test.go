package teamspeak

import (
	"context"
	"testing"

	"github.com/honeybbq/teamspeak-go/commands"
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
	err := NewCommands(rec).MoveClient(t.Context(), 7, 42, "hunter2")
	if err != nil {
		t.Fatal(err)
	}

	req := rec.requests[0]
	hashed := req.Encode(func(pw string) string { return "hashed(" + pw + ")" })
	if hashed != "clientmove clid=7 cid=42 cpw=hashed(hunter2)" {
		t.Errorf("hashed encoding = %q", hashed)
	}
	plain := req.Encode(func(pw string) string { return pw })
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
	if got := rec.requests[0].Encode(func(pw string) string { return pw }); got != "clientlist -uid -away" {
		t.Errorf("encoding = %q", got)
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
