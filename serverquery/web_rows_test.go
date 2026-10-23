package serverquery

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// webRecording answers every WebQuery request with success and records the
// body of each, by command.
func webRecording(t *testing.T) (string, func(command string) []string) {
	t.Helper()
	var mu sync.Mutex
	bodies := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		mu.Lock()
		bodies[name] = append(bodies[name], string(raw))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"body":[{"version":"6.0.0-beta13.1"}],"status":{"code":0,"message":"ok"}}`))
	}))
	t.Cleanup(srv.Close)

	return srv.URL, func(command string) []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), bodies[command]...)
	}
}

// webClient connects a client to a recording server.
func webClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(WebWith(url, "key", WebOptions{}), WithServer(1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Disconnect(t.Context()) })

	return c
}

// sameRows fails the test unless the body is an array of objects equal to want.
func sameRows(t *testing.T, body string, want []map[string]string) {
	t.Helper()
	var rows []map[string]string
	err := json.Unmarshal([]byte(body), &rows)
	if err != nil {
		t.Fatalf("body %s is not an array of objects: %v", body, err)
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
	for i := range want {
		if !maps.Equal(rows[i], want[i]) {
			t.Errorf("row %d = %v, want %v", i, rows[i], want[i])
		}
	}
}

// A command with rows goes as an array of objects, each carrying what the rows
// share and the flag as well as its own key, as the JavaScript client sends it.
// TeamSpeak 3 and 6 accept this form and the one that names the shared
// parameters in the first object only.
func TestWeb_RowsGoAsAnArrayOfObjects(t *testing.T) {
	url, bodies := webRecording(t)
	c := webClient(t, url)

	err := c.KickClients(t.Context(), []teamspeak.ClientID{4, 9, 12}, teamspeak.ReasonKickServer,
		teamspeak.KickClientsOptions{ReasonMessage: "bye now", ContinueOnError: true})
	if err != nil {
		t.Fatal(err)
	}
	got := bodies("clientkick")
	if len(got) != 1 {
		t.Fatalf("clientkick requests = %q", got)
	}
	sameRows(t, got[0], []map[string]string{
		{"-continueonerror": "", "reasonid": "5", "reasonmsg": "bye now", "clid": "4"},
		{"-continueonerror": "", "reasonid": "5", "reasonmsg": "bye now", "clid": "9"},
		{"-continueonerror": "", "reasonid": "5", "reasonmsg": "bye now", "clid": "12"},
	})
}

// Rows of several keys keep their own, and the shared target is in every one.
func TestWeb_RowsOfSeveralKeys(t *testing.T) {
	url, bodies := webRecording(t)
	c := webClient(t, url)

	err := c.AddServerGroupPermissions(t.Context(), 9, []teamspeak.PermissionEntry{
		{Permission: teamspeak.PermissionByName("i_a"), Value: 5},
		{Permission: teamspeak.PermissionByName("b_b"), Value: 1, Negated: true, Skip: true},
	}, teamspeak.PermissionBatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := bodies("servergroupaddperm")
	if len(got) != 1 {
		t.Fatalf("servergroupaddperm requests = %q", got)
	}
	sameRows(t, got[0], []map[string]string{
		{"sgid": "9", "permsid": "i_a", "permvalue": "5", "permnegated": "0", "permskip": "0"},
		{"sgid": "9", "permsid": "b_b", "permvalue": "1", "permnegated": "1", "permskip": "1"},
	})
}

// One row stays the object it always was.
func TestWeb_OneRowStaysAnObject(t *testing.T) {
	url, bodies := webRecording(t)
	c := webClient(t, url)

	err := c.KickClients(t.Context(), []teamspeak.ClientID{4}, teamspeak.ReasonKickServer,
		teamspeak.KickClientsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := bodies("clientkick")
	if len(got) != 1 || !strings.HasPrefix(got[0], "{") {
		t.Errorf("body = %q, want one object", got)
	}
}
