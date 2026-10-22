package teamspeak_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
)

// recorded is an Executor that answers each command from a list of recorded
// answers, in order, the way a test double or a replayed session might. The
// voice client and the ServerQuery client are Executors in the same way.
type recorded struct {
	answers []recordedAnswer
}

type recordedAnswer struct {
	err  error
	rows []map[string]string
}

func (r *recorded) Send(_ context.Context, req teamspeak.Request) ([]map[string]string, error) {
	if len(r.answers) == 0 {
		return nil, fmt.Errorf("%s: %w", req.Command(), teamspeak.ErrNotConnected)
	}
	next := r.answers[0]
	r.answers = r.answers[1:]

	return next.rows, next.err
}

// A typed command sends the request and reads the answer into typed values.
// With a client, the same call is c.ListChannels(ctx, teamspeak.ChannelListOptions{}).
func ExampleCommands_ListChannels() {
	cmds := teamspeak.NewCommands(&recorded{answers: []recordedAnswer{{rows: []map[string]string{
		{"cid": "1", "pid": "0", "channel_name": "Lobby", "total_clients": "3"},
		{"cid": "2", "pid": "1", "channel_name": "AFK", "total_clients": "0"},
	}}}})

	channels, err := cmds.ListChannels(context.Background(), teamspeak.ChannelListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	for _, ch := range channels {
		fmt.Printf("%d %s (parent %d)\n", ch.ID, ch.Name, ch.ParentID)
	}
	// Output:
	// 1 Lobby (parent 0)
	// 2 AFK (parent 1)
}

// ClientDatabase pages through the server's client records, fetching the next
// page as the loop reaches it. Breaking out of the loop stops the paging.
func ExampleCommands_IterateClientDatabase() {
	cmds := teamspeak.NewCommands(&recorded{answers: []recordedAnswer{
		{rows: []map[string]string{
			{"cldbid": "1", "client_nickname": "alice"},
			{"cldbid": "2", "client_nickname": "bob"},
		}},
		// The server reports the end of the records as an empty result.
		{err: &teamspeak.ServerError{Code: errcode.DatabaseEmptyResult}},
	}})

	for entry, err := range cmds.IterateClientDatabase(context.Background(), teamspeak.PagingOptions{}) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(entry.DatabaseID, entry.Nickname)
	}
	// Output:
	// 1 alice
	// 2 bob
}

// A server refusal is a *ServerError, which matches its errcode.Code and
// ErrServer with errors.Is, and carries the server's detail for errors.As.
func ExampleServerError() {
	cmds := teamspeak.NewCommands(&recorded{answers: []recordedAnswer{{err: &teamspeak.ServerError{
		Code:         errcode.PermissionsClientInsufficient,
		Message:      "insufficient client permissions",
		FailedPermID: 4353,
	}}}})

	opts := teamspeak.ClientKickOptions{ReasonMessage: "spam"}
	err := cmds.KickClient(context.Background(), 5, teamspeak.ReasonKickServer, opts)

	fmt.Println(errors.Is(err, errcode.PermissionsClientInsufficient))
	fmt.Println(errors.Is(err, teamspeak.ErrServer))
	if serverErr, ok := errors.AsType[*teamspeak.ServerError](err); ok {
		fmt.Println("failed permission:", serverErr.FailedPermID)
	}
	// Output:
	// true
	// true
	// failed permission: 4353
}

// A permission is named by its name, the portable choice, or by its id, which
// can differ between server builds.
func ExamplePermission() {
	byName := teamspeak.PermissionByName("i_client_talk_power")
	byID := teamspeak.PermissionByID(4353)

	fmt.Println(byName, byName.Name())
	fmt.Println(byID, byID.ID())
	fmt.Println(teamspeak.Permission{}.IsZero())
	// Output:
	// i_client_talk_power i_client_talk_power
	// permission 4353 4353
	// true
}

// A file transfer is negotiated with the server over the connection, then the
// data goes over a connection of its own: InitFileUpload answers with where to
// send it, and UploadFileData sends it.
func ExampleUploadFileData() { //nolint:testableexamples // needs a server, so it is compiled, not run
	ctx := context.Background()
	id, err := identity.Generate(ctx, 8)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(id, "ts.example.com", "bot")
	if err != nil {
		log.Fatal(err)
	}
	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	data := []byte("hello")

	upload, err := c.InitFileUpload(ctx, 1, "/notes.txt", uint64(len(data)),
		teamspeak.FileUploadOptions{Overwrite: true})
	if err != nil {
		log.Fatal(err)
	}
	err = teamspeak.UploadFileData(ctx, "ts.example.com", upload, bytes.NewReader(data), teamspeak.FileTransferOptions{})
	if err != nil {
		log.Fatal(err)
	}
}
