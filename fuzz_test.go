package teamspeak

import (
	"context"
	"testing"

	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// answerRows is an Executor that answers every request with the same rows.
type answerRows struct{ rows []map[string]string }

func (a answerRows) Send(context.Context, Request) ([]map[string]string, error) {
	return a.rows, nil
}

// rowsFromText reads the rows a server's answer would carry out of text, the
// way the transports do: split into rows, each parsed into its parameters.
func rowsFromText(text string) []map[string]string {
	var rows []map[string]string
	for _, line := range wire.SplitRows(text) {
		if parsed := wire.ParseCommand(line); parsed != nil {
			rows = append(rows, parsed.Params)
		}
	}

	return rows
}

// FuzzTypedResponses runs every typed command that turns an answer into
// values over whatever rows a server might send, which is where a number too
// wide for its field, a missing field or a field of the wrong kind first meets
// code that indexes, converts and allocates. Nothing a server answers may
// panic, and a list has one entry per row.
func FuzzTypedResponses(f *testing.F) {
	f.Add("clid=1 cid=2 client_nickname=a\\sb client_unique_identifier=abc= client_type=0|clid=3 cid=2")
	f.Add("cid=1 pid=0 channel_name=Lobby channel_maxclients=-1 channel_icon_id=-2004712318|cid=2 pid=1")
	f.Add("sgid=6 name=Guest type=1 iconid=300 savedb=1|sgid=7 name=Admin")
	f.Add("cldbid=9 client_created=99999999999999999999 client_lastconnected=-1 " +
		"client_totalconnections=18446744073709551615")
	f.Add("banid=1 ip=1.2.3.4 duration=0 created=1700000000000000000 invokercldbid=2|banid=2")
	f.Add("permid=4 permvalue=-1 permnegated=1 permskip=0|permid=5 permsid=b_virtualserver_modify")
	f.Add("path=/ size=1 datetime=1700000000 type=1 name=a|size=9999999999999999999999")
	f.Add("clientftfid=1 serverftfid=2 ftkey=abc port=30033 size=100 status=2568")
	f.Add("version=3.13.7 platform=Linux build=1700000000 virtualserver_status=online")
	f.Add("msgid=1 flag_read=1 timestamp=1 subject=hi|msgid=2")
	f.Add("last_pos=0 file_size=1 l=2023-01-01\\s00:00:00|l=x")
	f.Add("token=a tokentype=1 token1=2 token2=3 token_created=4|token=b")
	f.Add("=|=|\\p|-1")

	f.Fuzz(func(t *testing.T, text string) {
		rows := rowsFromText(text)
		c := NewCommands(answerRows{rows: rows})
		ctx := t.Context()

		clients, err := c.ListClients(ctx, ClientListOptions{Away: true, Groups: true, Times: true})
		if err == nil && len(clients) != len(rows) {
			t.Fatalf("ListClients: %d clients from %d rows", len(clients), len(rows))
		}
		channels, err := c.ListChannels(ctx)
		if err == nil && len(channels) != len(rows) {
			t.Fatalf("ListChannels: %d channels from %d rows", len(channels), len(rows))
		}

		readLists(ctx, c)
		readValues(ctx, c)
		readCreated(ctx, c)

		seen := 0
		for _, err := range c.ClientDatabase(ctx) {
			seen++
			if err != nil || seen >= 3*clientDatabasePageSize {
				break
			}
		}
	})
}

// readLists runs the typed commands that list or find, whose rows each become
// an entry.
func readLists(ctx context.Context, c *Commands) {
	_, _ = c.ListServerGroups(ctx)
	_, _ = c.ListChannelGroups(ctx)
	_, _ = c.ListBans(ctx)
	_, _ = c.ListMessages(ctx)
	_, _ = c.ListComplaints(ctx, ComplaintListOptions{})
	_, _ = c.ListPrivilegeKeys(ctx)
	_, _ = c.ListTempPasswords(ctx)
	_, _ = c.ListActiveTransfers(ctx)
	_, _ = c.ListBindings(ctx, BindingListOptions{})
	_, _ = c.ListPermissions(ctx)
	_, _ = c.ListChannelPermissions(ctx, 1)
	_, _ = c.ListClientPermissions(ctx, 1)
	_, _ = c.ListChannelClientPermissions(ctx, 1, 1)
	_, _ = c.ListChannelGroupPermissions(ctx, 1)
	_, _ = c.ListServerGroupPermissions(ctx, 1)
	_, _ = c.ListChannelGroupClients(ctx, ChannelGroupClientListOptions{})
	_, _ = c.ListServerGroupClients(ctx, 1, ServerGroupClientListOptions{})
	_, _ = c.GetServerGroupsByClient(ctx, 1)
	_, _ = c.GetPermissionOverview(ctx, 1, 1)
	_, _ = c.FindPermission(ctx, PermissionByName("b_virtualserver_modify"))
	_, _ = c.FindClients(ctx, "a")
	_, _ = c.FindChannels(ctx, "a")
	_, _ = c.FindClientDatabase(ctx, "a")
	_, _ = c.ListFiles(ctx, 1, "/", FileOptions{})
}

// readValues runs the typed commands that read one value, or one record, out
// of the first row.
func readValues(ctx context.Context, c *Commands) {
	_, _ = c.GetMessage(ctx, 1)
	_, found, _ := c.GetPermissionIDByName(ctx, "b_virtualserver_modify")
	_ = found
	_, _ = c.GetClientIDs(ctx, "uid")
	_, _ = c.GetClientDBIDByUID(ctx, "uid")
	_, _ = c.GetClientUIDByID(ctx, 1)
	_, _ = c.GetClientNameByDBID(ctx, 1)
	_, name, _ := c.GetClientNameByUID(ctx, "uid")
	_ = name
	_, _ = c.GetClientDatabaseInfo(ctx, 1)
	_, _ = c.GetClientInfo(ctx, 1)
	_, _ = c.GetChannelInfo(ctx, 1)
	_, _ = c.GetServerInfo(ctx)
	_, _ = c.GetHostInfo(ctx)
	_, _ = c.GetInstanceInfo(ctx)
	_, _ = c.GetVersion(ctx)
	_, _ = c.WhoAmI(ctx)
	_, _ = c.GetConnectionInfo(ctx)
	_, _ = c.GetServerIDByPort(ctx, 9987)
	_, _ = c.ViewLog(ctx, LogViewOptions{})
	_, _ = c.GetFileInfo(ctx, 1, "/a", FileOptions{})
}

// readCreated runs the typed commands that answer with the id of what they
// made, or with the key of a transfer.
func readCreated(ctx context.Context, c *Commands) {
	_, _ = c.InitFileUpload(ctx, 1, "/a", 10, FileUploadOptions{})
	_, _ = c.InitFileDownload(ctx, 1, "/a", FileDownloadOptions{})
	_, _ = c.CreateServerGroup(ctx, "g", GroupRegular)
	_, _ = c.CreateChannelGroup(ctx, "g", GroupRegular)
	_, _ = c.CopyServerGroup(ctx, 1, 0, "g", GroupRegular)
	_, _ = c.CopyChannelGroup(ctx, 1, 0, "g", GroupRegular)
	_, _ = c.CreateChannel(ctx, ChannelCreateOptions{Name: "a"})
	_, _ = c.AddBan(ctx, BanOptions{IP: "1.2.3.4"})
	_, _ = c.BanClient(ctx, 1, BanClientOptions{})
	_, _ = c.AddPrivilegeKey(ctx, PrivilegeKeyOptions{})
}
