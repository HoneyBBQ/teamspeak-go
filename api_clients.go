package teamspeak

import (
	"context"
	"errors"
	"iter"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Client commands.
//
// A "client" is someone connected right now, identified by clid; a "client
// database entry" is the persistent record, identified by cldbid. Both exist
// and both appear below, so the two are named apart in the types — ClientID
// and ClientDBID — rather than leaving the reader to tell a uint16 from a
// uint64.

func parseClient(row map[string]string) ClientInfo {
	return ClientInfo{
		ID:             ClientID(fieldUint16(row, "clid")),
		Nickname:       fieldStr(row, "client_nickname"),
		UID:            UID(fieldStr(row, "client_unique_identifier")),
		ChannelID:      ChannelID(fieldUint(row, "cid")),
		ChannelGroupID: ChannelGroupID(fieldUint(row, "client_channel_group_id")),
		Type:           ClientType(fieldInt(row, "client_type")),
		ServerGroups:   fieldIDList[ServerGroupID](row, "client_servergroups"),
		IsAway:         fieldBool(row, "client_away"),
		IsRecording:    fieldBool(row, "client_is_recording"),
		IsTalker:       fieldBool(row, "client_is_talker"),
		Created:        fieldTime(row, "client_created"),
		LastConnected:  fieldTime(row, "client_lastconnected"),
		IdleTime:       fieldDuration(row, "client_idle_time", time.Millisecond),
	}
}

// ClientListOptions selects which optional fields clientlist should include.
//
// The uid is on by default because almost every caller needs it — it is how a
// client is identified across reconnects, and the clid changes every time.
type ClientListOptions struct {
	// OmitUID drops -uid from the request.
	OmitUID bool
	Away    bool
	Voice   bool
	Groups  bool
	Times   bool
	Info    bool
	Country bool
	IP      bool
	Badges  bool
}

// ListClients returns every client currently connected.
func (c *Commands) ListClients(ctx context.Context, opts ...ClientListOptions) ([]ClientInfo, error) {
	var options ClientListOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	params := make([]param, 0, 9)
	if !options.OmitUID {
		params = append(params, boolArg("-uid", true))
	}
	for _, flag := range []struct {
		key string
		on  bool
	}{
		{"-away", options.Away},
		{"-voice", options.Voice},
		{"-groups", options.Groups},
		{"-times", options.Times},
		{"-info", options.Info},
		{"-country", options.Country},
		{"-ip", options.IP},
		{"-badges", options.Badges},
	} {
		if flag.on {
			params = append(params, boolArg(flag.key, true))
		}
	}

	rows, err := c.query(ctx, "clientlist", params)
	if err != nil {
		return nil, err
	}

	clients := make([]ClientInfo, 0, len(rows))
	for _, row := range rows {
		clients = append(clients, parseClient(row))
	}

	return clients, nil
}

// GetClientInfo returns one connected client's detail, unfiltered.
//
// Returned as the server sent it rather than narrowed to a struct: clientinfo
// carries well over a hundred fields and which ones appear depends on
// permissions, so anything narrower would silently drop data the caller asked
// for. Use ListClients for parsed fields.
func (c *Commands) GetClientInfo(ctx context.Context, clid ClientID) (map[string]string, error) {
	rows, err := c.query(ctx, "clientinfo", []param{idArg("clid", clid)})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrNoData
	}

	return rows[0], nil
}

// KickClient kicks a client from its channel (ReasonKickChannel), which moves
// it to the default channel, or from the server (ReasonKickServer), which
// disconnects it. Any other reason is refused with ErrInvalidCommand. message
// is shown to the client; "" sends none.
func (c *Commands) KickClient(ctx context.Context, clid ClientID, reason Reason, message string) error {
	reasonParam := intArg("reasonid", int64(reason))
	if reason != ReasonKickChannel && reason != ReasonKickServer {
		reasonParam = invalidArg("a kick's reason is ReasonKickChannel or ReasonKickServer, not " + reason.String())
	}

	return c.exec(ctx, "clientkick", []param{
		idArg("clid", clid),
		reasonParam,
		optStrArg("reasonmsg", message),
	})
}

// ClientUpdateOptions changes our own client state. Only the fields you set are
// sent.
//
// clientupdate addresses the calling client implicitly — there is no clid on
// the wire — which is why this takes no id.
type ClientUpdateOptions struct {
	Nickname           *string
	AwayMessage        *string
	Avatar             *string
	NicknamePhonetic   *string
	TalkRequestMsg     *string
	Badges             *string
	InputMuted         *bool
	OutputMuted        *bool
	Away               *bool
	InputHardware      *bool
	OutputHardware     *bool
	IsChannelCommander *bool
	IsRecording        *bool
	TalkRequest        *int32
}

// UpdateClient changes our own client state (nickname, mute, away, …).
func (c *Commands) UpdateClient(ctx context.Context, opts ClientUpdateOptions) error {
	return c.exec(ctx, "clientupdate", []param{
		strPtrArg("client_nickname", opts.Nickname),
		boolPtrArg("client_input_muted", opts.InputMuted),
		boolPtrArg("client_output_muted", opts.OutputMuted),
		boolPtrArg("client_away", opts.Away),
		strPtrArg("client_away_message", opts.AwayMessage),
		boolPtrArg("client_input_hardware", opts.InputHardware),
		boolPtrArg("client_output_hardware", opts.OutputHardware),
		boolPtrArg("client_is_channel_commander", opts.IsChannelCommander),
		strPtrArg("client_flag_avatar", opts.Avatar),
		strPtrArg("client_nickname_phonetic", opts.NicknamePhonetic),
		int32PtrArg("client_talk_request", opts.TalkRequest),
		strPtrArg("client_talk_request_msg", opts.TalkRequestMsg),
		boolPtrArg("client_is_recording", opts.IsRecording),
		strPtrArg("client_badges", opts.Badges),
	})
}

// ClientEditOptions change another client's editable attributes. Only the
// fields you set are sent: a pointer to "" clears the description, while nil
// leaves it alone.
type ClientEditOptions struct {
	Description *string
	IsTalker    *bool
}

// EditClient changes another client's editable attributes.
func (c *Commands) EditClient(ctx context.Context, clid ClientID, opts ClientEditOptions) error {
	return c.exec(ctx, "clientedit", []param{
		idArg("clid", clid),
		strPtrArg("client_description", opts.Description),
		boolPtrArg("client_is_talker", opts.IsTalker),
	})
}

// PokeClient sends a poke to a client.
func (c *Commands) PokeClient(ctx context.Context, clid ClientID, message string) error {
	return c.exec(ctx, "clientpoke", []param{
		idArg("clid", clid),
		strArg("msg", message),
	})
}

// ClientMatch is one row of a clientfind result.
type ClientMatch struct {
	Nickname string
	ID       ClientID
}

// FindClients returns clients whose nickname contains pattern.
func (c *Commands) FindClients(ctx context.Context, pattern string) ([]ClientMatch, error) {
	rows, err := c.query(ctx, "clientfind", []param{strArg("pattern", pattern)})
	if err != nil {
		return nil, err
	}

	out := make([]ClientMatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClientMatch{
			ID:       ClientID(fieldUint16(row, "clid")),
			Nickname: fieldStr(row, "client_nickname"),
		})
	}

	return out, nil
}

// SetClientChannelGroup puts a client into a channel group in a channel.
func (c *Commands) SetClientChannelGroup(
	ctx context.Context, channelGroupID ChannelGroupID, channelID ChannelID, clientDBID ClientDBID,
) error {
	return c.exec(ctx, "setclientchannelgroup", []param{
		idArg("cgid", channelGroupID),
		idArg("cid", channelID),
		idArg("cldbid", clientDBID),
	})
}

// ---- Client database --------------------------------------------------------

// ClientDatabaseEntry is a persistent client record.
type ClientDatabaseEntry struct {
	// Created is when the client first connected.
	Created time.Time
	// LastConnected is when the client last connected.
	LastConnected    time.Time
	UID              UID
	Nickname         string
	Description      string
	LastIP           string
	DatabaseID       ClientDBID
	TotalConnections uint64
}

func parseDatabaseEntry(row map[string]string) ClientDatabaseEntry {
	return ClientDatabaseEntry{
		DatabaseID:       ClientDBID(fieldUint(row, "cldbid")),
		UID:              UID(fieldStr(row, "client_unique_identifier")),
		Nickname:         fieldStr(row, "client_nickname"),
		Created:          fieldTime(row, "client_created"),
		LastConnected:    fieldTime(row, "client_lastconnected"),
		TotalConnections: fieldUint(row, "client_totalconnections"),
		Description:      fieldStr(row, "client_description"),
		LastIP:           fieldStr(row, "client_lastip"),
	}
}

// clientDatabasePageSize is how many records ClientDatabase asks for at a time.
const clientDatabasePageSize = 100

// ClientDatabase walks every persistent client record, fetching them from the
// server a page at a time as the loop asks for more:
//
//	for entry, err := range c.ClientDatabase(ctx) {
//		if err != nil {
//			return err
//		}
//		...
//	}
//
// The server pages clientdblist (start, duration) and answers a start past the
// last record with error 1281, "database empty result set", which here is the
// end of the walk rather than an error. A page shorter than an earlier one
// ends it too. The first page cannot end it that way: the server may cap a
// page below what was asked, so a short first page might be a capped one, and
// the walk asks once more to find out.
//
// Any other error is yielded once, with a zero entry, and ends the walk.
// Records added or removed during the walk can be skipped or seen twice, since
// each page is a separate query.
func (c *Commands) ClientDatabase(ctx context.Context) iter.Seq2[ClientDatabaseEntry, error] {
	return func(yield func(ClientDatabaseEntry, error) bool) {
		var start, fullPage int
		for {
			rows, err := c.query(ctx, "clientdblist", []param{
				uintArg("start", uint64(start)),
				uintArg("duration", clientDatabasePageSize),
			})
			if errors.Is(err, errcode.DatabaseEmptyResult) {
				return
			}
			if err != nil {
				yield(ClientDatabaseEntry{}, err)

				return
			}

			for _, row := range rows {
				if !yield(parseDatabaseEntry(row), nil) {
					return
				}
			}

			if len(rows) == 0 || len(rows) < fullPage {
				return
			}
			fullPage = max(fullPage, len(rows))
			start += len(rows)
		}
	}
}

// FindClientDatabase returns database records matching pattern.
func (c *Commands) FindClientDatabase(ctx context.Context, pattern string) ([]ClientDatabaseEntry, error) {
	rows, err := c.query(ctx, "clientdbfind", []param{strArg("pattern", pattern)})
	if err != nil {
		return nil, err
	}

	out := make([]ClientDatabaseEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseDatabaseEntry(row))
	}

	return out, nil
}

// GetClientDatabaseInfo returns one persistent client record.
func (c *Commands) GetClientDatabaseInfo(ctx context.Context, clientDBID ClientDBID) (ClientDatabaseEntry, error) {
	rows, err := c.query(ctx, "clientdbinfo", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return ClientDatabaseEntry{}, err
	}

	if len(rows) == 0 {
		return ClientDatabaseEntry{}, ErrNoData
	}

	return parseDatabaseEntry(rows[0]), nil
}

// ClientDatabaseEditOptions change a persistent client record. Only the fields
// you set are sent: a pointer to "" clears the description, while nil leaves
// it alone.
type ClientDatabaseEditOptions struct {
	Description *string
	Nickname    *string
}

// EditClientDatabase changes a persistent client record.
func (c *Commands) EditClientDatabase(
	ctx context.Context, clientDBID ClientDBID, opts ClientDatabaseEditOptions,
) error {
	return c.exec(ctx, "clientdbedit", []param{
		idArg("cldbid", clientDBID),
		strPtrArg("client_description", opts.Description),
		strPtrArg("client_nickname", opts.Nickname),
	})
}

// DeleteClientDatabase removes a client from the database entirely.
func (c *Commands) DeleteClientDatabase(ctx context.Context, clientDBID ClientDBID) error {
	return c.exec(ctx, "clientdbdelete", []param{idArg("cldbid", clientDBID)})
}

// AddClientPermission sets a permission on a client, server-wide.
//
// skip is required by the server here, unlike the channel equivalent.
func (c *Commands) AddClientPermission(
	ctx context.Context, clientDBID ClientDBID, perm Permission, value int32, skip bool,
) error {
	return c.exec(ctx, "clientaddperm", []param{
		idArg("cldbid", clientDBID),
		permArg(perm),
		intArg("permvalue", int64(value)),
		boolArg("permskip", skip),
	})
}

// DeleteClientPermission removes a permission from a client.
func (c *Commands) DeleteClientPermission(ctx context.Context, clientDBID ClientDBID, perm Permission) error {
	return c.exec(ctx, "clientdelperm", []param{
		idArg("cldbid", clientDBID),
		permArg(perm),
	})
}

// MoveClient moves a client to another channel.
//
// A channel password travels as base64(sha1(password)) rather than cleartext;
// passing a plaintext one makes a correct password fail with error 781.
func (c *Commands) MoveClient(ctx context.Context, clid ClientID, channelID ChannelID, password string) error {
	params := []param{
		idArg("clid", clid),
		idArg("cid", channelID),
	}
	if password != "" {
		params = append(params, strArg("cpw", password))
	}

	return c.exec(ctx, "clientmove", params, "cpw")
}

// ---- Client lookups -----------------------------------------------------------
//
// The voice protocol answers these with a notification (notifyclientids and
// the like) rather than data rows; the client pairs it with the command.

// GetClientDBIDByUID returns the persistent database id behind a uid.
func (c *Commands) GetClientDBIDByUID(ctx context.Context, uid UID) (ClientDBID, error) {
	rows, err := c.query(ctx, "clientgetdbidfromuid", []param{strArg("cluid", string(uid))})
	if err != nil {
		return 0, err
	}

	return ClientDBID(firstOrEmpty(rows, "cldbid")), nil
}

// GetClientIDs returns every clid currently using a uid.
func (c *Commands) GetClientIDs(ctx context.Context, uid UID) ([]ClientID, error) {
	rows, err := c.query(ctx, "clientgetids", []param{strArg("cluid", string(uid))})
	if err != nil {
		return nil, err
	}

	out := make([]ClientID, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClientID(fieldUint16(row, "clid")))
	}

	return out, nil
}

// GetClientUIDByID returns the uid of a connected client.
func (c *Commands) GetClientUIDByID(ctx context.Context, clid ClientID) (UID, error) {
	rows, err := c.query(ctx, "clientgetuidfromclid", []param{idArg("clid", clid)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return UID(fieldStr(rows[0], "cluid")), nil
}

// GetClientNameByDBID returns the nickname recorded for a database id.
func (c *Commands) GetClientNameByDBID(ctx context.Context, clientDBID ClientDBID) (string, error) {
	rows, err := c.query(ctx, "clientgetnamefromdbid", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "name"), nil
}

// GetClientNameByUID returns the database id and nickname recorded for a uid.
func (c *Commands) GetClientNameByUID(ctx context.Context, uid UID) (ClientDBID, string, error) {
	rows, err := c.query(ctx, "clientgetnamefromuid", []param{strArg("cluid", string(uid))})
	if err != nil {
		return 0, "", err
	}

	if len(rows) == 0 {
		return 0, "", nil
	}

	return ClientDBID(fieldUint(rows[0], "cldbid")), fieldStr(rows[0], "name"), nil
}

// ListClientPermissions returns the permissions granted to a client from the
// database.
func (c *Commands) ListClientPermissions(ctx context.Context, clientDBID ClientDBID) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "clientpermlist", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}
