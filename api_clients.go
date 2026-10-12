package teamspeak

import "context"

// Client commands.
//
// A "client" is someone connected right now, identified by clid; a "client
// database entry" is the persistent record, identified by cldbid. Both exist
// and both appear below, so the two are named apart in the types rather than
// leaving the reader to tell a uint16 from a uint64.

func parseClient(row map[string]string) ClientInfo {
	return ClientInfo{
		ID:             fieldUint16(row, "clid"),
		Nickname:       fieldStr(row, "client_nickname"),
		UID:            fieldStr(row, "client_unique_identifier"),
		ChannelID:      fieldUint(row, "cid"),
		ChannelGroupID: fieldUint(row, "client_channel_group_id"),
		Type:           int(fieldInt(row, "client_type")),
		ServerGroups:   fieldUintList(row, "client_servergroups"),
		IsAway:         fieldBool(row, "client_away"),
		IsRecording:    fieldBool(row, "client_is_recording"),
		IsTalker:       fieldBool(row, "client_is_talker"),
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
func (c *Commands) GetClientInfo(ctx context.Context, clid uint16) (map[string]string, error) {
	rows, err := c.query(ctx, "clientinfo", []param{uintArg("clid", uint64(clid))})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errNoDataReturned
	}

	return rows[0], nil
}

// KickClient disconnects a client from the server.
func (c *Commands) KickClient(ctx context.Context, clid uint16, reasonID int, reasonMessage *string) error {
	return c.exec(ctx, "clientkick", []param{
		uintArg("clid", uint64(clid)),
		intArg("reasonid", int64(reasonID)),
		strPtrArg("reasonmsg", reasonMessage),
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

// EditClient changes another client's editable attributes.
func (c *Commands) EditClient(ctx context.Context, clid uint16, description *string, isTalker *bool) error {
	return c.exec(ctx, "clientedit", []param{
		uintArg("clid", uint64(clid)),
		strPtrArg("client_description", description),
		boolPtrArg("client_is_talker", isTalker),
	})
}

// PokeClient sends a poke to a client.
func (c *Commands) PokeClient(ctx context.Context, clid uint16, message string) error {
	return c.exec(ctx, "clientpoke", []param{
		uintArg("clid", uint64(clid)),
		strArg("msg", message),
	})
}

// ClientMatch is one row of a clientfind result.
type ClientMatch struct {
	Nickname string
	ID       uint16
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
			ID:       fieldUint16(row, "clid"),
			Nickname: fieldStr(row, "client_nickname"),
		})
	}

	return out, nil
}

// SetClientChannelGroup puts a client into a channel group in a channel.
func (c *Commands) SetClientChannelGroup(ctx context.Context, channelGroupID, channelID, clientDBID uint64) error {
	return c.exec(ctx, "setclientchannelgroup", []param{
		uintArg("cgid", channelGroupID),
		uintArg("cid", channelID),
		uintArg("cldbid", clientDBID),
	})
}

// ---- Client database --------------------------------------------------------

// ClientDatabaseEntry is a persistent client record.
type ClientDatabaseEntry struct {
	UID              string
	Nickname         string
	Description      string
	LastIP           string
	DatabaseID       uint64
	Created          uint64
	LastConnected    uint64
	TotalConnections uint64
}

func parseDatabaseEntry(row map[string]string) ClientDatabaseEntry {
	return ClientDatabaseEntry{
		DatabaseID:       fieldUint(row, "cldbid"),
		UID:              fieldStr(row, "client_unique_identifier"),
		Nickname:         fieldStr(row, "client_nickname"),
		Created:          fieldUint(row, "client_created"),
		LastConnected:    fieldUint(row, "client_lastconnected"),
		TotalConnections: fieldUint(row, "client_totalconnections"),
		Description:      fieldStr(row, "client_description"),
		LastIP:           fieldStr(row, "client_lastip"),
	}
}

// ListClientDatabase walks the persistent client records.
//
// This is the whole database, so it is paged: pass a start and duration to take
// a slice. A nil start asks for the first page.
func (c *Commands) ListClientDatabase(ctx context.Context, start, duration *uint64) ([]ClientDatabaseEntry, error) {
	rows, err := c.query(ctx, "clientdblist", []param{
		uintPtrArg("start", start),
		uintPtrArg("duration", duration),
	})
	if err != nil {
		return nil, err
	}

	out := make([]ClientDatabaseEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseDatabaseEntry(row))
	}

	return out, nil
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
func (c *Commands) GetClientDatabaseInfo(ctx context.Context, clientDBID uint64) (ClientDatabaseEntry, error) {
	rows, err := c.query(ctx, "clientdbinfo", []param{uintArg("cldbid", clientDBID)})
	if err != nil {
		return ClientDatabaseEntry{}, err
	}

	if len(rows) == 0 {
		return ClientDatabaseEntry{}, errNoDataReturned
	}

	return parseDatabaseEntry(rows[0]), nil
}

// EditClientDatabase changes a persistent client record.
func (c *Commands) EditClientDatabase(ctx context.Context, clientDBID uint64, description, nickname *string) error {
	return c.exec(ctx, "clientdbedit", []param{
		uintArg("cldbid", clientDBID),
		strPtrArg("client_description", description),
		strPtrArg("client_nickname", nickname),
	})
}

// DeleteClientDatabase removes a client from the database entirely.
func (c *Commands) DeleteClientDatabase(ctx context.Context, clientDBID uint64) error {
	return c.exec(ctx, "clientdbdelete", []param{uintArg("cldbid", clientDBID)})
}

// AddClientPermission grants a permission to a client.
//
// permSkip is required by the server here, unlike the channel equivalent.
func (c *Commands) AddClientPermission(
	ctx context.Context, clientDBID uint64, permValue int32, permSkip bool, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "clientaddperm", []param{
		uintArg("cldbid", clientDBID),
		intArg("permvalue", int64(permValue)),
		boolArg("permskip", permSkip),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// DeleteClientPermission removes a permission from a client.
func (c *Commands) DeleteClientPermission(
	ctx context.Context, clientDBID uint64, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "clientdelperm", []param{
		uintArg("cldbid", clientDBID),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// MoveClient moves a client to another channel.
//
// A channel password travels as base64(sha1(password)) rather than cleartext;
// passing a plaintext one makes a correct password fail with error 781.
func (c *Commands) MoveClient(ctx context.Context, clid uint16, channelID uint64, password string) error {
	params := []param{
		uintArg("clid", uint64(clid)),
		uintArg("cid", channelID),
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
func (c *Commands) GetClientDBIDByUID(ctx context.Context, uid string) (uint64, error) {
	rows, err := c.query(ctx, "clientgetdbidfromuid", []param{strArg("cluid", uid)})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "cldbid"), nil
}

// GetClientIDs returns every clid currently using a uid.
func (c *Commands) GetClientIDs(ctx context.Context, uid string) ([]uint16, error) {
	rows, err := c.query(ctx, "clientgetids", []param{strArg("cluid", uid)})
	if err != nil {
		return nil, err
	}

	out := make([]uint16, 0, len(rows))
	for _, row := range rows {
		out = append(out, fieldUint16(row, "clid"))
	}

	return out, nil
}

// GetClientUIDByID returns the uid of a connected client.
func (c *Commands) GetClientUIDByID(ctx context.Context, clid uint16) (string, error) {
	rows, err := c.query(ctx, "clientgetuidfromclid", []param{uintArg("clid", uint64(clid))})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "cluid"), nil
}

// GetClientNameByDBID returns the nickname recorded for a database id.
func (c *Commands) GetClientNameByDBID(ctx context.Context, clientDBID uint64) (string, error) {
	rows, err := c.query(ctx, "clientgetnamefromdbid", []param{uintArg("cldbid", clientDBID)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "name"), nil
}

// GetClientNameByUID returns the database id and nickname recorded for a uid.
func (c *Commands) GetClientNameByUID(ctx context.Context, uid string) (uint64, string, error) {
	rows, err := c.query(ctx, "clientgetnamefromuid", []param{strArg("cluid", uid)})
	if err != nil {
		return 0, "", err
	}

	if len(rows) == 0 {
		return 0, "", nil
	}

	return fieldUint(rows[0], "cldbid"), fieldStr(rows[0], "name"), nil
}

// ListClientPermissions returns the permissions granted to a client from the
// database.
func (c *Commands) ListClientPermissions(ctx context.Context, clientDBID uint64) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "clientpermlist", []param{uintArg("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}
