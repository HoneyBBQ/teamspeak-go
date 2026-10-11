package teamspeak

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
func (c *Client) ListClients(opts ...ClientListOptions) ([]ClientInfo, error) {
	var options ClientListOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	params := make([]param, 0, 9)
	if !options.OmitUID {
		params = append(params, Bool("-uid", true))
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
			params = append(params, Bool(flag.key, true))
		}
	}

	rows, err := c.query("clientlist", params)
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
func (c *Client) GetClientInfo(clid uint16) (map[string]string, error) {
	rows, err := c.query("clientinfo", []param{Uint("clid", uint64(clid))})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errNoDataReturned
	}

	return rows[0], nil
}

// KickClient disconnects a client from the server.
func (c *Client) KickClient(clid uint16, reasonID int, reasonMessage *string) error {
	return c.exec("clientkick", []param{
		Uint("clid", uint64(clid)),
		Int("reasonid", int64(reasonID)),
		StrPtr("reasonmsg", reasonMessage),
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
func (c *Client) UpdateClient(opts ClientUpdateOptions) error {
	return c.exec("clientupdate", []param{
		StrPtr("client_nickname", opts.Nickname),
		BoolPtr("client_input_muted", opts.InputMuted),
		BoolPtr("client_output_muted", opts.OutputMuted),
		BoolPtr("client_away", opts.Away),
		StrPtr("client_away_message", opts.AwayMessage),
		BoolPtr("client_input_hardware", opts.InputHardware),
		BoolPtr("client_output_hardware", opts.OutputHardware),
		BoolPtr("client_is_channel_commander", opts.IsChannelCommander),
		StrPtr("client_flag_avatar", opts.Avatar),
		StrPtr("client_nickname_phonetic", opts.NicknamePhonetic),
		Int32Ptr("client_talk_request", opts.TalkRequest),
		StrPtr("client_talk_request_msg", opts.TalkRequestMsg),
		BoolPtr("client_is_recording", opts.IsRecording),
		StrPtr("client_badges", opts.Badges),
	})
}

// EditClient changes another client's editable attributes.
func (c *Client) EditClient(clid uint16, description *string, isTalker *bool) error {
	return c.exec("clientedit", []param{
		Uint("clid", uint64(clid)),
		StrPtr("client_description", description),
		BoolPtr("client_is_talker", isTalker),
	})
}

// PokeClient sends a poke to a client.
func (c *Client) PokeClient(clid uint16, message string) error {
	return c.exec("clientpoke", []param{
		Uint("clid", uint64(clid)),
		Str("msg", message),
	})
}

// ClientMatch is one row of a clientfind result.
type ClientMatch struct {
	Nickname string
	ID       uint16
}

// FindClients returns clients whose nickname contains pattern.
func (c *Client) FindClients(pattern string) ([]ClientMatch, error) {
	rows, err := c.query("clientfind", []param{Str("pattern", pattern)})
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
func (c *Client) SetClientChannelGroup(channelGroupID, channelID, clientDBID uint64) error {
	return c.exec("setclientchannelgroup", []param{
		Uint("cgid", channelGroupID),
		Uint("cid", channelID),
		Uint("cldbid", clientDBID),
	})
}

// ChannelID returns the channel the client is currently in, or 0 if that is not
// known yet, for example before the first notifycliententerview.
func (c *Client) ChannelID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if info, ok := c.clients[c.clid]; ok {
		return info.ChannelID
	}

	return 0
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
func (c *Client) ListClientDatabase(start, duration *uint64) ([]ClientDatabaseEntry, error) {
	rows, err := c.query("clientdblist", []param{
		UintPtr("start", start),
		UintPtr("duration", duration),
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
func (c *Client) FindClientDatabase(pattern string) ([]ClientDatabaseEntry, error) {
	rows, err := c.query("clientdbfind", []param{Str("pattern", pattern)})
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
func (c *Client) GetClientDatabaseInfo(clientDBID uint64) (ClientDatabaseEntry, error) {
	rows, err := c.query("clientdbinfo", []param{Uint("cldbid", clientDBID)})
	if err != nil {
		return ClientDatabaseEntry{}, err
	}

	if len(rows) == 0 {
		return ClientDatabaseEntry{}, errNoDataReturned
	}

	return parseDatabaseEntry(rows[0]), nil
}

// EditClientDatabase changes a persistent client record.
func (c *Client) EditClientDatabase(clientDBID uint64, description, nickname *string) error {
	return c.exec("clientdbedit", []param{
		Uint("cldbid", clientDBID),
		StrPtr("client_description", description),
		StrPtr("client_nickname", nickname),
	})
}

// DeleteClientDatabase removes a client from the database entirely.
func (c *Client) DeleteClientDatabase(clientDBID uint64) error {
	return c.exec("clientdbdelete", []param{Uint("cldbid", clientDBID)})
}

// AddClientPermission grants a permission to a client.
//
// permSkip is required by the server here, unlike the channel equivalent.
func (c *Client) AddClientPermission(
	clientDBID uint64, permValue int32, permSkip bool, permID *uint64, permSID *string,
) error {
	return c.exec("clientaddperm", []param{
		Uint("cldbid", clientDBID),
		Int("permvalue", int64(permValue)),
		Bool("permskip", permSkip),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// DeleteClientPermission removes a permission from a client.
func (c *Client) DeleteClientPermission(clientDBID uint64, permID *uint64, permSID *string) error {
	return c.exec("clientdelperm", []param{
		Uint("cldbid", clientDBID),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// MoveClient moves a client to another channel.
//
// A channel password travels as base64(sha1(password)) rather than cleartext;
// passing a plaintext one makes a correct password fail with error 781.
func (c *Client) MoveClient(clid uint16, channelID uint64, password string) error {
	params := []param{
		Uint("clid", uint64(clid)),
		Uint("cid", channelID),
	}
	if password != "" {
		params = append(params, Str("cpw", password))
	}

	return c.exec("clientmove", params, PlainPassword("cpw"))
}

// ---- Client lookups that the voice protocol answers empty ------------------
//
// The five commands below are documented and answer ok, but send no data row
// over the voice protocol — with or without Server Admin rights. The same
// commands return their rows over ServerQuery. They exist here because the
// commands do, and they are honest about returning nothing rather than being
// omitted: a caller porting from ServerQuery should be able to find them and
// read why they come back empty.
//
// See docs/voice-protocol-empty-responses.md in the JS repository. Use
// ListClients or GetClientInfo to read a uid.

// GetClientDBIDByUID returns the persistent database id behind a uid.
//
// Answers empty over the voice protocol.
func (c *Client) GetClientDBIDByUID(uid string) (uint64, error) {
	rows, err := c.query("clientgetdbidfromuid", []param{Str("cluid", uid)})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "cldbid"), nil
}

// GetClientIDs returns every clid currently using a uid.
//
// Answers empty over the voice protocol.
func (c *Client) GetClientIDs(uid string) ([]uint16, error) {
	rows, err := c.query("clientgetids", []param{Str("cluid", uid)})
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
//
// Answers empty over the voice protocol.
func (c *Client) GetClientUIDByID(clid uint16) (string, error) {
	rows, err := c.query("clientgetuidfromclid", []param{Uint("clid", uint64(clid))})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "cluid"), nil
}

// GetClientNameByDBID returns the nickname recorded for a database id.
//
// Answers empty over the voice protocol.
func (c *Client) GetClientNameByDBID(clientDBID uint64) (string, error) {
	rows, err := c.query("clientgetnamefromdbid", []param{Uint("cldbid", clientDBID)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "name"), nil
}

// GetClientNameByUID returns the database id and nickname recorded for a uid.
//
// Answers empty over the voice protocol.
func (c *Client) GetClientNameByUID(uid string) (uint64, string, error) {
	rows, err := c.query("clientgetnamefromuid", []param{Str("cluid", uid)})
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
func (c *Client) ListClientPermissions(clientDBID uint64) ([]PermissionEntry, error) {
	rows, err := c.query("clientpermlist", []param{Uint("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}
