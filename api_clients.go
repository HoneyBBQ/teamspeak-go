package teamspeak

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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

func parseClient(row map[string]string) ClientEntry {
	return ClientEntry{
		ID:             ClientID(fieldUint16(row, "clid")),
		Nickname:       fieldStr(row, "client_nickname"),
		UID:            UID(fieldStr(row, "client_unique_identifier")),
		ChannelID:      ChannelID(fieldUint(row, "cid")),
		ChannelGroupID: ChannelGroupID(fieldUint(row, "client_channel_group_id")),
		Type:           ClientType(fieldEnum(row, "client_type")),
		ServerGroups:   fieldIDList[ServerGroupID](row, "client_servergroups"),
		IsAway:         fieldBool(row, "client_away"),
		IsRecording:    fieldBool(row, "client_is_recording"),
		IsTalker:       fieldBool(row, "client_is_talker"),
		Created:        fieldTime(row, "client_created"),
		LastConnected:  fieldTime(row, "client_lastconnected"),
		IdleTime:       fieldDuration(row, "client_idle_time", time.Millisecond),

		DatabaseID:                     ClientDBID(fieldUint(row, "client_database_id")),
		AwayMessage:                    fieldStr(row, "client_away_message"),
		IsInputMuted:                   fieldOptBool(row, "client_input_muted"),
		IsOutputMuted:                  fieldOptBool(row, "client_output_muted"),
		IsOutputOnlyMuted:              fieldOptBool(row, "client_outputonly_muted"),
		HasInputHardware:               fieldOptBool(row, "client_input_hardware"),
		HasOutputHardware:              fieldOptBool(row, "client_output_hardware"),
		IsChannelCommander:             fieldOptBool(row, "client_is_channel_commander"),
		IsPrioritySpeaker:              fieldOptBool(row, "client_is_priority_speaker"),
		TalkPower:                      fieldOptInt32(row, "client_talk_power"),
		IsRequestingTalk:               fieldOptBool(row, "client_talk_request"),
		TalkRequestMessage:             fieldStr(row, "client_talk_request_msg"),
		Description:                    fieldStr(row, "client_description"),
		MetaData:                       fieldStr(row, "client_meta_data"),
		Avatar:                         fieldStr(row, "client_flag_avatar"),
		IconID:                         fieldIconID(row, "client_icon_id"),
		NicknamePhonetic:               fieldStr(row, "client_nickname_phonetic"),
		UnreadMessages:                 fieldOptInt32(row, "client_unread_messages"),
		NeededServerQueryViewPower:     fieldOptInt32(row, "client_needed_serverquery_view_power"),
		ChannelGroupInheritedChannelID: ChannelID(fieldUint(row, "client_channel_group_inherited_channel_id")),
		Country:                        fieldStr(row, "client_country"),
		Version:                        fieldStr(row, "client_version"),
		Platform:                       fieldStr(row, "client_platform"),
		IP:                             fieldStr(row, "connection_client_ip"),
		Badges:                         fieldStr(row, "client_badges"),
		SignedBadges:                   fieldStr(row, "client_signed_badges"),
		MyTeamSpeakID:                  fieldStr(row, "client_myteamspeak_id"),
		MyTeamSpeakAvatar:              fieldStr(row, "client_myteamspeak_avatar"),
		Integrations:                   fieldStr(row, "client_integrations"),
		UserTag:                        fieldStr(row, "client_user_tag"),
		IsStreaming:                    fieldOptBool(row, "client_is_streaming"),
	}
}

// ClientListOptions selects which optional fields clientlist should include.
//
// The uid is on by default because almost every caller needs it — it is how a
// client is identified across reconnects, and the clid changes every time.
type ClientListOptions struct {
	// OmitUID drops -uid from the request.
	OmitUID bool
	// Away adds whether each client is away and its message (-away).
	Away bool
	// Voice adds each client's mute, talk and recording state (-voice).
	Voice bool
	// Groups adds each client's server and channel groups (-groups).
	Groups bool
	// Times adds when each client was created, last connected and last active
	// (-times).
	Times bool
	// Info adds each client's version and platform (-info).
	Info bool
	// Country adds each client's country (-country).
	Country bool
	// IP adds each client's address (-ip).
	IP bool
	// Badges adds each client's badges (-badges).
	Badges bool
}

// ListClients returns every client currently connected, with the optional
// fields options asks for.
func (c *Commands) ListClients(ctx context.Context, options ClientListOptions) ([]ClientEntry, error) {
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

	rows, err := c.list(ctx, "clientlist", params)
	if err != nil {
		return nil, err
	}

	clients := make([]ClientEntry, 0, len(rows))
	for _, row := range rows {
		clients = append(clients, parseClient(row))
	}

	return clients, nil
}

// GetClientProperties returns one connected client's detail, unfiltered; the
// prop package names the keys.
//
// Returned as the server sent it, as Properties, rather than narrowed to a
// struct: clientinfo carries well over a hundred fields and which ones appear
// depends on permissions, so anything narrower would silently drop data the
// caller asked for. Use ListClients for parsed fields.
func (c *Commands) GetClientProperties(ctx context.Context, clid ClientID) (Properties, error) {
	return c.queryRow(ctx, "clientinfo", "", []param{idArg("clid", clid)})
}

// ClientKickOptions are KickClient's optional parameters.
type ClientKickOptions struct {
	// ReasonMessage is shown to the client; "" sends none.
	ReasonMessage string
}

// KickClient kicks a client from its channel (ReasonKickChannel), which moves
// it to the default channel, or from the server (ReasonKickServer), which
// disconnects it. Any other reason is refused with ErrInvalidCommand.
func (c *Commands) KickClient(ctx context.Context, clid ClientID, reason Reason, opts ClientKickOptions) error {
	reasonParam := intArg("reasonid", int64(reason))
	if reason != ReasonKickChannel && reason != ReasonKickServer {
		reasonParam = invalidArg("a kick's reason is ReasonKickChannel or ReasonKickServer, not " + reason.String())
	}

	return c.exec(ctx, "clientkick", []param{
		idArg("clid", clid),
		reasonParam,
		optStrArg("reasonmsg", opts.ReasonMessage),
	})
}

// ClientUpdateOptions changes our own client state. Only the fields you set are
// sent.
//
// clientupdate addresses the calling client implicitly — there is no clid on
// the wire — which is why this takes no id.
type ClientUpdateOptions struct {
	// Nickname is our nickname (client_nickname).
	Nickname *string
	// NicknamePhonetic is how the nickname is pronounced, for text-to-speech
	// (client_nickname_phonetic).
	NicknamePhonetic *string
	// AwayMessage is the away message (client_away_message); a pointer to ""
	// clears it.
	AwayMessage *string
	// TalkRequestMessage is the message sent with a talk request
	// (client_talk_request_msg).
	TalkRequestMessage *string
	// Avatar is our avatar's MD5, as uploaded to the file area; a pointer to
	// "" removes it (client_flag_avatar).
	Avatar *string
	// Badges are our badges, in the client's own format (client_badges).
	Badges *string
	// IsInputMuted is whether our microphone is muted (client_input_muted).
	IsInputMuted *bool
	// IsOutputMuted is whether our speakers are muted (client_output_muted).
	IsOutputMuted *bool
	// HasInputHardware is whether we have a working microphone
	// (client_input_hardware).
	HasInputHardware *bool
	// HasOutputHardware is whether we have working speakers
	// (client_output_hardware).
	HasOutputHardware *bool
	// IsAway is whether we are away (client_away).
	IsAway *bool
	// IsChannelCommander is whether we speak as channel commander
	// (client_is_channel_commander).
	IsChannelCommander *bool
	// IsRecording is whether we are recording (client_is_recording).
	IsRecording *bool
	// IsRequestingTalk is whether we are requesting to talk
	// (client_talk_request).
	IsRequestingTalk *bool
}

// UpdateClient changes our own client state (nickname, mute, away, …).
func (c *Commands) UpdateClient(ctx context.Context, opts ClientUpdateOptions) error {
	return c.exec(ctx, "clientupdate", []param{
		boolPtrArg("client_input_muted", opts.IsInputMuted),
		boolPtrArg("client_output_muted", opts.IsOutputMuted),
		boolPtrArg("client_away", opts.IsAway),
		strPtrArg("client_away_message", opts.AwayMessage),
		boolPtrArg("client_input_hardware", opts.HasInputHardware),
		boolPtrArg("client_output_hardware", opts.HasOutputHardware),
		boolPtrArg("client_is_channel_commander", opts.IsChannelCommander),
		strPtrArg("client_flag_avatar", opts.Avatar),
		strPtrArg("client_nickname_phonetic", opts.NicknamePhonetic),
		boolPtrArg("client_talk_request", opts.IsRequestingTalk),
		strPtrArg("client_talk_request_msg", opts.TalkRequestMessage),
		boolPtrArg("client_is_recording", opts.IsRecording),
		strPtrArg("client_badges", opts.Badges),
	})
}

// ClientEditOptions change another client's editable attributes. Only the
// fields you set are sent: a pointer to "" clears the description, while nil
// leaves it alone.
type ClientEditOptions struct {
	// Description is the client's description (client_description).
	Description *string
	// IsTalker grants or revokes talk power in a moderated channel
	// (client_is_talker).
	IsTalker *bool
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

// ClientMatch is a client a lookup found, as clientfind and clientgetids
// report one.
type ClientMatch struct {
	// Nickname is the client's nickname (client_nickname).
	Nickname string
	// ID is the client's id (clid).
	ID ClientID
}

// FindClients returns clients whose nickname contains pattern, none when no
// client matches.
func (c *Commands) FindClients(ctx context.Context, pattern string) ([]ClientMatch, error) {
	rows, err := c.list(ctx, "clientfind", []param{strArg("pattern", pattern)})
	// No match is 512, "invalid clientID", measured on TeamSpeak 3 and 6:
	// clientfind takes no clid, so the code can only mean none was found.
	if errors.Is(err, errcode.ClientInvalidID) {
		return nil, nil
	}
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
	LastConnected time.Time
	// UID is the client's identity (client_unique_identifier).
	UID UID
	// Nickname is the client's nickname when last seen (client_nickname).
	Nickname string
	// Description is the client's description (client_description).
	Description string
	// LastIP is the address the client last connected from (client_lastip).
	LastIP string
	// DatabaseID is the client's database id (cldbid).
	DatabaseID ClientDBID
	// TotalConnections is how often the client has connected
	// (client_totalconnections).
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

// ClientDatabasePageOptions select one page of ListClientDatabase.
type ClientDatabasePageOptions struct {
	// Start is the offset of the first record; 0 is the first (start).
	Start int
	// Limit is how many records to read at most; 0 leaves it to the server's
	// default. The server caps it (duration).
	Limit int
}

// ListClientDatabase returns one page of persistent client records. The server
// caps a page, so a short page does not mean the last; IterateClientDatabase
// walks all of it. A Start past the last record is an empty page. A negative
// Start or Limit is refused with ErrInvalidCommand.
func (c *Commands) ListClientDatabase(
	ctx context.Context, opts ClientDatabasePageOptions,
) ([]ClientDatabaseEntry, error) {
	params := make([]param, 0, 2)
	if opts.Start != 0 {
		params = append(params, nonNegativeArg("start", opts.Start))
	}
	if opts.Limit != 0 {
		params = append(params, nonNegativeArg("duration", opts.Limit))
	}

	return c.clientDatabasePage(ctx, params)
}

func (c *Commands) clientDatabasePage(ctx context.Context, params []param) ([]ClientDatabaseEntry, error) {
	rows, err := c.list(ctx, "clientdblist", params)
	if err != nil {
		return nil, err
	}

	out := make([]ClientDatabaseEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseDatabaseEntry(row))
	}

	return out, nil
}

func nonNegativeArg(key string, value int) param {
	if value < 0 {
		return invalidArg(fmt.Sprintf("%s: negative %d", key, value))
	}

	return uintArg(key, uint64(value))
}

// PagingOptions say how a paged command is walked, as by
// IterateClientDatabase.
type PagingOptions struct {
	// PageSize is how many records to ask for per page; 0 means 100. The server
	// may cap a page below it, which the walk allows for. A negative size is
	// yielded as an error wrapping ErrInvalidCommand.
	PageSize int
}

// defaultPageSize is how many records IterateClientDatabase asks for at a time
// when PagingOptions.PageSize is 0.
const defaultPageSize = 100

// IterateClientDatabase walks every persistent client record, fetching them
// from the server a page at a time as the loop asks for more:
//
//	for entry, err := range c.IterateClientDatabase(ctx, teamspeak.PagingOptions{}) {
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
// the walk asks once more to find out. A page that starts at or before the
// last record already seen ends it as well: that is a server ignoring start,
// which would otherwise be asked for its first page forever.
//
// Any other error is yielded once, with a zero entry, and ends the walk.
// Records added or removed during the walk can be skipped or seen twice, since
// each page is a separate query.
func (c *Commands) IterateClientDatabase(
	ctx context.Context, opts PagingOptions,
) iter.Seq2[ClientDatabaseEntry, error] {
	return func(yield func(ClientDatabaseEntry, error) bool) {
		pageSize := cmp.Or(opts.PageSize, defaultPageSize)
		if pageSize < 0 {
			yield(ClientDatabaseEntry{}, fmt.Errorf("%w: a page size is positive, not %d", ErrInvalidCommand, pageSize))

			return
		}

		var start, fullPage int
		var last *ClientDatabaseEntry
		for {
			page, err := c.clientDatabasePage(ctx, []param{
				uintArg("start", uint64(start)),
				uintArg("duration", uint64(pageSize)),
			})
			if err != nil {
				yield(ClientDatabaseEntry{}, err)

				return
			}
			if len(page) == 0 {
				return
			}
			if last != nil && page[0].DatabaseID <= last.DatabaseID {
				return
			}

			for _, entry := range page {
				if !yield(entry, nil) {
					return
				}
			}

			last = &page[len(page)-1]
			if len(page) < fullPage {
				return
			}
			fullPage = max(fullPage, len(page))
			start += len(page)
		}
	}
}

// FindClientDatabase returns the database ids of the records whose nickname
// matches pattern, which may use % as a wildcard. The server answers with ids
// only; GetClientDatabaseInfo reads a record.
func (c *Commands) FindClientDatabase(ctx context.Context, pattern string) ([]ClientDBID, error) {
	rows, err := c.list(ctx, "clientdbfind", []param{strArg("pattern", pattern)})
	if err != nil {
		return nil, err
	}

	out := make([]ClientDBID, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClientDBID(fieldUint(row, "cldbid")))
	}

	return out, nil
}

// GetClientDatabaseInfo returns one persistent client record.
func (c *Commands) GetClientDatabaseInfo(ctx context.Context, clientDBID ClientDBID) (ClientDatabaseEntry, error) {
	row, err := c.queryRow(ctx, "clientdbinfo", "", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return ClientDatabaseEntry{}, err
	}

	// The answer does not repeat the id it was asked about.
	entry := parseDatabaseEntry(row)
	entry.DatabaseID = clientDBID

	return entry, nil
}

// ClientDatabaseEditOptions change a persistent client record. Only the fields
// you set are sent: a pointer to "" clears the description, while nil leaves
// it alone.
type ClientDatabaseEditOptions struct {
	// Description is the client's description (client_description).
	Description *string
}

// EditClientDatabase changes a persistent client record.
func (c *Commands) EditClientDatabase(
	ctx context.Context, clientDBID ClientDBID, opts ClientDatabaseEditOptions,
) error {
	return c.exec(ctx, "clientdbedit", []param{
		idArg("cldbid", clientDBID),
		strPtrArg("client_description", opts.Description),
	})
}

// DeleteClientDatabase removes a client from the database entirely.
func (c *Commands) DeleteClientDatabase(ctx context.Context, clientDBID ClientDBID) error {
	return c.exec(ctx, "clientdbdelete", []param{idArg("cldbid", clientDBID)})
}

// ClientPermissionOptions are AddClientPermission's optional parameters.
type ClientPermissionOptions struct {
	// Skip makes the value override the client's channel and channel group
	// permissions (permskip). It is always sent: the server requires it here,
	// unlike the channel equivalent.
	Skip bool
}

// AddClientPermission sets a permission on a client, server-wide.
func (c *Commands) AddClientPermission(
	ctx context.Context, clientDBID ClientDBID, perm Permission, value int32, opts ClientPermissionOptions,
) error {
	return c.exec(ctx, "clientaddperm", []param{
		idArg("cldbid", clientDBID),
		permArg(perm),
		intArg("permvalue", int64(value)),
		boolArg("permskip", opts.Skip),
	})
}

// DeleteClientPermission removes a permission from a client.
func (c *Commands) DeleteClientPermission(ctx context.Context, clientDBID ClientDBID, perm Permission) error {
	return c.exec(ctx, "clientdelperm", []param{
		idArg("cldbid", clientDBID),
		permArg(perm),
	})
}

// ClientMoveOptions are MoveClient's optional parameters.
type ClientMoveOptions struct {
	// Password is the target channel's password, "" for none. Pass it as the
	// user typed it: the client encodes it as its protocol requires.
	Password string
}

// MoveClient moves a client to another channel.
func (c *Commands) MoveClient(ctx context.Context, clid ClientID, channelID ChannelID, opts ClientMoveOptions) error {
	params := []param{
		idArg("clid", clid),
		idArg("cid", channelID),
	}
	if opts.Password != "" {
		params = append(params, strArg("cpw", opts.Password))
	}

	return c.exec(ctx, "clientmove", params, "cpw")
}

// ---- Client lookups -----------------------------------------------------------
//
// The voice protocol answers these with a notification (notifyclientids and
// the like) rather than data rows; the client pairs it with the command.

// GetClientDBIDByUID returns the persistent database id behind a uid.
func (c *Commands) GetClientDBIDByUID(ctx context.Context, uid UID) (ClientDBID, error) {
	row, err := c.queryRow(ctx, "clientgetdbidfromuid", "cldbid", []param{strArg("cluid", string(uid))})
	if err != nil {
		return 0, err
	}

	return ClientDBID(fieldUint(row, "cldbid")), nil
}

// GetClientIDs returns every client currently using a uid, with its nickname.
func (c *Commands) GetClientIDs(ctx context.Context, uid UID) ([]ClientMatch, error) {
	rows, err := c.list(ctx, "clientgetids", []param{strArg("cluid", string(uid))})
	if err != nil {
		return nil, err
	}

	out := make([]ClientMatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClientMatch{
			ID:       ClientID(fieldUint16(row, "clid")),
			Nickname: fieldStr(row, "name"),
		})
	}

	return out, nil
}

// GetClientUIDByID returns the uid of a connected client.
func (c *Commands) GetClientUIDByID(ctx context.Context, clid ClientID) (UID, error) {
	row, err := c.queryRow(ctx, "clientgetuidfromclid", "cluid", []param{idArg("clid", clid)})
	if err != nil {
		return "", err
	}

	return UID(fieldStr(row, "cluid")), nil
}

// ClientDatabaseName is the database record a lookup by name names.
type ClientDatabaseName struct {
	// Name is the nickname the client last used (name).
	Name string
	// DatabaseID is the client's database id (cldbid).
	DatabaseID ClientDBID
}

// GetClientNameByDBID returns the database id and nickname recorded for a
// database id.
func (c *Commands) GetClientNameByDBID(ctx context.Context, clientDBID ClientDBID) (ClientDatabaseName, error) {
	row, err := c.queryRow(ctx, "clientgetnamefromdbid", "", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return ClientDatabaseName{}, err
	}

	// The answer need not repeat the id it was asked about.
	return ClientDatabaseName{
		DatabaseID: cmp.Or(ClientDBID(fieldUint(row, "cldbid")), clientDBID),
		Name:       fieldStr(row, "name"),
	}, nil
}

// GetClientNameByUID returns the database id and nickname recorded for a uid.
func (c *Commands) GetClientNameByUID(ctx context.Context, uid UID) (ClientDatabaseName, error) {
	row, err := c.queryRow(ctx, "clientgetnamefromuid", "cldbid", []param{strArg("cluid", string(uid))})
	if err != nil {
		return ClientDatabaseName{}, err
	}

	return ClientDatabaseName{
		DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
		Name:       fieldStr(row, "name"),
	}, nil
}

// ListClientPermissions returns the permissions granted to a client from the
// database.
func (c *Commands) ListClientPermissions(ctx context.Context, clientDBID ClientDBID) ([]PermissionEntry, error) {
	rows, err := c.list(ctx, "clientpermlist", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}
