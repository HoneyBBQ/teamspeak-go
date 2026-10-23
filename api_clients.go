package teamspeak

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
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
		ID:            ClientID(fieldUint16(row, "clid")),
		Nickname:      fieldStr(row, "client_nickname"),
		ChannelID:     ChannelID(fieldUint(row, "cid")),
		Type:          ClientType(fieldEnum(row, "client_type")),
		DatabaseID:    ClientDBID(fieldUint(row, "client_database_id")),
		ServerGroups:  fieldOptIDList[ServerGroupID](row, "client_servergroups"),
		Created:       fieldTime(row, "client_created"),
		LastConnected: fieldTime(row, "client_lastconnected"),

		UID:                            fieldOptStr[UID](row, "client_unique_identifier"),
		ChannelGroupID:                 fieldOptID[ChannelGroupID](row, "client_channel_group_id"),
		IsAway:                         fieldOptBool(row, "client_away"),
		IsRecording:                    fieldOptBool(row, "client_is_recording"),
		IsTalker:                       fieldOptBool(row, "client_is_talker"),
		IdleTime:                       fieldOptDuration(row, "client_idle_time", time.Millisecond),
		AwayMessage:                    fieldOptStr[string](row, "client_away_message"),
		IsInputMuted:                   fieldOptBool(row, "client_input_muted"),
		IsOutputMuted:                  fieldOptBool(row, "client_output_muted"),
		IsOutputOnlyMuted:              fieldOptBool(row, "client_outputonly_muted"),
		HasInputHardware:               fieldOptBool(row, "client_input_hardware"),
		HasOutputHardware:              fieldOptBool(row, "client_output_hardware"),
		IsChannelCommander:             fieldOptBool(row, "client_is_channel_commander"),
		IsPrioritySpeaker:              fieldOptBool(row, "client_is_priority_speaker"),
		TalkPower:                      fieldOptInt32(row, "client_talk_power"),
		IsRequestingTalk:               fieldOptBool(row, "client_talk_request"),
		TalkRequestedAt:                fieldTime(row, "client_talk_request"),
		TalkRequestMessage:             fieldOptStr[string](row, "client_talk_request_msg"),
		Description:                    fieldOptStr[string](row, "client_description"),
		MetaData:                       fieldOptStr[string](row, "client_meta_data"),
		Avatar:                         fieldOptStr[string](row, "client_flag_avatar"),
		IconID:                         fieldOptIconID(row, "client_icon_id"),
		NicknamePhonetic:               fieldOptStr[string](row, "client_nickname_phonetic"),
		UnreadMessages:                 fieldOptInt32(row, "client_unread_messages"),
		NeededServerQueryViewPower:     fieldOptInt32(row, "client_needed_serverquery_view_power"),
		ChannelGroupInheritedChannelID: fieldOptID[ChannelID](row, "client_channel_group_inherited_channel_id"),
		Country:                        fieldOptStr[string](row, "client_country"),
		Version:                        fieldOptStr[string](row, "client_version"),
		Platform:                       fieldOptStr[string](row, "client_platform"),
		IP:                             fieldOptStr[string](row, "connection_client_ip"),
		Badges:                         fieldOptStr[string](row, "client_badges"),
		SignedBadges:                   fieldOptStr[string](row, "client_signed_badges"),
		MyTeamSpeakID:                  fieldOptStr[string](row, "client_myteamspeak_id"),
		MyTeamSpeakAvatar:              fieldOptStr[string](row, "client_myteamspeak_avatar"),
		Integrations:                   fieldOptStr[string](row, "client_integrations"),
		UserTag:                        fieldOptStr[string](row, "client_user_tag"),
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
	// Icon adds each client's icon id (-icon), as ClientEntry.IconID.
	Icon bool
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
	params := make([]param, 0, 10)
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
		{"-icon", options.Icon},
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

// KickClientsOptions are KickClients' optional parameters.
type KickClientsOptions struct {
	// ReasonMessage is shown to the clients; "" sends none.
	ReasonMessage string
	// ContinueOnError sends -continueonerror, so a client that cannot be
	// kicked does not stop the ones after it. See KickClients for what the
	// server then answers.
	ContinueOnError bool
}

// KickClients kicks several clients in one command (clientkick, one clid row
// each), from their channel (ReasonKickChannel) or from the server
// (ReasonKickServer); any other reason is refused with ErrInvalidCommand.
// Kicking none sends nothing.
//
// The server answers one status for the whole command and never one per
// client, so the result is an error and nothing more. Measured on TeamSpeak 3
// 3.13.8 and 6 beta13.1, over raw ServerQuery, SSH, WebQuery and the voice
// protocol alike: without ContinueOnError the server kicks in order and stops at
// the first id it cannot kick (unknown, or already gone), answering that
// error, 512 for an unknown id: the clients before it were kicked and the ones
// after it were not. With ContinueOnError it goes on past such an id and
// answers success, even when no id could be kicked, so a failure is not
// reported at all: list the clients to see who is left. An error in what the
// ids share, the reason, still fails the command.
func (c *Commands) KickClients(
	ctx context.Context, clids []ClientID, reason Reason, opts KickClientsOptions,
) error {
	if len(clids) == 0 {
		return nil
	}

	reasonParam := intArg("reasonid", int64(reason))
	if reason != ReasonKickChannel && reason != ReasonKickServer {
		reasonParam = invalidArg("a kick's reason is ReasonKickChannel or ReasonKickServer, not " + reason.String())
	}

	return c.exec(ctx, "clientkick", []param{
		continueOnErrorArg(opts.ContinueOnError),
		reasonParam,
		optStrArg("reasonmsg", opts.ReasonMessage),
		idRowsArg("clid", clids),
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
	// MetaData is opaque data other clients see in their record of us
	// (client_meta_data); a pointer to "" clears it.
	MetaData *string
}

// UpdateClient changes our own client state (nickname, mute, away, …).
func (c *Commands) UpdateClient(ctx context.Context, opts ClientUpdateOptions) error {
	return c.exec(ctx, "clientupdate", []param{
		strPtrArg("client_nickname", opts.Nickname),
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
		strPtrArg("client_meta_data", opts.MetaData),
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

// PluginCommandTarget is who receives a plugin command. The zero value is the
// sender's channel. Build the others with PluginToServer and PluginToClient.
type PluginCommandTarget struct {
	clientID ClientID
	mode     pluginTargetMode
}

type pluginTargetMode uint8

// The targetmode values of plugincmd. The server has a fourth, 3, which was seen
// to reach the same clients as the whole server, so it is not offered.
const (
	pluginTargetChannel pluginTargetMode = 0
	pluginTargetServer  pluginTargetMode = 1
	pluginTargetClient  pluginTargetMode = 2
)

// PluginToChannel addresses the clients in the sender's channel, the sender
// included. A client in another channel gets nothing, subscribed to this one or
// not. It is the zero value of PluginCommandTarget.
func PluginToChannel() PluginCommandTarget {
	return PluginCommandTarget{mode: pluginTargetChannel}
}

// PluginToServer addresses every client on the server, the sender included.
func PluginToServer() PluginCommandTarget {
	return PluginCommandTarget{mode: pluginTargetServer}
}

// PluginToClient addresses one client. The sender receives the command only when
// it names itself. An id no client has is refused with
// errcode.ClientInvalidID.
func PluginToClient(clid ClientID) PluginCommandTarget {
	return PluginCommandTarget{mode: pluginTargetClient, clientID: clid}
}

// SendPluginCommand sends a plugin command: a named payload that other clients'
// plugins agree on and the server relays without reading. A voice client
// receives it as a PluginCommandEvent, the sender too when target is its channel
// or the server. data may be empty, and is delivered empty.
//
// Only a voice connection can send one: a ServerQuery connection is refused with
// 516, invalid client type.
func (c *Commands) SendPluginCommand(ctx context.Context, name, data string, target PluginCommandTarget) error {
	params := []param{
		strArg("name", name),
		strArg("data", data),
		uintArg("targetmode", uint64(target.mode)),
	}
	if target.mode == pluginTargetClient {
		params = append(params, idArg("target", target.clientID))
	}

	return c.exec(ctx, "plugincmd", params)
}

// SendChatComposing tells a client that we are typing a private message to it,
// which it receives as a ClientChatComposingEvent. Only that client is told,
// whatever channel it is in; naming ourselves tells ourselves. An id no client
// has is refused with errcode.ClientInvalidID. Only a voice connection can send
// it: the server answers a ServerQuery connection with 256, command not found.
func (c *Commands) SendChatComposing(ctx context.Context, clid ClientID) error {
	return c.exec(ctx, "clientchatcomposing", []param{idArg("clid", clid)})
}

// ClosePrivateChat tells a client that we closed our private chat with it. It
// only does something after we have sent that client a private message: for any
// other the server accepts the command and sends nothing, and raises no error.
// The client receives it as a ClientChatClosedEvent. Only a voice connection
// can send it.
func (c *Commands) ClosePrivateChat(ctx context.Context, clid ClientID) error {
	return c.exec(ctx, "clientchatclosed", []param{idArg("clid", clid)})
}

// ClientMatch is a client a lookup found, as clientfind and clientgetids
// report one.
type ClientMatch struct {
	// Nickname is the client's nickname (client_nickname).
	Nickname string
	// ChannelUID is the unique identifier of the channel the client is in
	// (chuid). Only FindClientsWith with ClientFindOptions.ChannelUID sets it,
	// and only TeamSpeak 6 sends it.
	ChannelUID ChannelUID
	// ChannelID is the channel the client is in (cid). Only FindClientsWith
	// with ClientFindOptions.ChannelID sets it, and only TeamSpeak 6 sends it.
	ChannelID ChannelID
	// ID is the client's id (clid).
	ID ClientID
}

// FindClients returns clients whose nickname contains pattern, none when no
// client matches.
//
// The match is a case-insensitive substring, not a regular expression:
// "vHol.*" finds nobody. FindClientsWith adds what the answer reports of each
// client's channel.
func (c *Commands) FindClients(ctx context.Context, pattern string) ([]ClientMatch, error) {
	return c.FindClientsWith(ctx, pattern, ClientFindOptions{})
}

// ClientFindOptions are FindClientsWith's optional parameters: which channel
// details the answer reports for each client.
type ClientFindOptions struct {
	// ChannelID reports the channel each client is in (-cid), as
	// ClientMatch.ChannelID.
	ChannelID bool
	// ChannelUID reports the unique identifier of that channel (-chuid), as
	// ClientMatch.ChannelUID.
	ChannelUID bool
}

// FindClientsWith is FindClients with the channel details opts asks for. It
// sends clientfind with -cid and -chuid.
//
// Only TeamSpeak 6 answers them: TeamSpeak 3 accepts the flags and leaves the
// channel out, so the fields stay zero there.
func (c *Commands) FindClientsWith(
	ctx context.Context, pattern string, opts ClientFindOptions,
) ([]ClientMatch, error) {
	rows, err := c.list(ctx, "clientfind", []param{
		boolArg("-cid", opts.ChannelID),
		boolArg("-chuid", opts.ChannelUID),
		strArg("pattern", pattern),
	})
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
			ID:         ClientID(fieldUint16(row, "clid")),
			Nickname:   fieldStr(row, "client_nickname"),
			ChannelID:  ChannelID(fieldUint(row, "cid")),
			ChannelUID: ChannelUID(fieldStr(row, "chuid")),
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
	// LoginName is the client's ServerQuery account name (client_login_name),
	// empty for a client with none. Only clientdblist carries it, so
	// GetClientDatabaseInfo leaves it empty.
	LoginName string
	// AvatarHash is the hash of the client's avatar (client_flag_avatar), empty
	// for a client with none. Only clientdbinfo carries it, so
	// ListClientDatabase leaves it empty.
	AvatarHash string
	// TotalBytesUploaded is the bytes the client has uploaded in all
	// (client_total_bytes_uploaded). Only clientdbinfo carries the four byte
	// counts, so ListClientDatabase leaves them nil.
	TotalBytesUploaded *uint64
	// TotalBytesDownloaded is the bytes the client has downloaded in all
	// (client_total_bytes_downloaded).
	TotalBytesDownloaded *uint64
	// MonthBytesUploaded is the bytes the client uploaded this month
	// (client_month_bytes_uploaded).
	MonthBytesUploaded *uint64
	// MonthBytesDownloaded is the bytes the client downloaded this month
	// (client_month_bytes_downloaded).
	MonthBytesDownloaded *uint64
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
		LoginName:        fieldStr(row, "client_login_name"),

		AvatarHash:           fieldStr(row, "client_flag_avatar"),
		TotalBytesUploaded:   fieldOptUint64(row, "client_total_bytes_uploaded"),
		TotalBytesDownloaded: fieldOptUint64(row, "client_total_bytes_downloaded"),
		MonthBytesUploaded:   fieldOptUint64(row, "client_month_bytes_uploaded"),
		MonthBytesDownloaded: fieldOptUint64(row, "client_month_bytes_downloaded"),
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

// FindClientDatabaseByUID returns the database ids of the records whose unique
// identifier matches pattern (clientdbfind -uid). No match is an empty slice.
//
// On TeamSpeak 3 and 6 alike the match is SQL LIKE over the whole identifier,
// ignoring case: without a wildcard pattern must be the entire uid, % stands
// for any run of characters and _ for any one, so a prefix needs a trailing %.
// A server answers at most 50 ids for one pattern. The server answers with ids
// only; GetClientDatabaseInfo reads a record.
func (c *Commands) FindClientDatabaseByUID(ctx context.Context, pattern string) ([]ClientDBID, error) {
	rows, err := c.list(ctx, "clientdbfind", []param{strArg("pattern", pattern), boolArg("-uid", true)})
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

// ConnectionTraffic is one direction of one class of a client's traffic, as
// the client itself reported it. Bandwidth is in bytes per second.
type ConnectionTraffic struct {
	// Packets is the count of packets (connection_packets_<direction>_<class>).
	Packets uint64
	// Bytes is the count of bytes (connection_bytes_<direction>_<class>).
	Bytes uint64
	// BandwidthLastSecond is the bandwidth over the last second
	// (connection_bandwidth_<direction>_last_second_<class>).
	BandwidthLastSecond uint64
	// BandwidthLastMinute is the bandwidth over the last minute
	// (connection_bandwidth_<direction>_last_minute_<class>).
	BandwidthLastMinute uint64
}

// ConnectionTrafficByClass is the traffic of one direction in the three
// classes TeamSpeak counts: speech (voice and whispers), keepalive (ping and
// pong) and control (commands, acknowledgements and the handshake).
type ConnectionTrafficByClass struct {
	// Speech is voice and whisper traffic.
	Speech ConnectionTraffic
	// Keepalive is ping and pong traffic.
	Keepalive ConnectionTraffic
	// Control is everything else.
	Control ConnectionTraffic
}

// PacketLoss is the share of packets lost, 0 to 1, per class and in total.
type PacketLoss struct {
	// Speech is the loss of voice packets.
	Speech float32
	// Keepalive is the loss of ping and pong packets.
	Keepalive float32
	// Control is the loss of command and acknowledgement packets.
	Control float32
	// Total is the loss over all packets.
	Total float32
}

// ClientConnectionInfo is one client's connection statistics, as
// getconnectioninfo reports them. Most figures are what the client itself
// reported with setconnectioninfo; a client that has not reported yet shows
// zeros. ConnectedTime, IdleTime and ClientToServerLoss come from the server,
// which ignores a client's own report of the loss.
type ClientConnectionInfo struct {
	// IP is the client's address (connection_client_ip); empty when the server
	// does not send it.
	IP string
	// Sent is what the client sent.
	Sent ConnectionTrafficByClass
	// Received is what the client received.
	Received ConnectionTrafficByClass
	// ServerToClientLoss is the loss on the way from the server to the client
	// (connection_server2client_packetloss_<class>).
	ServerToClientLoss PacketLoss
	// ClientToServerLoss is the loss on the way from the client to the server
	// (connection_client2server_packetloss_<class>).
	ClientToServerLoss PacketLoss
	// Ping is the round-trip time (connection_ping, in milliseconds).
	Ping time.Duration
	// PingDeviation is the deviation of the round-trip time
	// (connection_ping_deviation, in milliseconds).
	PingDeviation time.Duration
	// ConnectedTime is how long the client has been connected
	// (connection_connected_time, in milliseconds).
	ConnectedTime time.Duration
	// IdleTime is how long the client has been idle (connection_idle_time, in
	// milliseconds).
	IdleTime time.Duration
	// FileTransferBandwidthSent is the file transfer bandwidth out, in bytes
	// per second (connection_filetransfer_bandwidth_sent).
	FileTransferBandwidthSent uint64
	// FileTransferBandwidthReceived is the file transfer bandwidth in
	// (connection_filetransfer_bandwidth_received).
	FileTransferBandwidthReceived uint64
	// ID is the client the figures are about (clid).
	ID ClientID
	// Port is the client's port (connection_client_port); 0 when the server
	// does not send it.
	Port uint16
}

func parseConnectionTraffic(row map[string]string, direction string) ConnectionTrafficByClass {
	one := func(class string) ConnectionTraffic {
		return ConnectionTraffic{
			Packets:             fieldUint(row, "connection_packets_"+direction+"_"+class),
			Bytes:               fieldUint(row, "connection_bytes_"+direction+"_"+class),
			BandwidthLastSecond: fieldUint(row, "connection_bandwidth_"+direction+"_last_second_"+class),
			BandwidthLastMinute: fieldUint(row, "connection_bandwidth_"+direction+"_last_minute_"+class),
		}
	}

	return ConnectionTrafficByClass{Speech: one("speech"), Keepalive: one("keepalive"), Control: one("control")}
}

func parsePacketLoss(row map[string]string, way string) PacketLoss {
	return PacketLoss{
		Speech:    fieldFloat32(row, "connection_"+way+"_packetloss_speech"),
		Keepalive: fieldFloat32(row, "connection_"+way+"_packetloss_keepalive"),
		Control:   fieldFloat32(row, "connection_"+way+"_packetloss_control"),
		Total:     fieldFloat32(row, "connection_"+way+"_packetloss_total"),
	}
}

// GetClientConnectionInfo returns another client's connection statistics
// (getconnectioninfo). The server answers with what it holds and asks that
// client to report its figures meanwhile, so a client that never reported
// shows zeros. It is not GetConnectionInfo, which is about the virtual server.
func (c *Commands) GetClientConnectionInfo(ctx context.Context, clid ClientID) (ClientConnectionInfo, error) {
	row, err := c.queryRow(ctx, "getconnectioninfo", "", []param{idArg("clid", clid)})
	if err != nil {
		return ClientConnectionInfo{}, err
	}

	return ClientConnectionInfo{
		ID:                            ClientID(fieldUint16(row, "clid")),
		Ping:                          fieldMillis(row, "connection_ping"),
		PingDeviation:                 fieldMillis(row, "connection_ping_deviation"),
		ConnectedTime:                 fieldDuration(row, "connection_connected_time", time.Millisecond),
		IdleTime:                      fieldDuration(row, "connection_idle_time", time.Millisecond),
		IP:                            fieldStr(row, "connection_client_ip"),
		Port:                          fieldUint16(row, "connection_client_port"),
		Sent:                          parseConnectionTraffic(row, "sent"),
		Received:                      parseConnectionTraffic(row, "received"),
		ServerToClientLoss:            parsePacketLoss(row, "server2client"),
		ClientToServerLoss:            parsePacketLoss(row, "client2server"),
		FileTransferBandwidthSent:     fieldUint(row, "connection_filetransfer_bandwidth_sent"),
		FileTransferBandwidthReceived: fieldUint(row, "connection_filetransfer_bandwidth_received"),
	}, nil
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

// MoveClientsOptions are MoveClients' optional parameters.
type MoveClientsOptions struct {
	// Password is the target channel's password, "" for none. Pass it as the
	// user typed it: the client encodes it as its protocol requires.
	Password string
	// ContinueOnError sends -continueonerror, so a client that cannot be moved
	// is left out and the others are moved. See MoveClients.
	ContinueOnError bool
}

// MoveClients moves several clients to one channel in one command
// (clientmove, one clid row each). Moving none sends nothing.
//
// The server answers one status for the whole command, so the result is an
// error and nothing more. Measured on TeamSpeak 3 3.13.8 and 6 beta13.1, over
// raw ServerQuery, SSH, WebQuery and the voice protocol alike: the server
// checks every row first, so without ContinueOnError an unknown id (512) or a
// client already in the channel (770) refuses the whole command and nobody is
// moved. With ContinueOnError the rows that fail are left out, the others are
// moved, and the answer is success even when every row failed, so a failure is
// not reported: look at where the clients are. An unknown channel is refused
// (768) either way.
func (c *Commands) MoveClients(
	ctx context.Context, clids []ClientID, channelID ChannelID, opts MoveClientsOptions,
) error {
	if len(clids) == 0 {
		return nil
	}
	params := []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cid", channelID),
	}
	if opts.Password != "" {
		params = append(params, strArg("cpw", opts.Password))
	}
	params = append(params, idRowsArg("clid", clids))

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
	info, err := c.GetClientUIDInfoByID(ctx, clid)
	if err != nil {
		return "", err
	}

	return info.UID, nil
}

// ClientUIDInfo is what clientgetuidfromclid says about a connected client.
type ClientUIDInfo struct {
	// UID is the client's identity (cluid).
	UID UID
	// Nickname is the client's nickname (nickname).
	Nickname string
	// MyTSID is the client's MyTeamSpeak id (mytsid); empty for a client with
	// none, which is what both TeamSpeak 3.13.8 and 6.0.0-beta13.1 sent for an
	// anonymous client.
	MyTSID string
	// ClientID is the client id asked about (clid).
	ClientID ClientID
}

// GetClientUIDInfoByID returns the uid, nickname and MyTeamSpeak id of a
// connected client. GetClientUIDByID is the same command, keeping the uid
// only.
func (c *Commands) GetClientUIDInfoByID(ctx context.Context, clid ClientID) (ClientUIDInfo, error) {
	row, err := c.queryRow(ctx, "clientgetuidfromclid", "cluid", []param{idArg("clid", clid)})
	if err != nil {
		return ClientUIDInfo{}, err
	}

	return ClientUIDInfo{
		ClientID: cmp.Or(ClientID(fieldUint16(row, "clid")), clid),
		UID:      UID(fieldStr(row, "cluid")),
		Nickname: fieldStr(row, "nickname"),
		MyTSID:   fieldStr(row, "mytsid"),
	}, nil
}

// ClientDatabaseName is the database record a lookup by name names.
type ClientDatabaseName struct {
	// Name is the nickname the client last used (name).
	Name string
	// UID is the client's identity (cluid). GetClientNameByDBID is the lookup
	// from a database id to a uid; GetClientNameByUID, which was asked the uid,
	// leaves it empty.
	UID UID
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
		UID:        UID(fieldStr(row, "cluid")),
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

// ---- Custom properties ------------------------------------------------------

// CustomProperty is one custom property of a client: a key and a value the
// server keeps in the client's database record and otherwise ignores. Both can
// be any text, empty included.
type CustomProperty struct {
	// Ident is the property's key (ident).
	Ident string
	// Value is the property's value (value).
	Value string
}

// CustomPropertyMatch is a custom property CustomProperty search found, with
// the client it belongs to.
type CustomPropertyMatch struct {
	// Ident is the property's key (ident).
	Ident string
	// Value is the property's value (value).
	Value string
	// DatabaseID is the client the property belongs to (cldbid).
	DatabaseID ClientDBID
}

// SetCustomProperty creates or updates a custom property of a client. It sends
// customset.
//
// Needs b_client_modify_dbproperties. The server does not check that the
// client exists: a property set on an id nobody holds is kept, and
// ListCustomProperties finds it. Both TeamSpeak 3 and 6 serve it, over
// ServerQuery and the voice protocol.
func (c *Commands) SetCustomProperty(ctx context.Context, clientDBID ClientDBID, ident, value string) error {
	return c.exec(ctx, "customset", []param{
		idArg("cldbid", clientDBID),
		strArg("ident", ident),
		strArg("value", value),
	})
}

// DeleteCustomProperty removes a custom property of a client. It sends
// customdelete.
//
// Needs b_client_delete_dbproperties. A property the client does not have is
// not an error. Served as SetCustomProperty is.
func (c *Commands) DeleteCustomProperty(ctx context.Context, clientDBID ClientDBID, ident string) error {
	return c.exec(ctx, "customdelete", []param{
		idArg("cldbid", clientDBID),
		strArg("ident", ident),
	})
}

// ListCustomProperties returns a client's custom properties, none when it has
// none. It sends custominfo. A ServerQuery admin needs no permission for it; a
// guest voice client is refused with 2568 on TeamSpeak 3 and 6, whichever right
// that is.
//
// A client with no property is answered with an error, not an empty list:
// 512, "invalid clientID", over ServerQuery and, on TeamSpeak 3, the voice
// protocol, and 1281 on TeamSpeak 6's voice protocol. The server answers a
// client it does not know the same way, so both read as no properties here.
func (c *Commands) ListCustomProperties(ctx context.Context, clientDBID ClientDBID) ([]CustomProperty, error) {
	rows, err := c.list(ctx, "custominfo", []param{idArg("cldbid", clientDBID)})
	if errors.Is(err, errcode.ClientInvalidID) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]CustomProperty, 0, len(rows))
	for _, row := range rows {
		out = append(out, CustomProperty{Ident: fieldStr(row, "ident"), Value: fieldStr(row, "value")})
	}

	return out, nil
}

// FindCustomProperty returns the custom properties with the key ident whose
// value matches pattern, which may use the SQL wildcard %, none when none do.
// It sends customsearch. Refused to a guest voice client with 2568 as
// ListCustomProperties is; served as SetCustomProperty is.
//
// The match is against the whole value, ignoring case: "john doe" finds
// "John Doe", "John" does not, and "John%" does.
func (c *Commands) FindCustomProperty(ctx context.Context, ident, pattern string) ([]CustomPropertyMatch, error) {
	rows, err := c.list(ctx, "customsearch", []param{
		strArg("ident", ident),
		strArg("pattern", pattern),
	})
	if err != nil {
		return nil, err
	}

	out := make([]CustomPropertyMatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, CustomPropertyMatch{
			DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
			Ident:      fieldStr(row, "ident"),
			Value:      fieldStr(row, "value"),
		})
	}

	return out, nil
}

// ---- Custom sets ------------------------------------------------------------

// customSetValue encodes custom properties as the one value a privilege key's
// custom set is: "ident=a value=b|ident=c value=d", the pipe separating the
// properties.
//
// Each ident and value is escaped inside the set, and the set is escaped again
// as the parameter it travels in. A value is read by splitting on spaces, so
// the escape inside is what keeps a space in it: sent with only the
// parameter's own escape, "d e" reaches the client that redeems the key as "d"
// — measured on both servers. The pipe that separates properties needs it the
// same way.
func customSetValue(props []CustomProperty) string {
	parts := make([]string, 0, len(props))
	for _, prop := range props {
		parts = append(parts, "ident="+wire.Escape(prop.Ident)+" value="+wire.Escape(prop.Value))
	}

	return strings.Join(parts, "|")
}

// parseCustomSet reads a custom set as customSetValue writes it, undoing the
// escape inside it. A set written without that escape reads back as it was
// written, a value that holds a space included.
func parseCustomSet(raw string) []CustomProperty {
	if raw == "" {
		return nil
	}

	var out []CustomProperty
	for piece := range strings.SplitSeq(raw, "|") {
		rest, isIdent := strings.CutPrefix(piece, "ident=")
		ident, value, hasValue := strings.Cut(rest, " value=")
		if isIdent && hasValue {
			out = append(out, CustomProperty{Ident: wire.Unescape(ident), Value: wire.Unescape(value)})
		}
	}

	return out
}
