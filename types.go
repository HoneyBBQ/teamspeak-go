package teamspeak

import (
	"fmt"
	"log/slog"
	"time"
)

// Properties are a server's raw properties, by their wire names, unescaped,
// as it sent them: the open-ended answers — serverinfo, clientinfo, hostinfo,
// instanceinfo — whose fields depend on the server's version and the caller's
// permissions, and the settings EditServer and EditInstance pass through. The
// prop package names their keys.
type Properties map[string]string

// ClientEntry is a connected client, as clientlist or notifycliententerview
// reports one.
//
// One type covers both: the two carry the same client, and having separate
// structs made the list and event paths disagree about what a client is —
// including the type of ServerGroups.
type ClientEntry struct {
	// Created is when the client first connected to this server
	// (client_created); the zero time when the answer did not carry it, which
	// ListClients does with ClientListOptions.Times, and when the server sends
	// 0 for never.
	Created time.Time
	// LastConnected is when the client last connected before this session
	// (client_lastconnected); the zero time as Created is.
	LastConnected time.Time
	// Nickname is the client's nickname (client_nickname).
	Nickname string
	// ChannelID is the channel the client is in (cid, or ctid when it entered
	// view).
	ChannelID ChannelID
	// Type is whether the client is a voice client or a ServerQuery connection
	// (client_type). Every list and every enter notification carries it.
	Type ClientType
	// DatabaseID is the client's database id (client_database_id). Every list
	// and every enter notification carries it.
	DatabaseID ClientDBID
	// ID is the client's id for this session (clid); it changes on every
	// connection.
	ID ClientID
	// ServerGroups are the group ids this client holds. Ids rather than names:
	// the server sends ids, and resolving them costs a separate call. It is nil
	// when the answer did not carry the groups, which ListClients does with
	// ClientListOptions.Groups, and an empty list for a client that holds none.
	ServerGroups []ServerGroupID

	// The fields below are nil, or the zero value for IdleTime, where the answer
	// did not carry them, which is not the same as false, 0 or "": a client that
	// is not away and one whose away state was not asked for are different, and
	// a nil flag does not claim the first. A list brings only what its flags
	// ask for (the comment of each says which), and a few properties are in no
	// list at all. A client entered by notifycliententerview carries all of
	// them but Created, LastConnected, IdleTime, Version, Platform and IP, which
	// only a list brings.

	// UID is the client's identity (client_unique_identifier). ListClients
	// brings it unless run with OmitUID.
	UID *UID
	// ChannelGroupID is the client's channel group in its channel
	// (client_channel_group_id). ListClients brings it with
	// ClientListOptions.Groups.
	ChannelGroupID *ChannelGroupID
	// IsAway reports a client marked away (client_away). ListClients brings it
	// with ClientListOptions.Away.
	IsAway *bool
	// IsRecording reports a client that is recording (client_is_recording).
	// ListClients brings it with ClientListOptions.Voice.
	IsRecording *bool
	// IsTalker reports a client granted talk power (client_is_talker).
	// ListClients brings it with ClientListOptions.Voice.
	IsTalker *bool
	// IdleTime is how long since the client last did anything, reported in
	// milliseconds (client_idle_time). ListClients brings it with
	// ClientListOptions.Times.
	IdleTime *time.Duration
	// AwayMessage is the away message (client_away_message); a pointer to ""
	// for none. ListClients brings it with ClientListOptions.Away.
	AwayMessage *string
	// IsInputMuted reports a muted microphone (client_input_muted). ListClients
	// brings it with ClientListOptions.Voice.
	IsInputMuted *bool
	// IsOutputMuted reports muted speakers (client_output_muted). ListClients
	// brings it with ClientListOptions.Voice.
	IsOutputMuted *bool
	// IsOutputOnlyMuted reports speakers muted while the microphone is not
	// (client_outputonly_muted). No list brings it.
	IsOutputOnlyMuted *bool
	// HasInputHardware reports a working microphone (client_input_hardware).
	// ListClients brings it with ClientListOptions.Voice.
	HasInputHardware *bool
	// HasOutputHardware reports working speakers (client_output_hardware).
	// ListClients brings it with ClientListOptions.Voice.
	HasOutputHardware *bool
	// IsChannelCommander reports a client speaking as channel commander
	// (client_is_channel_commander). ListClients brings it with
	// ClientListOptions.Voice.
	IsChannelCommander *bool
	// IsPrioritySpeaker reports a priority speaker (client_is_priority_speaker).
	// ListClients brings it with ClientListOptions.Voice.
	IsPrioritySpeaker *bool
	// TalkPower is the client's talk power (client_talk_power). ListClients
	// brings it with ClientListOptions.Voice.
	TalkPower *int32
	// IsRequestingTalk reports a client asking for talk power
	// (client_talk_request; the server sends the time of the request, any
	// nonzero value is true). No list brings it.
	IsRequestingTalk *bool
	// TalkRequestedAt is when the client asked for talk power, the time
	// client_talk_request carries (whole seconds on both TeamSpeak 3 and 6);
	// the zero time when it is not asking, or when the answer did not carry
	// the field. No list brings it.
	TalkRequestedAt time.Time
	// TalkRequestMessage is the message sent with a talk request
	// (client_talk_request_msg). No list brings it.
	TalkRequestMessage *string
	// Description is the client's description (client_description). No list
	// brings it.
	Description *string
	// MetaData is the client's free-form meta data (client_meta_data). No list
	// brings it.
	MetaData *string
	// Avatar is the MD5 of the client's avatar, a pointer to "" for none
	// (client_flag_avatar). No list brings it.
	Avatar *string
	// IconID is the client's icon (client_icon_id); nil for none as well as for
	// an answer that did not carry it. Only ListClients with
	// ClientListOptions.Icon brings it among the lists.
	IconID *IconID
	// NicknamePhonetic is how the nickname is pronounced
	// (client_nickname_phonetic). No list brings it.
	NicknamePhonetic *string
	// UnreadMessages is how many offline messages the client has unread
	// (client_unread_messages). No list brings it.
	UnreadMessages *int32
	// NeededServerQueryViewPower is the power needed to see this client from a
	// ServerQuery connection (client_needed_serverquery_view_power). No list
	// brings it; the server sends it after every group change.
	NeededServerQueryViewPower *int32
	// ChannelGroupInheritedChannelID is the channel the client's channel group
	// is inherited from (client_channel_group_inherited_channel_id).
	// ListClients brings it with ClientListOptions.Groups.
	ChannelGroupInheritedChannelID *ChannelID
	// Country is the client's country code (client_country); a pointer to ""
	// for a client with none. ListClients brings it with
	// ClientListOptions.Country.
	Country *string
	// Version is the client's version string (client_version). ListClients
	// brings it with ClientListOptions.Info; a client entering view does not
	// carry it.
	Version *string
	// Platform is the client's platform (client_platform). ListClients brings
	// it with ClientListOptions.Info; a client entering view does not carry it.
	Platform *string
	// IP is the client's address (connection_client_ip). ListClients brings it
	// with ClientListOptions.IP; a client entering view does not carry it.
	IP *string
	// Badges are the client's badges (client_badges). ListClients brings them
	// with ClientListOptions.Badges.
	Badges *string
	// SignedBadges are the client's signed badges (client_signed_badges). No
	// list brings them.
	SignedBadges *string
	// MyTeamSpeakID is the client's MyTeamSpeak id (client_myteamspeak_id). No
	// list brings it.
	MyTeamSpeakID *string
	// MyTeamSpeakAvatar is the client's MyTeamSpeak avatar
	// (client_myteamspeak_avatar). No list brings it.
	MyTeamSpeakAvatar *string
	// Integrations are the client's linked integrations (client_integrations).
	// No list brings them.
	Integrations *string
	// UserTag is the client's user tag (client_user_tag); TeamSpeak 6 only, and
	// no list brings it.
	UserTag *string
	// IsStreaming reports a client that is streaming (client_is_streaming);
	// TeamSpeak 6 only, and no list brings it.
	IsStreaming *bool
}

// FileUploadInfo represents the information received when an upload is initialized.
//
// String, GoString and LogValue redact the file transfer key, so the value can reach fmt
// and log/slog safely. encoding/json does not: the file transfer key is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type FileUploadInfo struct {
	// FileTransferKey is the key that authorizes the transfer on the file
	// transfer port (ftkey).
	FileTransferKey string
	// Size is the file's whole size in bytes, as the negotiation declared it.
	Size uint64
	// SeekPosition is where the upload continues from, in bytes: 0 for a new
	// file, and with Resume the size of the partial file the server holds
	// (seekpos). The data to send is the file from here on.
	SeekPosition uint64
	// ClientFileTransferID is the id the client chose for the transfer
	// (clientftfid).
	ClientFileTransferID ClientFileTransferID
	// ServerFileTransferID is the id the server assigned (serverftfid).
	ServerFileTransferID ServerFileTransferID
	// Port is the file transfer port to connect to (port), on the host the
	// connection to the server uses.
	Port uint16
}

// FileDownloadInfo represents the information received when a download is initialized.
//
// String, GoString and LogValue redact the file transfer key, so the value can reach fmt
// and log/slog safely. encoding/json does not: the file transfer key is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type FileDownloadInfo struct {
	// FileTransferKey is the key that authorizes the transfer on the file
	// transfer port (ftkey).
	FileTransferKey string
	// Size is the file's whole size in bytes (size), whatever SeekPosition is.
	Size uint64
	// SeekPosition is where the download starts from, in bytes, as it was
	// asked for: the server sends the file from here to its end, Size less
	// this many bytes.
	SeekPosition uint64
	// ClientFileTransferID is the id the client chose for the transfer
	// (clientftfid).
	ClientFileTransferID ClientFileTransferID
	// ServerFileTransferID is the id the server assigned (serverftfid).
	ServerFileTransferID ServerFileTransferID
	// Port is the file transfer port to connect to (port), on the host the
	// connection to the server uses.
	Port uint16
}

// String describes the negotiation without its key, which is what lets anyone
// holding it transfer the file.
func (i FileUploadInfo) String() string {
	return fmt.Sprintf(
		"{Port:%d Size:%d SeekPosition:%d ClientFileTransferID:%d ServerFileTransferID:%d FileTransferKey:redacted}",
		i.Port, i.Size, i.SeekPosition, i.ClientFileTransferID, i.ServerFileTransferID)
}

// GoString is String, so %#v redacts too.
func (i FileUploadInfo) GoString() string { return i.String() }

// LogValue describes the negotiation to log/slog without its key.
func (i FileUploadInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("port", uint64(i.Port)),
		slog.Uint64("size", i.Size),
		slog.Uint64("seek_position", i.SeekPosition),
		slog.Uint64("client_file_transfer_id", uint64(i.ClientFileTransferID)),
		slog.Uint64("server_file_transfer_id", uint64(i.ServerFileTransferID)),
		slog.String("file_transfer_key", "redacted"),
	)
}

// String describes the negotiation without its key, which is what lets anyone
// holding it transfer the file.
func (i FileDownloadInfo) String() string {
	return fmt.Sprintf(
		"{Port:%d Size:%d SeekPosition:%d ClientFileTransferID:%d ServerFileTransferID:%d FileTransferKey:redacted}",
		i.Port, i.Size, i.SeekPosition, i.ClientFileTransferID, i.ServerFileTransferID)
}

// GoString is String, so %#v redacts too.
func (i FileDownloadInfo) GoString() string { return i.String() }

// LogValue describes the negotiation to log/slog without its key.
func (i FileDownloadInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("port", uint64(i.Port)),
		slog.Uint64("size", i.Size),
		slog.Uint64("seek_position", i.SeekPosition),
		slog.Uint64("client_file_transfer_id", uint64(i.ClientFileTransferID)),
		slog.Uint64("server_file_transfer_id", uint64(i.ServerFileTransferID)),
		slog.String("file_transfer_key", "redacted"),
	)
}
