package teamspeak

import (
	"fmt"
	"log/slog"
	"time"
)

// Properties are a server's raw properties, by their wire names, unescaped,
// as it sent them: the open-ended answers — serverinfo, clientinfo, hostinfo,
// instanceinfo — whose fields depend on the server's version and the caller's
// permissions, and the settings EditServer and EditInstance pass through.
type Properties map[string]string

// ClientInfo is a connected client, as clientlist or notifycliententerview
// reports one.
//
// One type covers both: the two carry the same client, and having separate
// structs made the list and event paths disagree about what a client is —
// including the type of ServerGroups.
type ClientInfo struct {
	// Created, LastConnected and IdleTime are reported only by ListClients
	// with ClientListOptions.Times; otherwise they are zero.
	//
	// Created is when the client first connected to this server, and
	// LastConnected when it last did before this session.
	Created       time.Time
	LastConnected time.Time
	// IdleTime is how long since the client last did anything, reported in
	// milliseconds (client_idle_time).
	IdleTime time.Duration
	Nickname string
	UID      UID
	// ServerGroups are the group ids this client holds. Ids rather than names:
	// the server sends ids, and resolving them costs a separate call.
	ServerGroups   []ServerGroupID
	ChannelID      ChannelID
	ChannelGroupID ChannelGroupID
	Type           ClientType
	ID             ClientID
	IsAway         bool
	IsRecording    bool
	IsTalker       bool
}

// FileUploadInfo represents the information received when an upload is initialized.
//
// String, GoString and LogValue redact the file transfer key, so the value can reach fmt
// and log/slog safely. encoding/json does not: the file transfer key is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type FileUploadInfo struct {
	FileTransferKey      string
	SeekPosition         uint64
	ClientFileTransferID ClientFileTransferID
	ServerFileTransferID ServerFileTransferID
	Port                 uint16
}

// FileDownloadInfo represents the information received when a download is initialized.
//
// String, GoString and LogValue redact the file transfer key, so the value can reach fmt
// and log/slog safely. encoding/json does not: the file transfer key is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type FileDownloadInfo struct {
	FileTransferKey      string
	Size                 uint64
	ClientFileTransferID ClientFileTransferID
	ServerFileTransferID ServerFileTransferID
	Port                 uint16
}

// String describes the negotiation without its key, which is what lets anyone
// holding it transfer the file.
func (i FileUploadInfo) String() string {
	return fmt.Sprintf(
		"{Port:%d SeekPosition:%d ClientFileTransferID:%d ServerFileTransferID:%d FileTransferKey:redacted}",
		i.Port, i.SeekPosition, i.ClientFileTransferID, i.ServerFileTransferID)
}

// GoString is String, so %#v redacts too.
func (i FileUploadInfo) GoString() string { return i.String() }

// LogValue describes the negotiation to log/slog without its key.
func (i FileUploadInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("port", uint64(i.Port)),
		slog.Uint64("seek_position", i.SeekPosition),
		slog.Uint64("client_file_transfer_id", uint64(i.ClientFileTransferID)),
		slog.Uint64("server_file_transfer_id", uint64(i.ServerFileTransferID)),
		slog.String("file_transfer_key", "redacted"),
	)
}

// String describes the negotiation without its key, which is what lets anyone
// holding it transfer the file.
func (i FileDownloadInfo) String() string {
	return fmt.Sprintf("{Port:%d Size:%d ClientFileTransferID:%d ServerFileTransferID:%d FileTransferKey:redacted}",
		i.Port, i.Size, i.ClientFileTransferID, i.ServerFileTransferID)
}

// GoString is String, so %#v redacts too.
func (i FileDownloadInfo) GoString() string { return i.String() }

// LogValue describes the negotiation to log/slog without its key.
func (i FileDownloadInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("port", uint64(i.Port)),
		slog.Uint64("size", i.Size),
		slog.Uint64("client_file_transfer_id", uint64(i.ClientFileTransferID)),
		slog.Uint64("server_file_transfer_id", uint64(i.ServerFileTransferID)),
		slog.String("file_transfer_key", "redacted"),
	)
}
