package teamspeak

// ClientInfo is a connected client, as clientlist or notifycliententerview
// reports one.
//
// One type covers both: the two carry the same client, and having separate
// structs made the list and event paths disagree about what a client is —
// including the type of ServerGroups.
type ClientInfo struct {
	Nickname string
	UID      string
	// ServerGroups are the group ids this client holds. Ids rather than names:
	// the server sends ids, and resolving them costs a separate call.
	ServerGroups   []uint64
	ChannelID      uint64
	ChannelGroupID uint64
	// Type is 0 for a normal client, 1 for a ServerQuery client.
	Type        int
	ID          uint16
	IsAway      bool
	IsRecording bool
	IsTalker    bool
}

// FileUploadInfo represents the information received when an upload is initialized.
type FileUploadInfo struct {
	FileTransferKey      string
	SeekPosition         uint64
	ClientFileTransferID uint16
	ServerFileTransferID uint16
	Port                 uint16
}

// FileDownloadInfo represents the information received when a download is initialized.
type FileDownloadInfo struct {
	FileTransferKey      string
	Size                 uint64
	ClientFileTransferID uint16
	ServerFileTransferID uint16
	Port                 uint16
}
