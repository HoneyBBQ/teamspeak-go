package teamspeak

// TextMessage is an incoming notifytextmessage payload.
type TextMessage struct {
	InvokerName   string
	InvokerUID    string
	Message       string
	InvokerGroups []uint64
	TargetMode    int
	TargetID      uint64
	InvokerID     uint16
}

// ClientMovedEvent is emitted when a client changes channel (notifyclientmoved).
type ClientMovedEvent struct {
	InvokerName     string
	InvokerUID      string
	TargetChannelID uint64
	ReasonID        int
	ID              uint16
	InvokerID       uint16
}

// PokeEvent is emitted when this client is poked (notifyclientpoke).
type PokeEvent struct {
	InvokerName string
	InvokerUID  string
	Message     string
	InvokerID   uint16
}

// ClientLeftViewEvent is emitted when a client leaves view (notifyclientleftview).
type ClientLeftViewEvent struct {
	ReasonMsg string
	ReasonID  int
	ID        uint16
	TargetID  uint16
}

// VoiceData is voice or whisper audio received from another client.
type VoiceData struct {
	Data     []byte
	ClientID uint16
	Codec    byte
}

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
