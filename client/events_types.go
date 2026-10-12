package client

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
