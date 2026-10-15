package teamspeak

import "strconv"

// Reason is why a client moved or left view, as the server reports it
// (reasonid).
type Reason int

const (
	// ReasonNone is a client joining, or moving of its own accord.
	ReasonNone Reason = 0
	// ReasonMoved is a client moved by someone else.
	ReasonMoved Reason = 1
	// ReasonSubscription is a client coming into or out of view because a
	// channel was subscribed or unsubscribed.
	ReasonSubscription Reason = 2
	// ReasonLostConnection is a client that timed out.
	ReasonLostConnection Reason = 3
	// ReasonKickChannel is a client kicked from its channel.
	ReasonKickChannel Reason = 4
	// ReasonKickServer is a client kicked from the server.
	ReasonKickServer Reason = 5
	// ReasonKickServerBan is a client banned from the server.
	ReasonKickServerBan Reason = 6
	// ReasonServerStop is the virtual server stopping.
	ReasonServerStop Reason = 7
	// ReasonDisconnect is a client that left the server.
	ReasonDisconnect Reason = 8
	// ReasonChannelUpdate is a change to a channel the client can see.
	ReasonChannelUpdate Reason = 9
	// ReasonChannelEdit is a channel edited by someone.
	ReasonChannelEdit Reason = 10
	// ReasonServerShutdown is the server instance shutting down.
	ReasonServerShutdown Reason = 11
)

var reasonNames = [...]string{
	ReasonNone:           "none",
	ReasonMoved:          "moved",
	ReasonSubscription:   "subscription",
	ReasonLostConnection: "lost connection",
	ReasonKickChannel:    "kicked from channel",
	ReasonKickServer:     "kicked from server",
	ReasonKickServerBan:  "banned from server",
	ReasonServerStop:     "server stopped",
	ReasonDisconnect:     "disconnected",
	ReasonChannelUpdate:  "channel updated",
	ReasonChannelEdit:    "channel edited",
	ReasonServerShutdown: "server shut down",
}

// String returns the reason's name, or "reason N" for a value this version
// does not know.
func (r Reason) String() string {
	if r >= 0 && int(r) < len(reasonNames) {
		return reasonNames[r]
	}

	return "reason " + strconv.Itoa(int(r))
}
