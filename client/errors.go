package client

import (
	"errors"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ErrTimedOut reports a connection the server stopped answering: nothing
// arrived, or a packet went unacknowledged, for a minute.
var ErrTimedOut = transport.ErrTimedOut

// ErrHandshake reports a connection attempt whose handshake failed: the server
// sent a step the client could not use — malformed, out of range, or failing
// verification — so the attempt ended there. Connect returns an error wrapping
// it, with the step's own error alongside.
var ErrHandshake = errors.New("TeamSpeak handshake failed")

// errConnectionClosed stands in for a cause the transport did not give, so a
// dropped connection is never reported with a nil error.
var errConnectionClosed = errors.New("connection closed")

// RemovedError reports the server ending this client's session: a kick, a
// ban, or the server stopping. The default reconnect policy retries a server
// that stopped, but not a kick or a ban.
type RemovedError struct {
	// Message is the reason the server or the invoker gave, if any.
	Message string
	// InvokerName is who removed the client, for a kick or a ban.
	InvokerName string
	// Reason is why: teamspeak.ReasonKickServer, ReasonKickServerBan,
	// ReasonServerStop or ReasonServerShutdown.
	Reason teamspeak.Reason
}

func (e *RemovedError) Error() string {
	msg := "removed from the server: " + e.Reason.String()
	if e.InvokerName != "" {
		msg += " by " + e.InvokerName
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}

	return msg
}
