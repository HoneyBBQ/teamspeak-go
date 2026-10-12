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

// ErrInvalidAddress reports a server address that cannot be one: no host, a
// host containing what no host name or IP address can, or a port outside
// 1–65535. Connect returns an error wrapping it before anything starts, and
// DefaultShouldRetry does not retry it. A host name that merely does not
// resolve is not this error: a lookup can fail for a while and then succeed.
var ErrInvalidAddress = errors.New("invalid server address")

// errConnectionClosed stands in for a cause the transport did not give, so a
// dropped connection is never reported with a nil error.
var errConnectionClosed = errors.New("connection closed")

// errStopped ends a reconnect attempt that finds Disconnect already called.
var errStopped = errors.New("client was disconnected")

// RemovedError reports the server ending this client's session: a kick, a
// ban, or the server stopping. The default reconnect policy retries a server
// that stopped, but not a kick or a ban.
type RemovedError struct {
	// ReasonMessage is the reason the server or the invoker gave
	// (reasonmsg), if any.
	ReasonMessage string
	// InvokerName is who removed the client, for a kick or a ban.
	InvokerName string
	// Reason is why: teamspeak.ReasonKickServer, ReasonKickServerBan,
	// ReasonServerStop or ReasonServerShutdown.
	Reason teamspeak.Reason
}

// Error says why and by whom the client was removed, with the reason given.
func (e *RemovedError) Error() string {
	msg := "removed from the server: " + e.Reason.String()
	if e.InvokerName != "" {
		msg += " by " + e.InvokerName
	}
	if e.ReasonMessage != "" {
		msg += ": " + e.ReasonMessage
	}

	return msg
}
