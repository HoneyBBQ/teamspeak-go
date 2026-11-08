package client

import (
	"errors"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// ErrConnectionTimeout reports a connection the server stopped answering:
// nothing arrived, or a packet went unacknowledged, for a minute.
var ErrConnectionTimeout = transport.ErrTimedOut

// ErrConnectionStalled reports a connection ended because a command packet
// from the server stayed missing for seconds while later ones arrived. The
// server sends a command again until it is acknowledged, so the stream was
// broken; carrying on would have lost an answer or a notification, and a
// reconnect starts from a consistent state.
var ErrConnectionStalled = transport.ErrCommandStalled

// ErrHandshake reports a connection attempt whose handshake failed: the server
// sent a step the client could not use — malformed, out of range, or failing
// verification — so the attempt ended there. Connect returns an error wrapping
// it, with the step's own error alongside.
var ErrHandshake = errors.New("TeamSpeak handshake failed")

// ErrPuzzleTooHard reports a connection attempt whose server asked for more
// squarings in its Init1 puzzle than the client will do. A server under a burst
// of connections raises the level it asks for, but not this far; nothing was
// solved. Connect returns an error wrapping it and ErrHandshake.
var ErrPuzzleTooHard = crypto.ErrPuzzleTooHard

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

// S3TransferError reports an S3 file transfer that failed: the storage answered
// a request with an HTTP error, a request got no answer, or the server reports
// that its own request to the storage failed. The message names the file, never
// the presigned URL. It wraps teamspeak.ErrFileTransfer, and Err when set.
type S3TransferError struct {
	// Err is why no answer came, or nil.
	Err error
	// Code is the error code in the storage's answer (NoSuchKey,
	// SignatureDoesNotMatch), "" if it sent none.
	Code string
	// msg describes the failure, without Err.
	msg string
	// Status is the HTTP status the storage answered with: 404 for a file that
	// is not there, 403 for a URL that expired or a body whose length is not the
	// one the URL is signed for. 0 when no answer came, and when the server
	// reported the failure.
	Status int
}

// Error describes the failure, and why no answer came when that is known.
func (e *S3TransferError) Error() string {
	if e.Err == nil {
		return e.msg
	}

	return e.msg + ": " + e.Err.Error()
}

// Unwrap returns teamspeak.ErrFileTransfer, and Err when it is set.
func (e *S3TransferError) Unwrap() []error {
	if e.Err == nil {
		return []error{teamspeak.ErrFileTransfer}
	}

	return []error{teamspeak.ErrFileTransfer, e.Err}
}

// S3UnsupportedError reports that the connected server does not say it does S3
// file transfer: its extensions (virtualserver_capability_extensions) do not
// name "s3". The S3 methods return this before sending: a TeamSpeak 6 server
// without it answers the commands with 1035, and a TeamSpeak 3 server, which
// names no extension, with an error that names no command, so they would wait
// out their timeout. Before the client has connected no server has named any,
// and it counts as unsupported the same way.
type S3UnsupportedError struct {
	// Family is the server generation the client found.
	Family ServerFamily
	// Version is the virtualserver_version the server sent; empty before the
	// client has connected.
	Version string
	// Extensions are the extensions the server named, "s3" not among them.
	Extensions []string
}

// Error describes the server and the extensions it named.
func (e *S3UnsupportedError) Error() string {
	what := "an unknown server"
	if e.Family != ServerFamilyUnknown {
		what = e.Family.String()
	}
	if e.Version != "" {
		what += " (" + e.Version + ")"
	}
	named := "none"
	if len(e.Extensions) > 0 {
		named = strings.Join(e.Extensions, ", ")
	}

	return "S3 file transfer needs a server that names s3 among its extensions; this is " + what +
		", which names " + named
}
