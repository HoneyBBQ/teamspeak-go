package stream

import (
	"errors"
	"fmt"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

var (
	// ErrClosed is returned by a call on a Streams after Close, and by a call on
	// a peer after it closed.
	ErrClosed = errors.New("stream: closed")
	// ErrNotPending is returned by JoinRequest.Accept and Deny for a request
	// that was answered already or is no longer waiting for an answer.
	ErrNotPending = errors.New("stream: the join request is not pending")
	// ErrAlreadyWatching is returned by Watch for a stream this Streams is
	// already watching or asking to watch.
	ErrAlreadyWatching = errors.New("stream: already watching the stream")
	// ErrInvalidOptions is returned for an option that is out of range, such as
	// a bitrate below zero or a source the protocol has no number for.
	ErrInvalidOptions = errors.New("stream: invalid options")
)

var (
	errDropped   = errors.New("stream: dropping the oldest")
	errNoSession = errors.New("stream: signalling from a client with no session")
	errNoOffer   = errors.New("stream: the publisher accepted the request without an offer")
)

// UnsupportedError reports that the connected server does not do streams: only
// TeamSpeak 6 does. A TeamSpeak 3 server answers none of the stream commands,
// not even with an error, so Publish and Watch return this before sending
// instead of waiting out a timeout. A server the client has not identified
// yet, because it has not connected, counts as unsupported.
type UnsupportedError struct {
	// Version is the virtualserver_version the server sent; empty before the
	// client has connected.
	Version string
	// Family is the server generation the client found; never
	// client.ServerFamilyTS6.
	Family client.ServerFamily
}

// Error describes the server.
func (e *UnsupportedError) Error() string {
	what := "an unknown server"
	if e.Family != client.ServerFamilyUnknown {
		what = e.Family.String()
	}
	if e.Version != "" {
		what += " (" + e.Version + ")"
	}

	return "stream: streams need a TeamSpeak 6 server; this is " + what
}

// JoinDeniedError reports that a stream's owner refused a request to watch it.
// Watch returns it.
//
// The server remembers no decision, so a client can ask again, and every ask is
// relayed to the publisher. A publisher that means to refuse for good can set
// Options.RememberDenied, or leave the request unanswered.
type JoinDeniedError struct {
	// StreamID is the stream that was asked for.
	StreamID ID
	// Message is what the owner gave with the refusal; empty for none.
	Message string
}

// Error quotes the owner's message, if it gave one.
func (e *JoinDeniedError) Error() string {
	msg := "stream: the stream's owner denied the request to watch it"
	if e.Message != "" {
		msg += ": " + e.Message
	}

	return msg
}

// PayloadTooLargeError reports a stream command too long for the server to
// take. The server drops a command line of about 9.2 KB, escaped, without an
// answer, so the call fails before sending instead of timing out; Limit has
// the figure this package holds to. An SDP offer of a few kilobytes is far
// under it.
type PayloadTooLargeError struct {
	// Command is the command that would have been sent.
	Command string
	// Size is the size of its line on the wire, escaped, in bytes.
	Size int
	// Limit is the longest line this package sends, in bytes.
	Limit int
}

// Error says how long the line is.
func (e *PayloadTooLargeError) Error() string {
	return fmt.Sprintf("stream: %s is %d bytes escaped; the server takes at most %d", e.Command, e.Size, e.Limit)
}

// EndedError reports that a stream is gone: it ended, or its id is not one this
// client knows or the server does (error 5635). Watch returns it for an id it
// has not heard of, and when the stream ends before its owner answers; a
// signalling call does when the stream ended under it.
//
// When the server refused with 5635, Unwrap gives that *teamspeak.ServerError,
// so errors.Is(err, errcode.StreamNotFound) holds too.
type EndedError struct {
	err error
	// StreamID is the stream that ended.
	StreamID ID
}

// Error names the stream.
func (e *EndedError) Error() string {
	return fmt.Sprintf("stream: stream %s has ended, or is not known", e.StreamID)
}

// Unwrap returns the server's refusal, when there was one.
func (e *EndedError) Unwrap() error { return e.err }

// isGone reports whether err says the connection is not there to send on.
func isGone(err error) bool {
	return errors.Is(err, teamspeak.ErrNotConnected)
}
