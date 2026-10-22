package stream

import (
	"encoding/json"
	"log/slog"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// ID identifies a stream. The server assigns it when the stream starts.
type ID string

// Source is what a stream shows. The server stores any number, so a stream
// from a client that sends another value is reported with that number.
type Source uint32

// The sources the protocol names.
const (
	// SourceNone is a stream that shows nothing in particular.
	SourceNone Source = iota
	// SourceCamera is a camera.
	SourceCamera
	// SourceScreen is a screen, which is what a screen share shows.
	SourceScreen
	// SourceWindow is one window.
	SourceWindow
	// SourceSession is a session.
	SourceSession
)

var sourceNames = [...]string{"none", "camera", "screen", "window", "session"}

// String names the source, such as "screen". A number with no name reads as
// "Source(7)".
func (s Source) String() string {
	if int(s) < len(sourceNames) {
		return sourceNames[s]
	}

	return "Source(" + strconv.FormatUint(uint64(s), 10) + ")"
}

// known reports whether the protocol has a name for s.
func (s Source) known() bool { return int(s) < len(sourceNames) }

// Accessibility is who a stream says may watch it. Only the publisher enforces
// it: the server relays every request. A value outside the four is reported with
// its number.
type Accessibility uint32

// The accessibilities the protocol names.
const (
	// AccessibilityNone says nobody may watch.
	AccessibilityNone Accessibility = iota
	// AccessibilityPublic says anybody may watch.
	AccessibilityPublic
	// AccessibilityContacts says the publisher's contacts may watch.
	AccessibilityContacts
	// AccessibilityPrivate says only those invited may watch.
	AccessibilityPrivate
)

var accessibilityNames = [...]string{"none", "public", "contacts", "private"}

// String names the accessibility, such as "public". A number with no name reads
// as "Accessibility(7)".
func (a Accessibility) String() string {
	if int(a) < len(accessibilityNames) {
		return accessibilityNames[a]
	}

	return "Accessibility(" + strconv.FormatUint(uint64(a), 10) + ")"
}

// known reports whether the protocol has a name for a.
func (a Accessibility) known() bool { return int(a) < len(accessibilityNames) }

// Info is a stream as the server describes it.
//
// A nil pointer field means the server never reported the value, which is not
// the same as reporting zero. List, Get and every event hand out their own copy:
// the pointers point to values nobody else shares.
type Info struct {
	// Source is what the stream shows.
	Source *Source
	// Bitrate is the bitrate the server reports, in bits per second. It is not
	// the one requested: the server substitutes its own figure, and the real
	// limit is the sender's own encoder setting.
	Bitrate *int
	// Accessibility is who the stream says may watch it.
	Accessibility *Accessibility
	// ViewerLimit is the viewer limit the publisher set; 0 is none. The server
	// does not enforce it.
	ViewerLimit *int
	// Viewers is how many clients had asked to watch, pending requests
	// included, when the server last answered requeststreaminfo for the stream.
	// Nothing updates it, and it is what a client that is not the publisher
	// knows. The publisher's own, current list of accepted viewers is
	// Published.Viewers.
	Viewers *int
	// ID is the stream's id, assigned by the server.
	ID ID
	// Name is the stream's name.
	Name string
	// ClientID is the client that publishes the stream.
	ClientID teamspeak.ClientID
	// Audio is whether the stream carries an audio track.
	Audio bool
}

// clone returns a copy that shares no memory with i.
func (i Info) clone() Info {
	i.Source = clonePtr(i.Source)
	i.Bitrate = clonePtr(i.Bitrate)
	i.Accessibility = clonePtr(i.Accessibility)
	i.ViewerLimit = clonePtr(i.ViewerLimit)
	i.Viewers = clonePtr(i.Viewers)

	return i
}

// equal reports whether two descriptions of a stream say the same.
func (i Info) equal(o Info) bool {
	return i.ID == o.ID && i.ClientID == o.ClientID && i.Name == o.Name && i.Audio == o.Audio &&
		ptrEqual(i.Source, o.Source) && ptrEqual(i.Bitrate, o.Bitrate) &&
		ptrEqual(i.Accessibility, o.Accessibility) && ptrEqual(i.ViewerLimit, o.ViewerLimit) &&
		ptrEqual(i.Viewers, o.Viewers)
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}

	return new(*p)
}

func ptrEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// IceCandidate is an ICE candidate in the shape of the browser's
// RTCIceCandidateInit and of the candidate init type that WebRTC libraries for
// Go share with it, so one converts to the other field by field.
type IceCandidate struct {
	// SDPMid is the media section's id; nil when none.
	SDPMid *string
	// SDPMLineIndex is the media section's index; nil when none.
	SDPMLineIndex *uint16
	// Candidate is the candidate line, such as "candidate:1 1 udp 2122260223 ...".
	Candidate string
}

// RawSignal is a signalling message this package has no name for, or that was
// not shaped as the ones it has: handed over rather than dropped.
type RawSignal struct {
	// Cmd is the message's "cmd"; empty when the JSON had none.
	Cmd string
	// JSON is the whole message, as the text arrived.
	JSON string
	// Args is the "args" part of the message: the JSON value under that key,
	// unparsed. Untrusted: the server relays the JSON unseen, so this is
	// whatever the other client sent, of any shape. It is nil when the text was
	// not JSON or had no "args"; when it was JSON but no object with a "cmd",
	// it is the whole value.
	Args json.RawMessage
}

// Viewer is a client that asked to watch a stream.
type Viewer struct {
	// UID is the client's unique identifier; empty when the client is out of
	// view and the server could not say who it is.
	UID teamspeak.UID
	// Nickname is the client's nickname; empty under the same condition.
	Nickname string
	// ClientID is the client's id.
	ClientID teamspeak.ClientID
}

// EndCause says why a stream ended.
type EndCause uint8

// The causes a stream ends with. Streams.OnStopped reports EndCauseServer,
// EndCauseStopped and EndCauseGone; Published.OnEnded reports all five.
const (
	// EndCauseStopped is a stream that Published.Stop ended here.
	EndCauseStopped EndCause = iota + 1
	// EndCauseServer is a stream the server reported stopped
	// (notifystreamstopped), whoever stopped it.
	EndCauseServer
	// EndCauseGone is a stream whose publisher cleared client_is_streaming or
	// came into view not streaming, with no stop reaching this client within
	// two seconds.
	EndCauseGone
	// EndCauseDisconnected is the client's connection ending.
	EndCauseDisconnected
	// EndCauseShutdown is Streams.Close.
	EndCauseShutdown
)

var endCauseNames = [...]string{
	EndCauseStopped: "stopped", EndCauseServer: "server", EndCauseGone: "gone",
	EndCauseDisconnected: "disconnected", EndCauseShutdown: "shutdown",
}

// String names the cause, such as "gone".
func (c EndCause) String() string {
	if c > 0 && int(c) < len(endCauseNames) {
		return endCauseNames[c]
	}

	return "EndCause(" + strconv.FormatUint(uint64(c), 10) + ")"
}

// peer is the cause a peer of a stream that ended with c closes with.
func (c EndCause) peer() PeerCause {
	switch c {
	case EndCauseDisconnected:
		return PeerCauseDisconnected
	case EndCauseShutdown:
		return PeerCauseShutdown
	case EndCauseStopped, EndCauseServer, EndCauseGone:
		return PeerCauseStopped
	default:
		return PeerCauseStopped
	}
}

// PeerCause says why a peer closed.
type PeerCause uint8

// The causes a peer closes with.
const (
	// PeerCauseClosed is a peer that the application closed, or a viewer that
	// left.
	PeerCauseClosed PeerCause = iota + 1
	// PeerCauseLeft is the other end of the peer leaving the stream.
	PeerCauseLeft
	// PeerCauseStopped is the stream ending, whoever ended it.
	PeerCauseStopped
	// PeerCauseDisconnected is the client's connection ending.
	PeerCauseDisconnected
	// PeerCauseShutdown is Streams.Close.
	PeerCauseShutdown
)

var peerCauseNames = [...]string{
	PeerCauseClosed: "closed", PeerCauseLeft: "left", PeerCauseStopped: "stopped",
	PeerCauseDisconnected: "disconnected", PeerCauseShutdown: "shutdown",
}

// String names the cause, such as "left".
func (c PeerCause) String() string {
	if c > 0 && int(c) < len(peerCauseNames) {
		return peerCauseNames[c]
	}

	return "PeerCause(" + strconv.FormatUint(uint64(c), 10) + ")"
}

// PeerClosedEvent is a peer closing.
type PeerClosedEvent struct {
	// Cause is why it closed.
	Cause PeerCause
	// Reason is the stop reason the server reported, for PeerCauseStopped when
	// the stream ended on the server's word or by Published.Stop; otherwise 0.
	Reason uint32
}

// EndedEvent is a published stream ending.
type EndedEvent struct {
	// Cause is why it ended. Always set: a Reason of 0 alone does not say.
	Cause EndCause
	// Reason is the numeric reason: the one Stop was given, or the server's.
	// The server reported 1 when the publisher's connection ended. It is 0 for
	// EndCauseGone, EndCauseDisconnected and EndCauseShutdown, which carry none.
	Reason uint32
}

// StoppedEvent is a stream ending, as Streams.OnStopped reports it.
type StoppedEvent struct {
	// Info is the stream as it was last known.
	Info Info
	// Cause is EndCauseServer for a notifystreamstopped, EndCauseStopped for a
	// stream this client stopped, and EndCauseGone for a stream whose publisher
	// cleared client_is_streaming or came into view not streaming, without a
	// stop reaching this client.
	Cause EndCause
	// Reason is the stop reason the server reported; 0 unless the stopper gave
	// one, and for EndCauseGone.
	Reason uint32
}

// ViewerEvent is a viewer joining or leaving a stream, as the server tells the
// owner, the other viewers and, for a join, the clients of the owner's channel.
type ViewerEvent struct {
	// Info is the stream.
	Info Info
	// ClientID is the viewer.
	ClientID teamspeak.ClientID
}

// WarningCode says what a Warning is about.
type WarningCode string

// WarningOfferWithoutAudio is an SDP offer with no m=audio section: the
// TeamSpeak 6 client does not answer it.
const WarningOfferWithoutAudio WarningCode = "offer-without-audio"

// WarningEvent is something the package noticed and did not stop: the offer or
// message goes out unchanged.
type WarningEvent struct {
	// Code is what was noticed.
	Code WarningCode
	// StreamID is the stream.
	StreamID ID
	// Message is a sentence saying what and why.
	Message string
	// ClientID is the viewer the offer was for.
	ClientID teamspeak.ClientID
}

// Options configures New.
type Options struct {
	// Logger receives what happens inside: errors nobody handles, and
	// recovered handler panics. Nil discards it, as the client does.
	Logger *slog.Logger
	// RememberDenied keeps the unique identifiers of the clients Deny refused
	// and leaves their later requests unanswered. Off by default. The server
	// remembers no decision, so a client can ask again, and every ask is
	// relayed. The identifiers are held in memory only, the 1024 most recent,
	// and dropped by Close. A requester whose identifier cannot be found out is
	// not remembered.
	RememberDenied bool
}

// PublishOptions starts a stream with Streams.Publish.
type PublishOptions struct {
	// Source is what the stream shows. Nil means SourceScreen.
	Source *Source
	// Bitrate is the bitrate to announce, in bits per second, 0 to
	// 2147483647. Nil means 1500000. It is only an announcement: the server
	// reports a figure of its own, and the encoder's setting is what limits the
	// stream.
	Bitrate *int
	// Accessibility is who the stream says may watch it. Nil means
	// AccessibilityPublic. The server does not enforce it.
	Accessibility *Accessibility
	// Name is the stream's name.
	Name string
	// ViewerLimit is the viewer limit to announce, 0 to 65535; 0 is none. The
	// server does not enforce it.
	ViewerLimit int
	// Audio is whether the stream carries an audio track.
	Audio bool
}

// WatchOptions asks to watch a stream with Streams.Watch.
type WatchOptions struct {
	// Message goes to the publisher, shown with the request.
	Message string
	// ClientID is the publisher, for a stream that is not in List: the id
	// of the stream alone does not say who runs it. Leave it 0 for a stream
	// this Streams has heard of, which names its own publisher.
	ClientID teamspeak.ClientID
}

// RequestState is where a join request stands.
type RequestState uint8

// The states of a join request.
const (
	// RequestPending is a request nobody has answered yet.
	RequestPending RequestState = iota
	// RequestAccepted is a request Accept took.
	RequestAccepted
	// RequestDenied is a request Deny refused.
	RequestDenied
	// RequestFailed is a request whose answer did not reach the server.
	RequestFailed
	// RequestWithdrawn is a request the viewer took back, or left view
	// before it was answered. JoinRequest.OnClosed reports it.
	RequestWithdrawn
	// RequestEnded is a request the stream ended before it was answered.
	// JoinRequest.OnClosed reports it.
	RequestEnded
)

var requestStateNames = [...]string{"pending", "accepted", "denied", "failed", "withdrawn", "ended"}

// String names the state, such as "pending".
func (s RequestState) String() string {
	if int(s) < len(requestStateNames) {
		return requestStateNames[s]
	}

	return "RequestState(" + strconv.FormatUint(uint64(s), 10) + ")"
}
