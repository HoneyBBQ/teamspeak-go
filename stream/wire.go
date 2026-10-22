package stream

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/internal/request"
)

// maxCommandLineBytes is the longest command line, in bytes, this package sends
// for a stream, before the " return_code=N" the client appends (13 bytes and
// the digits, at most 23 in all).
//
// The server drops a longer line without an answer, whatever the command, and
// the limit is on the whole line, return code included. Measured on TeamSpeak 6
// 6.0.0-beta13.1 with a two-digit return code: a setupstream line of 9203 bytes
// passed and one of 9204 was dropped. A sendtextmessage of 9500 characters is
// dropped without an answer as well. The constant is well under that, so a
// longer return code, or a server that counts a little differently, does not
// turn a send into a silent drop.
const maxCommandLineBytes = 9150

// ---- Commands ----------------------------------------------------------------

func newRequest(command string, params ...[2]string) teamspeak.Request {
	return request.New(command, params).(teamspeak.Request) //nolint:forcetypeassert // New returns a Request
}

func flag(on bool) string {
	if on {
		return "1"
	}

	return "0"
}

func number[T ~int | ~uint32 | ~uint16](n T) string {
	return strconv.FormatInt(int64(n), 10)
}

// setupRequest is setupstream, with all seven parameters because the server
// refuses a command without any. The mode is peer to peer, the only one the
// server allows an ordinary client.
func setupRequest(
	name string, source Source, bitrate int, accessibility Accessibility, viewerLimit int, audio bool,
) teamspeak.Request {
	return newRequest(commands.SetupStream,
		[2]string{"name", name},
		[2]string{"type", number(source)},
		[2]string{"bitrate", number(bitrate)},
		[2]string{"accessibility", number(accessibility)},
		[2]string{"mode", "1"},
		[2]string{"viewer_limit", number(viewerLimit)},
		[2]string{"audio", flag(audio)},
	)
}

// joinRequest is joinstreamrequest: ask to watch, or with remove stop watching.
func joinRequest(id ID, streamer teamspeak.ClientID, message string, remove bool) teamspeak.Request {
	return newRequest(commands.JoinStreamRequest,
		[2]string{"id", string(id)},
		[2]string{"clid", number(streamer)},
		[2]string{"msg", message},
		[2]string{"is_remove", flag(remove)},
	)
}

// respondRequest is respondjoinstreamrequest. The offer is sent empty on a
// refusal, which the server insists on: without it the answer is error 1542.
func respondRequest(id ID, viewer teamspeak.ClientID, message, offer string, accept bool) teamspeak.Request {
	return newRequest(commands.RespondJoinStreamRequest,
		[2]string{"id", string(id)},
		[2]string{"clid", number(viewer)},
		[2]string{"msg", message},
		[2]string{"offer", offer},
		[2]string{"decision", flag(accept)},
	)
}

// signalRequest is streamsignaling: relay a JSON text to the other end of a
// stream.
func signalRequest(id ID, peer teamspeak.ClientID, text string) teamspeak.Request {
	return newRequest(commands.StreamSignaling,
		[2]string{"id", string(id)},
		[2]string{"clid", number(peer)},
		[2]string{"json", text},
	)
}

func stopRequest(id ID, reason uint32) teamspeak.Request {
	return newRequest(commands.StopStream, [2]string{"id", string(id)}, [2]string{"reason", number(reason)})
}

func infoRequest(clid teamspeak.ClientID) teamspeak.Request {
	return newRequest(commands.RequestStreamInfo, [2]string{"clid", number(clid)})
}

// encoded is the command line as it will be sent, without its return_code.
func encoded(req teamspeak.Request) string {
	return request.Encode(req, func(password string) string { return password })
}

// assertFits returns a *PayloadTooLargeError when the request's line is longer
// than the server takes. The line is measured as it will be sent: escaped, in
// UTF-8 bytes.
func assertFits(req teamspeak.Request) error {
	if size := len(encoded(req)); size > maxCommandLineBytes {
		return &PayloadTooLargeError{Command: req.Command(), Size: size, Limit: maxCommandLineBytes}
	}

	return nil
}

// ---- Signalling --------------------------------------------------------------

// signalMessage is the JSON of a signalling message. The order of its fields is
// the order of its keys on the wire, which the other end may be picky about, so
// it is not rearranged for alignment.
//
//nolint:govet // see above
type signalMessage struct {
	Cmd  string `json:"cmd"`
	Args any    `json:"args,omitempty"`
}

// encodeSignal is the JSON text of a signalling message. It is marshalled with
// the same bytes as the other SDK's, so HTML characters are not escaped.
func encodeSignal(cmd string, args any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(signalMessage{Cmd: cmd, Args: args})
	if err != nil {
		return "", err
	}

	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

func answerJSON(sdp string) string {
	text, _ := encodeSignal("answer", map[string]string{"answer": sdp})

	return text
}

func offerJSON(sdp string) string {
	text, _ := encodeSignal("offer", map[string]string{"offer": sdp})

	return text
}

func candidateJSON(c IceCandidate) string {
	type args struct { //nolint:govet // the order of the keys on the wire
		SDP   string  `json:"sdp"`
		Mid   *string `json:"mid"`
		MLine *uint16 `json:"mLine"`
	}
	// A string and two small numbers always marshal.
	text, _ := encodeSignal("iceCandidate", args{SDP: c.Candidate, Mid: c.SDPMid, MLine: c.SDPMLineIndex})

	return text
}

// signalKind is what a received signalling message is.
type signalKind uint8

const (
	signalRaw signalKind = iota
	signalOffer
	signalAnswer
	signalCandidate
)

// signal is a received signalling message, by what it is.
type signal struct {
	sdp       string
	candidate IceCandidate
	raw       RawSignal
	kind      signalKind
}

// parseSignal reads a signalling message. A shape this does not know, or JSON
// that is none, comes back raw: a wrong shape is accepted by the server and
// dropped by the receiver without an error, so nothing here guesses.
func parseSignal(text string) signal {
	raw := func(cmd string, args json.RawMessage) signal {
		return signal{kind: signalRaw, raw: RawSignal{Cmd: cmd, Args: args, JSON: text}}
	}
	data := []byte(text)
	if !json.Valid(data) {
		return raw("", nil)
	}
	fields, ok := object(data)
	if !ok {
		return raw("", bytes.TrimSpace(data))
	}
	cmd, ok := str(fields["cmd"])
	if !ok {
		return raw("", bytes.TrimSpace(data))
	}
	args := fields["args"]
	unknown := raw(cmd, args)

	switch cmd {
	case "answer":
		if sdp, ok := member(args, "answer"); ok {
			return signal{kind: signalAnswer, sdp: sdp}
		}
	// A renegotiation is the part of the protocol never seen live, so every
	// spelling a sender might use is read.
	case "offer", "reconnectOffer":
		if sdp, ok := str(args); ok {
			return signal{kind: signalOffer, sdp: sdp}
		}
		for _, key := range []string{"offer", "sdp"} {
			if sdp, ok := member(args, key); ok {
				return signal{kind: signalOffer, sdp: sdp}
			}
		}
	case "iceCandidate":
		return candidateFrom(args, unknown)
	}

	return unknown
}

func candidateFrom(args []byte, unknown signal) signal {
	fields, ok := object(args)
	if !ok {
		return unknown
	}
	line, ok := str(fields["sdp"])
	if !ok {
		return unknown
	}
	c := IceCandidate{Candidate: line}
	if mid, ok := str(fields["mid"]); ok {
		c.SDPMid = &mid
	}
	mline, err := strconv.ParseUint(string(fields["mLine"]), 10, 16)
	if err == nil {
		c.SDPMLineIndex = new(uint16(mline))
	}

	return signal{kind: signalCandidate, candidate: c}
}

// object reads a JSON object, or reports that data is none.
func object(data []byte) (map[string]json.RawMessage, bool) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return nil, false
	}

	return fields, true
}

// str reads a JSON string, or reports that data is none.
func str(data []byte) (string, bool) {
	var s string
	if len(data) == 0 || data[0] != '"' || json.Unmarshal(data, &s) != nil {
		return "", false
	}

	return s, true
}

// member reads the string under key of a JSON object.
func member(data []byte, key string) (string, bool) {
	fields, ok := object(data)
	if !ok {
		return "", false
	}

	return str(fields[key])
}

// ---- Notifications -----------------------------------------------------------

// decimal reads an integer of at most 15 digits, as the server writes them.
func decimal(raw string) (int64, bool) {
	digits := len(raw)
	if raw != "" && raw[0] == '-' {
		digits--
	}
	if digits < 1 || digits > 15 {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)

	return n, err == nil
}

// intField reads the integer under key; nil when it is absent or is none.
func intField(params map[string]string, keys ...string) *int {
	for _, key := range keys {
		if raw, ok := params[key]; ok {
			if n, ok := decimal(raw); ok {
				return new(int(n))
			}

			return nil
		}
	}

	return nil
}

// wireNumber reads an unsigned 32-bit number, which is what a source and an
// accessibility are; nil when it is absent or out of range.
func wireNumber(params map[string]string, keys ...string) *uint32 {
	n := intField(params, keys...)
	if n == nil || *n < 0 || *n > math.MaxUint32 {
		return nil
	}

	return new(uint32(*n))
}

// clidOf reads the clid of a notification; 0 when it names none.
func clidOf(params map[string]string) teamspeak.ClientID {
	n, err := strconv.ParseUint(params["clid"], 10, 16)
	if err != nil {
		return 0
	}

	return teamspeak.ClientID(n)
}

// reasonOf reads the stop reason; 0 when there is none.
func reasonOf(params map[string]string) uint32 {
	n, err := strconv.ParseUint(params["reason"], 10, 32)
	if err != nil {
		return 0
	}

	return uint32(n)
}

// infoFrom reads the stream a notifystreamstarted or notifystreaminfo
// describes, merged over what was known of it. It reports false for the empty
// notifystreaminfo the server sends for a client that streams nothing.
//
// The two name the accessibility differently: "access" and "accessibility".
// Only the info carries "viewer".
func infoFrom(params map[string]string, known *Info) (Info, bool) {
	id := params["id"]
	if id == "" {
		return Info{}, false
	}
	var info Info
	if known != nil {
		info = known.clone()
	}
	info.ID = ID(id)
	if clid := clidOf(params); clid != 0 {
		info.ClientID = clid
	}
	if name, ok := params["name"]; ok {
		info.Name = name
	}
	if v, ok := params["audio"]; ok {
		info.Audio = v == "1"
	}
	if n := wireNumber(params, "type"); n != nil {
		info.Source = new(Source(*n))
	}
	if n := wireNumber(params, "accessibility", "access"); n != nil {
		info.Accessibility = new(Accessibility(*n))
	}
	if n := intField(params, "bitrate"); n != nil {
		info.Bitrate = n
	}
	if n := intField(params, "viewer_limit"); n != nil {
		info.ViewerLimit = n
	}
	if n := intField(params, "viewer"); n != nil {
		info.Viewers = n
	}

	return info, true
}

var audioSection = regexp.MustCompile(`(?m)^m=audio[ \t]`)

// hasAudioSection reports whether an SDP has an audio media section.
func hasAudioSection(sdp string) bool {
	return audioSection.MatchString(sdp)
}
