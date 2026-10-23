package stream

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/commands"
)

// The expected lines below are the ones the TypeScript SDK's wire tests expect
// for the same inputs, so the two cannot drift apart. One difference is known
// and harmless: encoding/json writes U+2028 and U+2029 as \u2028 and \u2029
// where JSON.stringify leaves them as they are; both read back the same.

func TestValueTables_NumberTheNamesAsTheServerDoes(t *testing.T) {
	sources := []Source{SourceNone, SourceCamera, SourceScreen, SourceWindow, SourceSession}
	for i, s := range sources {
		if uint32(s) != uint32(i) || !s.known() {
			t.Errorf("source %v = %d", s, s)
		}
	}
	for i, want := range []string{"none", "camera", "screen", "window", "session"} {
		if got := Source(i).String(); got != want {
			t.Errorf("Source(%d) = %q, want %q", i, got, want)
		}
	}
	if got := Source(9).String(); got != "Source(9)" || Source(9).known() {
		t.Errorf("Source(9) = %q", got)
	}
	for i, want := range []string{"none", "public", "contacts", "private"} {
		if got := Accessibility(i).String(); got != want || !Accessibility(i).known() {
			t.Errorf("Accessibility(%d) = %q, want %q", i, got, want)
		}
	}
	if got := Accessibility(4).String(); got != "Accessibility(4)" || Accessibility(4).known() {
		t.Errorf("Accessibility(4) = %q", got)
	}
	if got := TransportP2P.String(); got != "p2p" || !TransportP2P.known() {
		t.Errorf("TransportP2P = %q", got)
	}
	for _, other := range []Transport{0, 2} {
		if got, want := other.String(), fmt.Sprintf("Transport(%d)", other); got != want || other.known() {
			t.Errorf("Transport(%d) = %q, want %q", other, got, want)
		}
	}
}

// The server stores any integer, so a stream from another client may carry one.
func TestInfoFrom_PassesANumberWithNoNameThrough(t *testing.T) {
	info, ok := infoFrom(map[string]string{"id": "a", "clid": "2", "type": "9", "accessibility": "4"}, nil)
	if !ok || *info.Source != 9 || *info.Accessibility != 4 {
		t.Errorf("info = %+v", info)
	}
}

// Only 1 has been seen; another value is the server's word, passed through.
func TestInfoFrom_ReadsTheTransportAndKeepsItWhenTheRowLacksIt(t *testing.T) {
	info, _ := infoFrom(map[string]string{"id": "a", "clid": "2", "mode": "1"}, nil)
	if info.Transport == nil || *info.Transport != TransportP2P {
		t.Errorf("mode=1: transport = %v", info.Transport)
	}
	other, _ := infoFrom(map[string]string{"id": "a", "mode": "2"}, &info)
	if other.Transport == nil || *other.Transport != 2 || other.Transport.String() != "Transport(2)" {
		t.Errorf("mode=2: transport = %v", other.Transport)
	}
	if *info.Transport != TransportP2P {
		t.Error("the merge changed what it merged over")
	}
	kept, _ := infoFrom(map[string]string{"id": "a", "viewer": "1"}, &other)
	if kept.Transport == nil || *kept.Transport != 2 {
		t.Errorf("a row without mode: transport = %v", kept.Transport)
	}
	none, _ := infoFrom(map[string]string{"id": "a"}, nil)
	unreadable, _ := infoFrom(map[string]string{"id": "a", "mode": "x"}, nil)
	if none.Transport != nil || unreadable.Transport != nil {
		t.Errorf("transport = %v, %v; want none reported", none.Transport, unreadable.Transport)
	}
}

func TestInfo_SeesATransportChangeAndCopiesIt(t *testing.T) {
	a := Info{ID: "a", Transport: new(TransportP2P)}
	if !a.equal(a.clone()) {
		t.Error("a copy differs")
	}
	if a.equal(Info{ID: "a", Transport: new(Transport(2))}) || a.equal(Info{ID: "a"}) {
		t.Error("a change of transport is not seen")
	}
	c := a.clone()
	*c.Transport = 2
	if *a.Transport != TransportP2P {
		t.Error("clone shares the transport")
	}
}

func TestSetupRequest_SendsAllSevenParametersInPeerToPeerMode(t *testing.T) {
	got := encoded(setupRequest("same", SourceScreen, 1, AccessibilityPublic, 0, false))
	want := "setupstream name=same type=2 bitrate=1 accessibility=1 mode=1 viewer_limit=0 audio=0"
	if got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

func TestRespondRequest_AlwaysCarriesTheOfferEmptyOnARefusal(t *testing.T) {
	got := encoded(respondRequest("id", 3, "no", "", false))
	want := "respondjoinstreamrequest id=id clid=3 msg=no offer= decision=0"
	if got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

// lineCase is a request and the line it is sent as.
type lineCase struct {
	want string
	req  teamspeak.Request
}

func line(req teamspeak.Request, want string) lineCase { return lineCase{want: want, req: req} }

func TestRequests_Lines(t *testing.T) {
	for _, tc := range []lineCase{
		line(joinRequest("s-1", 5, "let me in", false), `joinstreamrequest id=s-1 clid=5 msg=let\sme\sin is_remove=0`),
		line(joinRequest("s-1", 5, "", true), "joinstreamrequest id=s-1 clid=5 msg= is_remove=1"),
		line(respondRequest("s-1", 9, "hi", "v=0\r\n", true),
			`respondjoinstreamrequest id=s-1 clid=9 msg=hi offer=v=0\r\n decision=1`),
		line(signalRequest("s-1", 9, `{"cmd":"x"}`), `streamsignaling id=s-1 clid=9 json={"cmd":"x"}`),
		line(stopRequest("s-1", 4294967295), "stopstream id=s-1 reason=4294967295"),
		line(infoRequest(7), "requeststreaminfo clid=7"),
		line(setupRequest("a|b", SourceNone, 0, AccessibilityPrivate, 65535, true),
			`setupstream name=a\pb type=0 bitrate=0 accessibility=3 mode=1 viewer_limit=65535 audio=1`),
	} {
		if got := encoded(tc.req); got != tc.want {
			t.Errorf("%s: line = %q, want %q", tc.req.Command(), got, tc.want)
		}
	}
}

func TestSignalJSON_Golden(t *testing.T) {
	const mixed = "a b|c\\d/e\"f\r\n日本 ü <>&\x01\b\f\t\x7f"
	for _, tc := range []struct{ name, got, want string }{
		{"answer", answerJSON("v=0\r\n"), `{"cmd":"answer","args":{"answer":"v=0\r\n"}}`},
		{"offer", offerJSON("v=0\r\n"), `{"cmd":"offer","args":{"offer":"v=0\r\n"}}`},
		{"answer with every kind of character", answerJSON(mixed),
			`{"cmd":"answer","args":{"answer":"a b|c\\d/e\"f\r\n日本 ü <>&\u0001\b\f\t` + "\x7f" + `"}}`},
		{"candidate", candidateJSON(IceCandidate{Candidate: "candidate:1", SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}),
			`{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}`},
		{"candidate with no mid or line", candidateJSON(IceCandidate{Candidate: "c"}),
			`{"cmd":"iceCandidate","args":{"sdp":"c","mid":null,"mLine":null}}`},
	} {
		if tc.got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, tc.got, tc.want)
		}
	}
}

func TestEncodeSignal_ArgumentsOfAnyShape(t *testing.T) {
	for _, tc := range []struct {
		args any
		want string
	}{
		{nil, `{"cmd":"x"}`},
		{map[string]bool{"on": true}, `{"cmd":"x","args":{"on":true}}`},
		{"text", `{"cmd":"x","args":"text"}`},
		{[]int{1, 2}, `{"cmd":"x","args":[1,2]}`},
	} {
		got, err := encodeSignal("x", tc.args)
		if err != nil || got != tc.want {
			t.Errorf("encodeSignal(%v) = %q, %v; want %q", tc.args, got, err, tc.want)
		}
	}
}

func TestParseSignal_ReadsAnAnswer(t *testing.T) {
	got := parseSignal(`{"cmd":"answer","args":{"answer":"v=0\r\n"}}`)
	if got.kind != signalAnswer || got.sdp != "v=0\r\n" {
		t.Errorf("signal = %+v", got)
	}
}

func TestParseSignal_ReadsAnICECandidateWithTheBrowsersFieldNames(t *testing.T) {
	got := parseSignal(`{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}`)
	want := IceCandidate{Candidate: "candidate:1", SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}
	if got.kind != signalCandidate || !reflect.DeepEqual(got.candidate, want) {
		t.Errorf("signal = %+v", got)
	}
}

func TestParseSignal_ReadsACandidateWithoutAMidOrALineAsNil(t *testing.T) {
	for _, in := range []string{
		`{"cmd":"iceCandidate","args":{"sdp":"c"}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"c","mid":null,"mLine":null}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"c","mid":7,"mLine":-1}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"c","mLine":65536}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"c","mLine":1.5}}`,
	} {
		got := parseSignal(in)
		bare := got.candidate.SDPMid == nil && got.candidate.SDPMLineIndex == nil
		if got.kind != signalCandidate || got.candidate.Candidate != "c" || !bare {
			t.Errorf("%s: signal = %+v", in, got)
		}
	}
}

func TestParseSignal_ReadsARenegotiationOfferInEverySpelling(t *testing.T) {
	for name, in := range map[string]string{
		"a string":      `{"cmd":"offer","args":"sdp"}`,
		"an offer key":  `{"cmd":"offer","args":{"offer":"sdp"}}`,
		"an sdp key":    `{"cmd":"reconnectOffer","args":{"sdp":"sdp"}}`,
		"reconnect key": `{"cmd":"reconnectOffer","args":{"offer":"sdp"}}`,
	} {
		if got := parseSignal(in); got.kind != signalOffer || got.sdp != "sdp" {
			t.Errorf("%s: signal = %+v", name, got)
		}
	}
}

// A wrong shape is relayed by the server and dropped by the receiver, so it
// must come out as something the application can see.
func TestParseSignal_HandsOverAWrongShapeAsARawSignal(t *testing.T) {
	for _, tc := range []struct{ name, in, cmd string }{
		{"an answer as a bare string", `{"cmd":"answer","args":"sdp"}`, "answer"},
		{"an answer under the wrong key", `{"cmd":"answer","args":{"sdp":"sdp"}}`, "answer"},
		{"a candidate without a line", `{"cmd":"iceCandidate","args":{"mid":"0"}}`, "iceCandidate"},
		{"a command it does not know", `{"cmd":"mute","args":{"on":true}}`, "mute"},
		{"an offer of a number", `{"cmd":"offer","args":7}`, "offer"},
	} {
		got := parseSignal(tc.in)
		if got.kind != signalRaw || got.raw.Cmd != tc.cmd || got.raw.JSON != tc.in {
			t.Errorf("%s: signal = %+v", tc.name, got)
		}
	}
}

func TestParseSignal_HandsOverWhatIsNoSignallingMessageWithItsText(t *testing.T) {
	for _, in := range []string{"not json", "", "[1,2]", "null", `"text"`, `{"args":{}}`, `{"cmd":7}`, `{"cmd":`} {
		got := parseSignal(in)
		if got.kind != signalRaw || got.raw.Cmd != "" || got.raw.JSON != in {
			t.Errorf("%q: signal = %+v", in, got)
		}
	}
	if got := parseSignal("not json"); got.raw.Args != nil {
		t.Errorf("unreadable text has args %q", got.raw.Args)
	}
	if got := parseSignal(`[1, 2]`); string(got.raw.Args) != "[1, 2]" {
		t.Errorf("args = %q, want the value", got.raw.Args)
	}
}

func TestParseSignal_SurvivesTheEscaperWithAnSDPsWhitespacePipesAndQuotes(t *testing.T) {
	c := IceCandidate{Candidate: "a b|c\\d/e\"f\r\n日本 ü", SDPMid: new("audio"), SDPMLineIndex: new(uint16(1))}
	line := encoded(signalRequest("id", 2, candidateJSON(c)))
	if strings.ContainsAny(strings.TrimPrefix(line, "streamsignaling id=id clid=2 json="), " |\r\n") {
		t.Errorf("the line is not escaped: %q", line)
	}
	got := parseSignal(candidateJSON(c))
	if got.kind != signalCandidate || !reflect.DeepEqual(got.candidate, c) {
		t.Errorf("signal = %+v", got)
	}
}

func TestInfoFrom_ReadsTheAnnouncementWhichNamesTheAccessibilityAccess(t *testing.T) {
	info, ok := infoFrom(map[string]string{
		"clid": "5", "id": "u-1", "name": "Demo", "type": "2", "access": "1", "mode": "1",
		"bitrate": "58208", "viewer_limit": "0", "audio": "1",
	}, nil)
	want := Info{
		ID: "u-1", ClientID: 5, Name: "Demo", Audio: true, Source: new(SourceScreen),
		Bitrate: new(58208), Accessibility: new(AccessibilityPublic), Transport: new(TransportP2P), ViewerLimit: new(0),
	}
	if !ok || !reflect.DeepEqual(info, want) {
		t.Errorf("info = %+v, want %+v", info, want)
	}
}

func TestInfoFrom_ReadsTheInfoWhichAddsTheViewersAndKeepsWhatItLacks(t *testing.T) {
	known, _ := infoFrom(map[string]string{"clid": "5", "id": "u-1", "name": "Demo", "type": "3"}, nil)
	info, ok := infoFrom(map[string]string{"id": "u-1", "viewer": "2", "accessibility": "3"}, &known)
	if !ok || *info.Viewers != 2 || *info.Accessibility != AccessibilityPrivate || info.Name != "Demo" ||
		*info.Source != SourceWindow || info.ClientID != 5 {
		t.Errorf("info = %+v", info)
	}
	// The merge did not change what it merged over.
	if known.Viewers != nil || known.Accessibility != nil {
		t.Errorf("known = %+v", known)
	}
}

// The server answers a client that streams nothing with a bare row.
func TestInfoFrom_TakesTheEmptyAnswerAsNoStream(t *testing.T) {
	for _, params := range []map[string]string{{"return_code": "4"}, {"id": ""}, nil} {
		if _, ok := infoFrom(params, nil); ok {
			t.Errorf("%v is a stream", params)
		}
	}
}

func TestInfoFrom_LeavesOutNumbersItCannotRead(t *testing.T) {
	info, _ := infoFrom(map[string]string{
		"id": "a", "type": "x", "bitrate": "1234567890123456", "viewer_limit": "-3", "accessibility": "99999999999",
		"clid": "70000",
	}, nil)
	if info.Source != nil || info.Bitrate != nil || info.Accessibility != nil || info.ClientID != 0 {
		t.Errorf("info = %+v", info)
	}
	if info.ViewerLimit == nil || *info.ViewerLimit != -3 {
		t.Errorf("viewer limit = %v", info.ViewerLimit)
	}
}

func TestInfoFrom_KeepsTheClientWhenTheRowNamesNone(t *testing.T) {
	known, _ := infoFrom(map[string]string{"id": "a", "clid": "5"}, nil)
	for _, clid := range []string{"0", "", "oops"} {
		info, _ := infoFrom(map[string]string{"id": "a", "clid": clid}, &known)
		if info.ClientID != 5 {
			t.Errorf("clid %q: client = %d", clid, info.ClientID)
		}
	}
}

func TestAssertFits(t *testing.T) {
	overhead := len(encoded(respondRequest("id", 2, "", "", true)))
	fill := func(n int, unit string) teamspeak.Request {
		return respondRequest("id", 2, "", strings.Repeat(unit, n), true)
	}

	t.Run("lets an offer of a few kilobytes through", func(t *testing.T) {
		err := assertFits(fill(4000, "a"))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("accepts the limit and refuses a byte over", func(t *testing.T) {
		err := assertFits(fill(maxCommandLineBytes-overhead, "a"))
		if err != nil {
			t.Errorf("at the limit: %v", err)
		}
		err = assertFits(fill(maxCommandLineBytes-overhead+1, "a"))
		var big *PayloadTooLargeError
		if !errors.As(err, &big) || big.Size != maxCommandLineBytes+1 || big.Limit != maxCommandLineBytes ||
			big.Command != commands.RespondJoinStreamRequest {
			t.Errorf("one over: %v", err)
		}
	})
	t.Run("measures the escaped line, not the characters", func(t *testing.T) {
		// 3000 spaces are 6000 bytes escaped, so 5000 of them are over.
		err := assertFits(fill(3000, " "))
		if err != nil {
			t.Error(err)
		}
		err = assertFits(fill(5000, " "))
		if err == nil {
			t.Error("5000 spaces fit")
		}
	})
	t.Run("counts UTF-8 bytes", func(t *testing.T) {
		// Three bytes each: 3100 of them are over the limit though they are few characters.
		err := assertFits(fill(3100, "日"))
		if err == nil {
			t.Error("3100 characters fit")
		}
	})
	t.Run("says how big the line is", func(t *testing.T) {
		err := assertFits(fill(maxCommandLineBytes, "a"))
		var big *PayloadTooLargeError
		if !errors.As(err, &big) || big.Size != overhead+maxCommandLineBytes ||
			!strings.Contains(err.Error(), "respondjoinstreamrequest") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestHasAudioSection(t *testing.T) {
	for in, want := range map[string]bool{
		"m=audio 9 X 111":                          true,
		"v=0\r\nm=video 9 X\r\nm=audio\t9 X 1\r\n": true,
		"v=0\r\nm=video 9 X 96\r\n":                false,
		"a=m=audio 9":                              false,
		" m=audio 9":                               false,
		"m=audiox 9":                               false,
		"":                                         false,
	} {
		if got := hasAudioSection(in); got != want {
			t.Errorf("hasAudioSection(%q) = %v", in, got)
		}
	}
}

func TestErrors_Messages(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{
			&UnsupportedError{Family: "ts3", Version: "3.13.8"},
			"stream: streams need a server that names STREAM_P2P among its extensions" +
				"; this is ts3 (3.13.8), which names none",
		},
		{
			&UnsupportedError{Family: "ts6", Version: "6.0.0", Extensions: []string{"FILETIME"}},
			"stream: streams need a server that names STREAM_P2P among its extensions" +
				"; this is ts6 (6.0.0), which names FILETIME",
		},
		{
			&UnsupportedError{},
			"stream: streams need a server that names STREAM_P2P among its extensions" +
				"; this is an unknown server, which names none",
		},
		{&JoinDeniedError{StreamID: "a", Message: "no"}, "stream: the stream's owner denied the request to watch it: no"},
		{&JoinDeniedError{StreamID: "a"}, "stream: the stream's owner denied the request to watch it"},
		{&PayloadTooLargeError{Command: "x", Size: 9, Limit: 5}, "stream: x is 9 bytes escaped; the server takes at most 5"},
		{&EndedError{StreamID: "a"}, "stream: stream a has ended, or is not known"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("message = %q, want %q", got, tc.want)
		}
	}
}

func TestEndCause_Strings(t *testing.T) {
	for c, want := range map[EndCause]string{
		EndCauseStopped: "stopped", EndCauseServer: "server", EndCauseGone: "gone",
		EndCauseDisconnected: "disconnected", EndCauseShutdown: "shutdown", 0: "EndCause(0)", 99: "EndCause(99)",
	} {
		if got := c.String(); got != want {
			t.Errorf("EndCause(%d) = %q, want %q", uint8(c), got, want)
		}
	}
}

func TestPeerCause_Strings(t *testing.T) {
	for c, want := range map[PeerCause]string{
		PeerCauseClosed: "closed", PeerCauseLeft: "left", PeerCauseStopped: "stopped",
		PeerCauseDisconnected: "disconnected", PeerCauseShutdown: "shutdown", 0: "PeerCause(0)", 99: "PeerCause(99)",
	} {
		if got := c.String(); got != want {
			t.Errorf("PeerCause(%d) = %q, want %q", uint8(c), got, want)
		}
	}
}

// A peer closes with the cause of the stream that ended under it.
func TestEndCause_PeerCause(t *testing.T) {
	for c, want := range map[EndCause]PeerCause{
		EndCauseStopped: PeerCauseStopped, EndCauseServer: PeerCauseStopped, EndCauseGone: PeerCauseStopped,
		EndCauseDisconnected: PeerCauseDisconnected, EndCauseShutdown: PeerCauseShutdown,
	} {
		if got := c.peer(); got != want {
			t.Errorf("%v.peer() = %v, want %v", c, got, want)
		}
	}
}

func TestRequestState_Strings(t *testing.T) {
	for s, want := range map[RequestState]string{
		RequestPending: "pending", RequestAccepted: "accepted", RequestDenied: "denied", RequestFailed: "failed",
		RequestWithdrawn: "withdrawn", RequestEnded: "ended", 9: "RequestState(9)",
	} {
		if got := s.String(); got != want {
			t.Errorf("RequestState(%d) = %q, want %q", uint8(s), got, want)
		}
	}
}

func TestWireNumber_ReadsAnUnsigned32BitNumberAndNothingElse(t *testing.T) {
	for raw, want := range map[string]*uint32{
		"0": new(uint32(0)), "2": new(uint32(2)), "4294967295": new(uint32(4294967295)),
		"4294967296": nil, "-1": nil, "x": nil, "": nil, "1.5": nil, "1234567890123456": nil,
	} {
		got := wireNumber(map[string]string{"type": raw}, "type")
		if !ptrEqual(got, want) {
			t.Errorf("%q: got %v, want %v", raw, got, want)
		}
	}
	if wireNumber(map[string]string{}, "type") != nil {
		t.Error("an absent key reads as a number")
	}
}

func TestIntField_ReadsASignedIntegerOfAtMost15Digits(t *testing.T) {
	for raw, want := range map[string]*int{
		"0": new(0), "-3": new(-3), "999999999999999": new(999999999999999),
		"1000000000000000": nil, "-": nil, "": nil, "1e3": nil,
	} {
		got := intField(map[string]string{"k": raw}, "k")
		if !ptrEqual(got, want) {
			t.Errorf("%q: got %v, want %v", raw, got, want)
		}
	}
}
