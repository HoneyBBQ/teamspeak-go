package stream

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/notify"
)

// FuzzParseSignal feeds the signalling parser what a stranger could relay. It
// must not panic, must hand over text it cannot read as a raw signal with its
// text, and every candidate it reads must survive being written and read again.
func FuzzParseSignal(f *testing.F) {
	for _, seed := range []string{
		`{"cmd":"answer","args":{"answer":"v=0\r\n"}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}`,
		`{"cmd":"iceCandidate","args":{"sdp":"c","mLine":99999}}`,
		`{"cmd":"offer","args":"sdp"}`,
		`{"cmd":"reconnectOffer","args":{"sdp":"sdp"}}`,
		`{"cmd":"mute","args":{"on":true}}`,
		`{"cmd":7}`, `[1,2]`, `null`, `"text"`, ``, `{`, `{"cmd":"answer","cmd":"offer"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		got := parseSignal(text)
		switch got.kind {
		case signalRaw:
			if got.raw.JSON != text {
				t.Fatalf("raw signal lost its text: %q", got.raw.JSON)
			}
			if got.raw.Args != nil && !json.Valid(got.raw.Args) {
				t.Fatalf("raw args are not JSON: %q", got.raw.Args)
			}
		case signalCandidate:
			if !utf8.ValidString(got.candidate.Candidate) {
				return // invalid UTF-8 is replaced when written, so it cannot round-trip
			}
			again := parseSignal(candidateJSON(got.candidate))
			if again.kind != signalCandidate || again.candidate.Candidate != got.candidate.Candidate ||
				!ptrEqual(again.candidate.SDPMid, got.candidate.SDPMid) ||
				!ptrEqual(again.candidate.SDPMLineIndex, got.candidate.SDPMLineIndex) {
				if got.candidate.SDPMid == nil || utf8.ValidString(*got.candidate.SDPMid) {
					t.Fatalf("candidate %+v came back as %+v", got.candidate, again)
				}
			}
		case signalOffer, signalAnswer:
			if !utf8.ValidString(got.sdp) {
				return
			}
			var again signal
			if got.kind == signalOffer {
				again = parseSignal(offerJSON(got.sdp))
			} else {
				again = parseSignal(answerJSON(got.sdp))
			}
			if again.kind != got.kind || again.sdp != got.sdp {
				t.Fatalf("%q came back as %q", got.sdp, again.sdp)
			}
		}
	})
}

// FuzzInfoFrom reads rows of any shape without panicking, and merging a row over
// what is known leaves the known value alone.
func FuzzInfoFrom(f *testing.F) {
	f.Add("a", "5", "Demo", "2", "1", "58208", "0", "1", "2")
	f.Add("", "", "", "", "", "", "", "", "")
	f.Add("a", "99999", "", "-1", "x", "99999999999999999999", "-", "0", "")
	f.Fuzz(func(t *testing.T, id, clid, name, typ, access, bitrate, limit, audio, viewer string) {
		params := map[string]string{
			"id": id, "clid": clid, "name": name, "type": typ, "access": access,
			"bitrate": bitrate, "viewer_limit": limit, "audio": audio, "viewer": viewer,
		}
		info, ok := infoFrom(params, nil)
		if ok != (id != "") {
			t.Fatalf("ok = %v for id %q", ok, id)
		}
		if !ok {
			return
		}
		again, _ := infoFrom(params, &info)
		if !again.equal(info) {
			t.Fatalf("reading the same row twice changed it: %+v then %+v", info, again)
		}
		sparse, _ := infoFrom(map[string]string{"id": id}, &info)
		if !sparse.equal(info) {
			t.Fatalf("a bare row changed what was known: %+v then %+v", info, sparse)
		}
		copied := info.clone()
		if copied.Bitrate != nil {
			*copied.Bitrate++
			if info.Bitrate != nil && *info.Bitrate == *copied.Bitrate {
				t.Fatal("clone shares memory")
			}
		}
	})
}

// FuzzAssertFits errors exactly when the escaped line is over the limit.
func FuzzAssertFits(f *testing.F) {
	f.Add("", 0)
	f.Add(" ", 9000)
	f.Add("日", 3050)
	f.Add("a|b", 3000)
	f.Fuzz(func(t *testing.T, unit string, n int) {
		if n < 0 || n > 20000 || len(unit) > 64 {
			return
		}
		req := respondRequest("id", 2, "", strings.Repeat(unit, n), true)
		size := len(encoded(req))
		err := assertFits(req)
		if (err != nil) != (size > MaxCommandLineBytes) {
			t.Fatalf("size %d, err %v", size, err)
		}
		big, ok := errors.AsType[*PayloadTooLargeError](err)
		if ok && (big.Size != size || big.Limit != MaxCommandLineBytes) {
			t.Fatalf("error %+v for size %d", big, size)
		}
	})
}

// FuzzNotifications plays a stream of notifications and client events, from a
// script of bytes, at a Streams that also publishes. Nothing may panic, no
// stopstream may name a stream this Streams did not start, and when it has been
// closed no goroutine may be left, which the bubble checks.
func FuzzNotifications(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
	f.Add([]byte{12, 0, 0, 12, 1, 2, 5, 0, 1, 6, 0, 1, 9, 1, 3, 255})
	f.Add([]byte{13, 3, 13, 7, 4, 2, 4, 2, 8, 0, 14, 1})
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 400 {
			script = script[:400]
		}
		synctest.Test(t, func(t *testing.T) { playScript(t, script) })
	})
}

var fuzzSignals = []string{`{"cmd":"answer","args":{"answer":"x"}}`, `{"cmd":"iceCandidate","args":{"sdp":"c"}}`, "?"}

var fuzzIDs = []string{"a", "b", "c", "mine-1", "mine-2"}

func playScript(t *testing.T, script []byte) {
	h := newFakeHost()
	s := newStreams(h, Options{RememberDenied: true})
	e := &env{t: t, h: h, s: s}
	mine := map[string]bool{}
	next := func() int {
		if len(script) == 0 {
			return 0
		}
		b := script[0]
		script = script[1:]

		return int(b)
	}
	pick := func() map[string]string {
		id := fuzzIDs[next()%len(fuzzIDs)]
		clid := strconv.Itoa(next() % 12)
		h.see(1+teamspeak.ClientID(next()%11), nil)

		return map[string]string{
			"id": id, "clid": clid, "name": "n", "type": strconv.Itoa(next() % 6), "decision": strconv.Itoa(next() % 2),
			"offer": []string{"", sdp}[next()%2], "is_remove": strconv.Itoa(next() % 2), "reason": strconv.Itoa(next()),
			"json":   fuzzSignals[next()%len(fuzzSignals)],
			"viewer": strconv.Itoa(next() % 4),
		}
	}
	names := []string{
		notify.StreamStarted, notify.StreamInfo, notify.StreamStopped, notify.JoinStreamRequest,
		notify.RespondJoinStreamRequest, notify.StreamSignaling, notify.StreamClientJoined, notify.StreamClientLeft,
	}
	var requests collector[*JoinRequest]
	s.OnError(func(error) {})
	for len(script) > 0 {
		switch op := next() % 16; {
		case op < 8:
			h.notify(names[op], pick())
		case op == 8:
			h.enter(teamspeak.ClientID(1+next()%11), new(next()%2 == 0))
		case op == 9:
			h.setStreaming(teamspeak.ClientID(1+next()%11), next()%2 == 0)
		case op == 10:
			h.leave(teamspeak.ClientID(1 + next()%11))
		case op == 11:
			time.Sleep(time.Duration(next()) * 20 * time.Millisecond)
		case op == 12:
			publishInScript(e, mine, fuzzIDs[3+next()%2], &requests)
		case op == 13:
			p := pick()
			go func() { _, _ = s.Watch(t.Context(), ID(p["id"]), WatchOptions{}) }()
		case op == 14:
			for _, r := range requests.all() {
				if next()%2 == 0 {
					_, _ = r.Accept(t.Context(), sdp, "")
				} else {
					_ = r.Deny(t.Context(), "")
				}
			}
		default:
			if next()%4 == 0 {
				h.disconnect()
				h.connect()
			}
		}
		synctest.Wait()
	}
	_ = s.Close(t.Context())
	time.Sleep(time.Minute)
	for _, stop := range h.commands("stopstream") {
		if id := stop.params["id"]; !mine[id] {
			t.Fatalf("stopstream for %q, which this Streams did not start", id)
		}
	}
}

// publishInScript starts a publish and announces it as stream id.
func publishInScript(e *env, mine map[string]bool, id string, requests *collector[*JoinRequest]) {
	ctx, cancel := context.WithTimeout(e.t.Context(), 3*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		p, err := e.s.Publish(ctx, PublishOptions{Name: "n"})
		if err == nil {
			p.OnRequest(requests.add)
		}
	}()
	synctest.Wait()
	if e.h.pendingSetups() > 0 {
		mine[id] = true
		e.h.announce(e.t, announcement(id, 1), 0)
	}
}
