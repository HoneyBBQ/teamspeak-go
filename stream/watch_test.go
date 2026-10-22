package stream

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/notify"
)

type watchResult struct {
	view *View
	err  error
}

// startWatch calls Watch in the background and lets it send its request.
func (e *env) startWatch(ctx context.Context, id ID) chan watchResult {
	done := make(chan watchResult, 1)
	go func() {
		v, err := e.s.Watch(ctx, id, WatchOptions{Message: "pair"})
		done <- watchResult{v, err}
	}()
	e.settle()

	return done
}

// streamOf5 makes stream "a" of client 5 known.
func (e *env) streamOf5() {
	e.h.notify(notify.StreamStarted, announcement("a", 5))
	e.settle()
}

func (e *env) respond(params map[string]string) {
	p := map[string]string{"id": "a", "clid": "5", "decision": "1", "offer": sdp, "msg": ""}
	for k, v := range params {
		p[k] = v
	}
	e.h.notify(notify.RespondJoinStreamRequest, p)
}

func (e *env) watchAccepted() *View {
	e.t.Helper()
	e.streamOf5()
	done := e.startWatch(e.t.Context(), "a")
	e.respond(nil)
	r := <-done
	if r.err != nil {
		e.t.Fatalf("Watch: %v", r.err)
	}

	return r.view
}

func TestWatch(t *testing.T) {
	t.Run("asks, and resolves with the offer when the publisher accepts", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			join := e.h.commands("joinstreamrequest")
			if len(join) != 1 || join[0].line != "joinstreamrequest id=a clid=5 msg=pair is_remove=0" {
				t.Fatalf("sent %v", join)
			}
			e.respond(nil)
			r := <-done
			if r.err != nil || r.view.Offer() != sdp || r.view.StreamID() != "a" || r.view.ClientID() != 5 || r.view.Closed() {
				t.Errorf("view = %+v, err %v", r.view, r.err)
			}
		})
	})
	t.Run("takes an Info for a stream it has not heard of", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan watchResult, 1)
			go func() {
				v, err := e.s.WatchInfo(t.Context(), Info{ID: "a", ClientID: 5}, WatchOptions{})
				done <- watchResult{v, err}
			}()
			e.settle()
			e.respond(nil)
			if r := <-done; r.err != nil || r.view.Offer() != sdp {
				t.Errorf("err = %v", r.err)
			}
		})
	})
	t.Run("rejects an id it knows nothing of, without sending", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			_, err := e.s.Watch(t.Context(), "nope", WatchOptions{})
			var ended *EndedError
			if !errors.As(err, &ended) || ended.StreamID != "nope" || e.h.count() != 0 {
				t.Errorf("err = %v, sent %d", err, e.h.count())
			}
		})
	})
	t.Run("rejects with the publishers message when it denies", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			e.respond(map[string]string{"decision": "0", "offer": "", "msg": "not you"})
			r := <-done
			var denied *JoinDeniedError
			if !errors.As(r.err, &denied) || denied.StreamID != "a" || denied.Message != "not you" || !strings.Contains(r.err.Error(), "not you") {
				t.Errorf("err = %v", r.err)
			}
			if len(e.h.commands("joinstreamrequest")) != 1 {
				t.Error("withdrew a request that was answered")
			}
			// Asking again is allowed once denied.
			done = e.startWatch(t.Context(), "a")
			e.respond(nil)
			if r := <-done; r.err != nil {
				t.Errorf("asking again: %v", r.err)
			}
		})
	})
	t.Run("rejects an acceptance without an offer, and withdraws", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			e.respond(map[string]string{"offer": ""})
			if r := <-done; r.err == nil || !strings.Contains(r.err.Error(), "without an offer") {
				t.Errorf("err = %v", r.err)
			}
			e.settle()
			join := e.h.commands("joinstreamrequest")
			if len(join) != 2 || join[1].params["is_remove"] != "1" {
				t.Errorf("sent %v", join)
			}
		})
	})
	t.Run("surfaces 5638 as the servers error, and 5635 as a stream that ended", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.StreamAlreadyJoined), s.name == "joinstreamrequest"
			}
			_, err := e.s.Watch(t.Context(), "a", WatchOptions{})
			var se *teamspeak.ServerError
			var ended *EndedError
			if !errors.Is(err, errcode.StreamAlreadyJoined) || !errors.As(err, &se) || errors.As(err, &ended) {
				t.Errorf("5638: err = %v", err)
			}
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.StreamNotFound), s.name == "joinstreamrequest"
			}
			_, err = e.s.Watch(t.Context(), "a", WatchOptions{})
			if !errors.As(err, &ended) || !errors.Is(err, errcode.StreamNotFound) || ended.StreamID != "a" {
				t.Errorf("5635: err = %v", err)
			}
			// Neither left a request behind.
			if _, err := e.s.Watch(t.Context(), "a", WatchOptions{}); errors.Is(err, ErrAlreadyWatching) {
				t.Error("still watching after a refusal")
			}
		})
	})
	t.Run("rejects when the stream stops before the publisher answers", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			e.h.notify(notify.StreamStopped, map[string]string{"id": "a"})
			var ended *EndedError
			if r := <-done; !errors.As(r.err, &ended) {
				t.Errorf("err = %v", r.err)
			}
		})
	})
	t.Run("withdraws the request when the wait runs out", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			start := time.Now()
			done := e.startWatch(t.Context(), "a")
			r := <-done
			if !errors.Is(r.err, context.DeadlineExceeded) || time.Since(start) != 60*time.Second {
				t.Errorf("err = %v after %v", r.err, time.Since(start))
			}
			e.settle()
			join := e.h.commands("joinstreamrequest")
			if len(join) != 2 || join[1].params["is_remove"] != "1" || join[1].params["id"] != "a" {
				t.Errorf("sent %v", join)
			}
		})
	})
	t.Run("withdraws the request when the context is cancelled", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			ctx, cancel := context.WithCancel(t.Context())
			done := e.startWatch(ctx, "a")
			cancel()
			if r := <-done; !errors.Is(r.err, context.Canceled) {
				t.Errorf("err = %v", r.err)
			}
			e.settle()
			if join := e.h.commands("joinstreamrequest"); len(join) != 2 || join[1].params["is_remove"] != "1" {
				t.Errorf("sent %v", join)
			}
			// The withdrawal outlived the cancelled context.
			if errs := e.h.commands("joinstreamrequest"); len(errs) != 2 {
				t.Errorf("sent %v", errs)
			}
		})
	})
	t.Run("will not watch a stream twice", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			e.startWatch(t.Context(), "a")
			if _, err := e.s.Watch(t.Context(), "a", WatchOptions{}); !errors.Is(err, ErrAlreadyWatching) {
				t.Errorf("err = %v", err)
			}
			e.respond(nil)
			if _, err := e.s.Watch(t.Context(), "a", WatchOptions{}); !errors.Is(err, ErrAlreadyWatching) {
				t.Errorf("after accepting: err = %v", err)
			}
		})
	})
	t.Run("keeps what arrives with the offer, for the first handler", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			// Signalling that outruns the publisher's answer waits for the view.
			e.h.notify(notify.StreamSignaling, map[string]string{"id": "a", "clid": "5", "json": `{"cmd":"iceCandidate","args":{"sdp":"early"}}`})
			e.respond(nil)
			e.h.notify(notify.StreamSignaling, map[string]string{"id": "a", "clid": "5", "json": `{"cmd":"iceCandidate","args":{"sdp":"late"}}`})
			v := (<-done).view
			var cands collector[IceCandidate]
			v.OnCandidate(cands.add)
			e.settle()
			if got := cands.all(); len(got) != 2 || got[0].Candidate != "early" || got[1].Candidate != "late" {
				t.Errorf("candidates = %+v", got)
			}
		})
	})
	t.Run("sends the answer and candidates to the publisher", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			if err := v.Answer(t.Context(), "v=0\r\nanswer"); err != nil {
				t.Fatal(err)
			}
			if err := v.SendCandidate(t.Context(), IceCandidate{Candidate: "c1", SDPMid: ptr("0"), SDPMLineIndex: ptr(uint16(0))}); err != nil {
				t.Fatal(err)
			}
			sigs := e.h.commands("streamsignaling")
			if len(sigs) != 2 || sigs[0].params["clid"] != "5" || sigs[0].params["id"] != "a" ||
				sigs[0].params["json"] != `{"cmd":"answer","args":{"answer":"v=0\r\nanswer"}}` ||
				sigs[1].params["json"] != `{"cmd":"iceCandidate","args":{"sdp":"c1","mid":"0","mLine":0}}` {
				t.Errorf("sent %v", sigs)
			}
		})
	})
	t.Run("delivers a renegotiation offer", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			var offers collector[string]
			v.OnOffer(offers.add)
			e.h.notify(notify.StreamSignaling, map[string]string{"id": "a", "clid": "5", "json": `{"cmd":"offer","args":{"offer":"v=1"}}`})
			e.settle()
			if got := offers.all(); len(got) != 1 || got[0] != "v=1" {
				t.Errorf("offers = %v", got)
			}
		})
	})
	t.Run("leaves with is_remove, once", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			var closed collector[PeerClosed]
			v.OnClosed(closed.add)
			if err := v.Leave(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := v.Leave(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.settle()
			join := e.h.commands("joinstreamrequest")
			if len(join) != 2 || join[1].line != "joinstreamrequest id=a clid=5 msg= is_remove=1" {
				t.Errorf("sent %v", join)
			}
			if got := closed.all(); len(got) != 1 || got[0].Cause != CauseClosed || !v.Closed() {
				t.Errorf("closed = %+v", got)
			}
			// The stream can be watched again.
			done := e.startWatch(t.Context(), "a")
			e.respond(nil)
			if r := <-done; r.err != nil {
				t.Errorf("watching again: %v", r.err)
			}
		})
	})
	t.Run("leaves quietly when the stream is gone or the connection is", func(t *testing.T) {
		for name, err := range map[string]error{
			"stream gone":   serverError(errcode.StreamNotFound),
			"not connected": teamspeak.ErrNotConnected,
		} {
			t.Run(name, func(t *testing.T) {
				run(t, func(t *testing.T, e *env) {
					v := e.watchAccepted()
					e.h.reply = func(s sent) ([]map[string]string, error, bool) { return nil, err, s.name == "joinstreamrequest" }
					if got := v.Leave(t.Context()); got != nil {
						t.Errorf("Leave = %v", got)
					}
				})
			})
		}
	})
	t.Run("raises any other failure to leave", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "joinstreamrequest"
			}
			if err := v.Leave(t.Context()); !errors.Is(err, errcode.PermissionsClientInsufficient) {
				t.Errorf("Leave = %v", err)
			}
			if !v.Closed() {
				t.Error("the view is still open")
			}
		})
	})
	t.Run("stays when another viewer leaves, and closes when it is itself the one", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			var closed collector[PeerClosed]
			v.OnClosed(closed.add)
			e.h.notify(notify.StreamClientLeft, map[string]string{"id": "a", "clid": "9"})
			e.settle()
			if v.Closed() {
				t.Fatal("closed for another viewer")
			}
			e.h.notify(notify.StreamClientLeft, map[string]string{"id": "a", "clid": "1"})
			e.settle()
			if got := closed.all(); len(got) != 1 || got[0].Cause != CauseLeft {
				t.Errorf("closed = %+v", got)
			}
		})
	})
	t.Run("closes with the reason when the stream stops", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			var closed collector[PeerClosed]
			v.OnClosed(closed.add)
			e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "4"})
			e.settle()
			if got := closed.all(); len(got) != 1 || got[0] != (PeerClosed{Cause: CauseStopped, Reason: 4}) {
				t.Errorf("closed = %+v", got)
			}
		})
	})
	t.Run("stays when the publisher changes channel or leaves view", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			v := e.watchAccepted()
			e.h.leave(5)
			e.settle()
			if v.Closed() {
				t.Error("closed")
			}
		})
	})
	t.Run("reports signalling from a client it has no session with", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var errs collector[error]
			e.s.OnError(errs.add)
			e.h.notify(notify.StreamSignaling, map[string]string{"id": "zz", "clid": "5", "json": "{}"})
			e.settle()
			if got := errs.all(); len(got) != 1 || !strings.Contains(got[0].Error(), "no session") {
				t.Errorf("errors = %v", got)
			}
		})
	})
	t.Run("bounds the signalling before the answer, and reports it once", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			var errs collector[error]
			e.s.OnError(errs.add)
			done := e.startWatch(t.Context(), "a")
			for range maxKept + 5 {
				e.h.notify(notify.StreamSignaling, map[string]string{"id": "a", "clid": "5", "json": `{"cmd":"x"}`})
			}
			e.respond(nil)
			v := (<-done).view
			var raws collector[RawSignal]
			v.OnSignal(raws.add)
			e.settle()
			if errs.len() != 1 || raws.len() != maxKept {
				t.Errorf("errors %d, raw %d", errs.len(), raws.len())
			}
		})
	})
}

func TestCleanup(t *testing.T) {
	t.Run("ends every session once when the connection ends, and forgets what it knew", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			v := e.watchAccepted()
			var ended collector[Ended]
			var closedPeer, closedView collector[PeerClosed]
			p.OnEnded(ended.add)
			peer.OnClosed(closedPeer.add)
			v.OnClosed(closedView.add)
			before := e.h.count()
			e.h.disconnect()
			e.h.disconnect()
			e.settle()
			if got := ended.all(); len(got) != 1 || got[0] != (Ended{Cause: CauseDisconnected}) {
				t.Errorf("ended = %+v", got)
			}
			if closedPeer.len() != 1 || closedPeer.all()[0].Cause != CauseDisconnected || closedView.len() != 1 || closedView.all()[0].Cause != CauseDisconnected {
				t.Errorf("peer %+v, view %+v", closedPeer.all(), closedView.all())
			}
			if len(e.s.List()) != 0 || e.h.count() != before {
				t.Errorf("List %+v, sent %d", e.s.List(), e.h.count()-before)
			}
		})
	})
	t.Run("rejects a watch pending at the end of the connection", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.streamOf5()
			done := e.startWatch(t.Context(), "a")
			e.h.disconnect()
			if r := <-done; !errors.Is(r.err, teamspeak.ErrNotConnected) {
				t.Errorf("err = %v", r.err)
			}
			e.settle()
			if got := len(e.h.commands("joinstreamrequest")); got != 1 {
				t.Errorf("sent %d, want no withdrawal over a dead connection", got)
			}
		})
	})
	t.Run("looks the streams up again after a reconnection", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.see(7, ptr(true)) }, func(t *testing.T, e *env) {
			e.settle()
			e.h.disconnect()
			e.h.connect()
			e.settle()
			if got := len(e.h.commands("requeststreaminfo")); got != 2 {
				t.Errorf("asked %d times, want 2", got)
			}
		})
	})
	t.Run("detaches and ends everything on Close, once", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var ended collector[Ended]
			var closed collector[PeerClosed]
			p.OnEnded(ended.add)
			peer.OnClosed(closed.add)
			if err := e.s.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := e.s.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.settle()
			if got := ended.all(); len(got) != 1 || got[0] != (Ended{Cause: CauseShutdown}) {
				t.Errorf("ended = %+v", got)
			}
			if got := closed.all(); len(got) != 1 || got[0].Cause != CauseShutdown {
				t.Errorf("closed = %+v", got)
			}
			for _, event := range []string{"notification", "enter", "updated", "leave", "connected", "disconnected"} {
				if n := e.h.listeners(event); n != 0 {
					t.Errorf("%d %s subscriptions left", n, event)
				}
			}
			if _, err := e.s.Publish(t.Context(), PublishOptions{}); !errors.Is(err, ErrClosed) {
				t.Errorf("Publish after Close: %v", err)
			}
			if _, err := e.s.Watch(t.Context(), "a", WatchOptions{}); !errors.Is(err, ErrClosed) {
				t.Errorf("Watch after Close: %v", err)
			}
		})
	})
	t.Run("tells the server on Close: stops what it published, leaves what it watched", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			e.watchAccepted()
			if err := e.s.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			stops := e.h.commands("stopstream")
			if len(stops) != 1 || stops[0].params["id"] != string(p.ID()) {
				t.Errorf("stops = %v", stops)
			}
			join := e.h.commands("joinstreamrequest")
			if len(join) != 2 || join[1].params["is_remove"] != "1" || join[1].params["id"] != "a" {
				t.Errorf("join = %v", join)
			}
		})
	})
	t.Run("returns the failures of the goodbye, joined", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.publish(PublishOptions{Name: "x"})
			e.watchAccepted()
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "stopstream" || s.name == "joinstreamrequest"
			}
			err := e.s.Close(t.Context())
			joined, ok := err.(interface{ Unwrap() []error })
			if !ok || len(joined.Unwrap()) != 2 || !errors.Is(err, errcode.PermissionsClientInsufficient) {
				t.Errorf("err = %v", err)
			}
		})
	})
	t.Run("does not count a stream or connection already gone as a failure", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.publish(PublishOptions{Name: "x"})
			e.watchAccepted()
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				if s.name == "stopstream" {
					return nil, serverError(errcode.StreamNotFound), true
				}

				return nil, teamspeak.ErrNotConnected, s.name == "joinstreamrequest"
			}
			if err := e.s.Close(t.Context()); err != nil {
				t.Errorf("err = %v", err)
			}
		})
	})
	t.Run("waits for the goodbye within its context", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.publish(PublishOptions{Name: "x"})
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				if s.name == "stopstream" {
					time.Sleep(3 * time.Second)
				}

				return nil, nil, false
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			start := time.Now()
			err := e.s.Close(ctx)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
				t.Errorf("err = %v after %v", err, time.Since(start))
			}
		})
	})
	t.Run("sends nothing on Close when the connection is gone", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.publish(PublishOptions{Name: "x"})
			e.h.disconnect()
			before := e.h.count()
			if err := e.s.Close(t.Context()); err != nil || e.h.count() != before {
				t.Errorf("err %v, sent %d", err, e.h.count()-before)
			}
		})
	})
	t.Run("clears the remembered denials on Close", func(t *testing.T) {
		runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if err := reqs.all()[0].Deny(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			e.s.mu.Lock()
			remembered := e.s.denied.has("uid-9")
			e.s.mu.Unlock()
			if !remembered {
				t.Fatal("not remembered")
			}
			_ = e.s.Close(t.Context())
			e.s.mu.Lock()
			defer e.s.mu.Unlock()
			if e.s.denied.has("uid-9") {
				t.Error("still remembered")
			}
		})
	})
	t.Run("bounds the remembered denials to the most recent 1024", func(t *testing.T) {
		l := newLRU[teamspeak.UID](maxDenied)
		for i := range maxDenied + 10 {
			l.add(teamspeak.UID(time.Duration(i).String()))
		}
		l.add("0s")
		if l.has("1ns") || l.has("0s") != true || len(l.items) != maxDenied {
			t.Errorf("size %d, has 0s %v, has 1ns %v", len(l.items), l.has("0s"), l.has("1ns"))
		}
	})
}

func TestPublisherThatStopsStreaming(t *testing.T) {
	known := func(e *env) {
		e.h.enter(5, ptr(true))
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.settle()
	}
	t.Run("drops its streams, with the cause gone, once the flag has stayed clear for the grace", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var stopped collector[StoppedEvent]
			e.s.OnStopped(stopped.add)
			known(e)
			e.h.setStreaming(5, false)
			time.Sleep(goneGrace - time.Millisecond)
			e.settle()
			if stopped.len() != 0 {
				t.Fatal("ended before the grace")
			}
			time.Sleep(time.Millisecond)
			e.settle()
			if got := stopped.all(); len(got) != 1 || got[0].Cause != CauseGone || got[0].Reason != 0 || len(e.s.List()) != 0 {
				t.Errorf("stopped = %+v", got)
			}
		})
	})
	t.Run("lets the stop notification that follows the clear win, with its reason", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var stopped collector[StoppedEvent]
			e.s.OnStopped(stopped.add)
			known(e)
			e.h.setStreaming(5, false)
			e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "1"})
			time.Sleep(10 * time.Second)
			e.settle()
			if got := stopped.all(); len(got) != 1 || got[0].Cause != CauseServer || got[0].Reason != 1 {
				t.Errorf("stopped = %+v", got)
			}
		})
	})
	t.Run("cancels the end when the flag is set again within the grace", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			known(e)
			e.h.setStreaming(5, false)
			time.Sleep(time.Second)
			e.h.setStreaming(5, true)
			time.Sleep(10 * time.Second)
			e.settle()
			if len(e.s.List()) != 1 {
				t.Errorf("List = %+v", e.s.List())
			}
		})
	})
	t.Run("does not run the end after Close, and leaves no timer", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var stopped collector[StoppedEvent]
			e.s.OnStopped(stopped.add)
			known(e)
			e.h.setStreaming(5, false)
			_ = e.s.Close(t.Context())
			time.Sleep(10 * time.Second)
			e.settle()
			if stopped.len() != 0 {
				t.Errorf("stopped = %+v", stopped.all())
			}
		})
	})
	t.Run("leaves no timer when the connection ends", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var stopped collector[StoppedEvent]
			e.s.OnStopped(stopped.add)
			known(e)
			e.h.setStreaming(5, false)
			e.h.disconnect()
			time.Sleep(10 * time.Second)
			e.settle()
			if stopped.len() != 0 {
				t.Errorf("stopped = %+v", stopped.all())
			}
		})
	})
	t.Run("drops its streams after the grace when it comes into view not streaming", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.enter(5, ptr(false))
			time.Sleep(goneGrace)
			e.settle()
			if len(e.s.List()) != 0 {
				t.Errorf("List = %+v", e.s.List())
			}
		})
	})
	t.Run("keeps a stream when the flag says nothing, and the streams of others", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.notify(notify.StreamStarted, announcement("b", 6))
			e.h.enter(5, nil)
			e.h.setStreaming(6, true)
			e.h.setStreaming(5, false)
			e.h.setStreaming(7, false)
			time.Sleep(goneGrace)
			e.settle()
			if list := e.s.List(); len(list) != 1 || list[0].ID != "b" {
				t.Errorf("List = %+v", list)
			}
		})
	})
	t.Run("ends the viewers side of a stream that is gone, after the grace", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(5, ptr(true))
			v := e.watchAccepted()
			var closed collector[PeerClosed]
			v.OnClosed(closed.add)
			e.h.setStreaming(5, false)
			time.Sleep(goneGrace)
			e.settle()
			if got := closed.all(); len(got) != 1 || got[0] != (PeerClosed{Cause: CauseStopped}) {
				t.Errorf("closed = %+v", got)
			}
		})
	})
	t.Run("keeps the real reason for a viewer when the stop follows the clear", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(5, ptr(true))
			v := e.watchAccepted()
			var closed collector[PeerClosed]
			v.OnClosed(closed.add)
			e.h.setStreaming(5, false)
			e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "9"})
			time.Sleep(goneGrace)
			e.settle()
			if got := closed.all(); len(got) != 1 || got[0] != (PeerClosed{Cause: CauseStopped, Reason: 9}) {
				t.Errorf("closed = %+v", got)
			}
		})
	})
}
