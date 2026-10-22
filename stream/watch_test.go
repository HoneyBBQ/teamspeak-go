package stream

import (
	"context"
	"errors"
	"fmt"
	"maps"
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
func (e *env) startWatch(ctx context.Context) chan watchResult {
	done := make(chan watchResult, 1)
	go func() {
		v, err := e.s.Watch(ctx, "a", WatchOptions{Message: "pair"})
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

// fromFive is a signalling message of client 5 for stream "a".
func fromFive(json string) map[string]string {
	return map[string]string{"id": "a", "clid": "5", "json": json}
}

func (e *env) respond(params map[string]string) {
	p := map[string]string{"id": "a", "clid": "5", "decision": "1", "offer": sdp, "msg": ""}
	maps.Copy(p, params)
	e.h.notify(notify.RespondJoinStreamRequest, p)
}

func (e *env) watchAccepted() *View {
	e.t.Helper()
	e.streamOf5()
	done := e.startWatch(e.t.Context())
	e.respond(nil)
	r := <-done
	if r.err != nil {
		e.t.Fatalf("Watch: %v", r.err)
	}

	return r.view
}

func TestWatch_AsksAndResolvesWithTheOfferWhenThePublisherAccepts(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
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
}

func TestWatch_TakesAnInfoForAStreamItHasNotHeardOf(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		done := make(chan watchResult, 1)
		go func() {
			v, err := e.s.Watch(t.Context(), "a", WatchOptions{ClientID: 5})
			done <- watchResult{v, err}
		}()
		e.settle()
		e.respond(nil)
		if r := <-done; r.err != nil || r.view.Offer() != sdp {
			t.Errorf("err = %v", r.err)
		}
	})
}

func TestWatch_RejectsAnIdItKnowsNothingOfWithoutSending(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		_, err := e.s.Watch(t.Context(), "nope", WatchOptions{})
		var ended *EndedError
		if !errors.As(err, &ended) || ended.StreamID != "nope" || e.h.count() != 0 {
			t.Errorf("err = %v, sent %d", err, e.h.count())
		}
	})
}

func TestWatch_RejectsWithThePublishersMessageWhenItDenies(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
		e.respond(map[string]string{"decision": "0", "offer": "", "msg": "not you"})
		r := <-done
		var denied *JoinDeniedError
		if !errors.As(r.err, &denied) || denied.StreamID != "a" || denied.Message != "not you" {
			t.Errorf("err = %#v", r.err)
		}
		if !strings.Contains(r.err.Error(), "not you") {
			t.Errorf("message = %q", r.err)
		}
		if len(e.h.commands("joinstreamrequest")) != 1 {
			t.Error("withdrew a request that was answered")
		}
		// Asking again is allowed once denied.
		done = e.startWatch(t.Context())
		e.respond(nil)
		if r := <-done; r.err != nil {
			t.Errorf("asking again: %v", r.err)
		}
	})
}

func TestWatch_RejectsAnAcceptanceWithoutAnOfferAndWithdraws(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
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
}

func TestWatch_Surfaces5638AsTheServersErrorAnd5635AsAStreamThatEnded(t *testing.T) {
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
		_, err = e.s.Watch(t.Context(), "a", WatchOptions{})
		if errors.Is(err, ErrAlreadyWatching) {
			t.Error("still watching after a refusal")
		}
	})
}

func TestWatch_RejectsWhenTheStreamStopsBeforeThePublisherAnswers(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
		e.h.notify(notify.StreamStopped, map[string]string{"id": "a"})
		var ended *EndedError
		if r := <-done; !errors.As(r.err, &ended) {
			t.Errorf("err = %v", r.err)
		}
	})
}

func TestWatch_WithdrawsTheRequestWhenTheWaitRunsOut(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		start := time.Now()
		done := e.startWatch(t.Context())
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
}

func TestWatch_WithdrawsTheRequestWhenTheContextIsCancelled(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		ctx, cancel := context.WithCancel(t.Context())
		done := e.startWatch(ctx)
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
}

func TestWatch_WillNotWatchAStreamTwice(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		e.startWatch(t.Context())
		_, err := e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.Is(err, ErrAlreadyWatching) {
			t.Errorf("err = %v", err)
		}
		e.respond(nil)
		_, err = e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.Is(err, ErrAlreadyWatching) {
			t.Errorf("after accepting: err = %v", err)
		}
	})
}

func TestWatch_KeepsWhatArrivesWithTheOfferForTheFirstHandler(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
		// Signalling that outruns the publisher's answer waits for the view.
		e.h.notify(notify.StreamSignaling, fromFive(`{"cmd":"iceCandidate","args":{"sdp":"early"}}`))
		e.respond(nil)
		e.h.notify(notify.StreamSignaling, fromFive(`{"cmd":"iceCandidate","args":{"sdp":"late"}}`))
		v := (<-done).view
		var cands collector[IceCandidate]
		v.OnCandidate(cands.add)
		e.settle()
		if got := cands.all(); len(got) != 2 || got[0].Candidate != "early" || got[1].Candidate != "late" {
			t.Errorf("candidates = %+v", got)
		}
	})
}

func TestWatch_SendsTheAnswerAndCandidatesToThePublisher(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		err := v.Answer(t.Context(), "v=0\r\nanswer")
		if err != nil {
			t.Fatal(err)
		}
		err = v.SendCandidate(t.Context(), IceCandidate{Candidate: "c1", SDPMid: new("0"), SDPMLineIndex: new(uint16(0))})
		if err != nil {
			t.Fatal(err)
		}
		sigs := e.h.commands("streamsignaling")
		if len(sigs) != 2 || sigs[0].params["clid"] != "5" || sigs[0].params["id"] != "a" ||
			sigs[0].params["json"] != `{"cmd":"answer","args":{"answer":"v=0\r\nanswer"}}` ||
			sigs[1].params["json"] != `{"cmd":"iceCandidate","args":{"sdp":"c1","mid":"0","mLine":0}}` {
			t.Errorf("sent %v", sigs)
		}
	})
}

func TestWatch_DeliversARenegotiationOffer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		var offers collector[string]
		v.OnOffer(offers.add)
		e.h.notify(notify.StreamSignaling, fromFive(`{"cmd":"offer","args":{"offer":"v=1"}}`))
		e.settle()
		if got := offers.all(); len(got) != 1 || got[0] != "v=1" {
			t.Errorf("offers = %v", got)
		}
	})
}

func TestWatch_LeavesWithIsRemoveOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		var closed collector[PeerClosedEvent]
		v.OnClosed(closed.add)
		err := v.Leave(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		err = v.Leave(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		join := e.h.commands("joinstreamrequest")
		if len(join) != 2 || join[1].line != "joinstreamrequest id=a clid=5 msg= is_remove=1" {
			t.Errorf("sent %v", join)
		}
		if got := closed.all(); len(got) != 1 || got[0].Cause != PeerCauseClosed || !v.Closed() {
			t.Errorf("closed = %+v", got)
		}
		// The stream can be watched again.
		done := e.startWatch(t.Context())
		e.respond(nil)
		if r := <-done; r.err != nil {
			t.Errorf("watching again: %v", r.err)
		}
	})
}

func TestWatch_LeavesQuietlyWhenTheStreamIsGoneOrTheConnectionIs(t *testing.T) {
	for name, err := range map[string]error{
		"stream gone":   serverError(errcode.StreamNotFound),
		"not connected": teamspeak.ErrNotConnected,
	} {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, e *env) {
				v := e.watchAccepted()
				e.h.reply = func(s sent) ([]map[string]string, error, bool) { return nil, err, s.name == "joinstreamrequest" }
				got := v.Leave(t.Context())
				if got != nil {
					t.Errorf("Leave = %v", got)
				}
			})
		})
	}
}

func TestWatch_RaisesAnyOtherFailureToLeave(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "joinstreamrequest"
		}
		err := v.Leave(t.Context())
		if !errors.Is(err, errcode.PermissionsClientInsufficient) {
			t.Errorf("Leave = %v", err)
		}
		if !v.Closed() {
			t.Error("the view is still open")
		}
	})
}

func TestWatch_StaysWhenAnotherViewerLeavesAndClosesWhenItIsItselfTheOne(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		var closed collector[PeerClosedEvent]
		v.OnClosed(closed.add)
		e.h.notify(notify.StreamClientLeft, map[string]string{"id": "a", "clid": "9"})
		e.settle()
		if v.Closed() {
			t.Fatal("closed for another viewer")
		}
		e.h.notify(notify.StreamClientLeft, map[string]string{"id": "a", "clid": "1"})
		e.settle()
		if got := closed.all(); len(got) != 1 || got[0].Cause != PeerCauseLeft {
			t.Errorf("closed = %+v", got)
		}
	})
}

func TestWatch_ClosesWithTheReasonWhenTheStreamStops(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		var closed collector[PeerClosedEvent]
		v.OnClosed(closed.add)
		e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "4"})
		e.settle()
		if got := closed.all(); len(got) != 1 || got[0] != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 4}) {
			t.Errorf("closed = %+v", got)
		}
	})
}

func TestWatch_StaysWhenThePublisherChangesChannelOrLeavesView(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		e.h.leave(5)
		e.settle()
		if v.Closed() {
			t.Error("closed")
		}
	})
}

func TestWatch_ReportsSignallingFromAClientItHasNoSessionWith(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var errs collector[error]
		e.s.OnError(errs.add)
		e.h.notify(notify.StreamSignaling, map[string]string{"id": "zz", "clid": "5", "json": "{}"})
		e.settle()
		if got := errs.all(); len(got) != 1 || !strings.Contains(got[0].Error(), "no session") {
			t.Errorf("errors = %v", got)
		}
	})
}

func TestWatch_BoundsTheSignallingBeforeTheAnswerAndReportsItOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		var errs collector[error]
		e.s.OnError(errs.add)
		done := e.startWatch(t.Context())
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
}

func TestCleanup_EndsEverySessionOnceWhenTheConnectionEndsAndForgetsWhatItKnew(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		v := e.watchAccepted()
		var ended collector[EndedEvent]
		var closedPeer, closedView collector[PeerClosedEvent]
		p.OnEnded(ended.add)
		peer.OnClosed(closedPeer.add)
		v.OnClosed(closedView.add)
		before := e.h.count()
		e.h.disconnect()
		e.h.disconnect()
		e.settle()
		if got := ended.all(); len(got) != 1 || got[0] != (EndedEvent{Cause: EndCauseDisconnected}) {
			t.Errorf("ended = %+v", got)
		}
		if closedPeer.len() != 1 || closedPeer.all()[0].Cause != PeerCauseDisconnected {
			t.Errorf("peer %+v", closedPeer.all())
		}
		if closedView.len() != 1 || closedView.all()[0].Cause != PeerCauseDisconnected {
			t.Errorf("view %+v", closedView.all())
		}
		if len(e.s.List()) != 0 || e.h.count() != before {
			t.Errorf("List %+v, sent %d", e.s.List(), e.h.count()-before)
		}
	})
}

func TestCleanup_RejectsAWatchPendingAtTheEndOfTheConnection(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		done := e.startWatch(t.Context())
		e.h.disconnect()
		if r := <-done; !errors.Is(r.err, teamspeak.ErrNotConnected) {
			t.Errorf("err = %v", r.err)
		}
		e.settle()
		if got := len(e.h.commands("joinstreamrequest")); got != 1 {
			t.Errorf("sent %d, want no withdrawal over a dead connection", got)
		}
	})
}

func TestCleanup_LooksTheStreamsUpAgainAfterAReconnection(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) { h.see(7, new(true)) }, func(t *testing.T, e *env) {
		e.settle()
		e.h.disconnect()
		e.h.connect()
		e.settle()
		if got := len(e.h.commands("requeststreaminfo")); got != 2 {
			t.Errorf("asked %d times, want 2", got)
		}
	})
}

func TestCleanup_DetachesAndEndsEverythingOnCloseOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var ended collector[EndedEvent]
		var closed collector[PeerClosedEvent]
		p.OnEnded(ended.add)
		peer.OnClosed(closed.add)
		err := e.s.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		err = e.s.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		if got := ended.all(); len(got) != 1 || got[0] != (EndedEvent{Cause: EndCauseShutdown}) {
			t.Errorf("ended = %+v", got)
		}
		if got := closed.all(); len(got) != 1 || got[0].Cause != PeerCauseShutdown {
			t.Errorf("closed = %+v", got)
		}
		for _, event := range []string{"notification", "enter", "updated", "leave", "connected", "disconnected"} {
			if n := e.h.listeners(event); n != 0 {
				t.Errorf("%d %s subscriptions left", n, event)
			}
		}
		_, err = e.s.Publish(t.Context(), PublishOptions{})
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Publish after Close: %v", err)
		}
		_, err = e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Watch after Close: %v", err)
		}
	})
}

func TestCleanup_TellsTheServerOnCloseStopsWhatItPublishedLeavesWhatItWatched(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		e.watchAccepted()
		err := e.s.Close(t.Context())
		if err != nil {
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
}

func TestCleanup_ReturnsTheFailuresOfTheGoodbyeJoined(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.publish(PublishOptions{Name: "x"})
		e.watchAccepted()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			refused := s.name == "stopstream" || s.name == "joinstreamrequest"

			return nil, serverError(errcode.PermissionsClientInsufficient), refused
		}
		err := e.s.Close(t.Context())
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 2 || !errors.Is(err, errcode.PermissionsClientInsufficient) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestCleanup_DoesNotCountAStreamOrConnectionAlreadyGoneAsAFailure(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.publish(PublishOptions{Name: "x"})
		e.watchAccepted()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name == "stopstream" {
				return nil, serverError(errcode.StreamNotFound), true
			}

			return nil, teamspeak.ErrNotConnected, s.name == "joinstreamrequest"
		}
		err := e.s.Close(t.Context())
		if err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

func TestCleanup_WaitsForTheGoodbyeWithinItsContext(t *testing.T) {
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
}

func TestCleanup_SendsNothingOnCloseWhenTheConnectionIsGone(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.publish(PublishOptions{Name: "x"})
		e.h.disconnect()
		before := e.h.count()
		err := e.s.Close(t.Context())
		if err != nil || e.h.count() != before {
			t.Errorf("err %v, sent %d", err, e.h.count()-before)
		}
	})
}

func TestCleanup_ClearsTheRememberedDenialsOnClose(t *testing.T) {
	runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		err := reqs.all()[0].Deny(t.Context(), "")
		if err != nil {
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
}

func TestCleanup_BoundsTheRememberedDenialsToTheMostRecent1024(t *testing.T) {
	l := newLRU[teamspeak.UID](maxDenied)
	for i := range maxDenied + 10 {
		l.add(teamspeak.UID(time.Duration(i).String()))
	}
	l.add("0s")
	if l.has("1ns") || l.has("0s") != true || len(l.items) != maxDenied {
		t.Errorf("size %d, has 0s %v, has 1ns %v", len(l.items), l.has("0s"), l.has("1ns"))
	}
}

func streamOfFive(e *env) {
	e.h.enter(5, new(true))
	e.h.notify(notify.StreamStarted, announcement("a", 5))
	e.settle()
}

func TestPublisherThatStopsStreaming_DropsItsStreamsWithTheCauseGoneOnceTheFlagHasStayedClearForTheGrace(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		streamOfFive(e)
		e.h.setStreaming(5, false)
		time.Sleep(goneGrace - time.Millisecond)
		e.settle()
		if stopped.len() != 0 {
			t.Fatal("ended before the grace")
		}
		time.Sleep(time.Millisecond)
		e.settle()
		if got := stopped.all(); len(got) != 1 || got[0].Cause != EndCauseGone || got[0].Reason != 0 || len(e.s.List()) != 0 {
			t.Errorf("stopped = %+v", got)
		}
	})
}

func TestPublisherThatStopsStreaming_LetsTheStopNotificationThatFollowsTheClearWinWithItsReason(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		streamOfFive(e)
		e.h.setStreaming(5, false)
		e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "1"})
		time.Sleep(10 * time.Second)
		e.settle()
		if got := stopped.all(); len(got) != 1 || got[0].Cause != EndCauseServer || got[0].Reason != 1 {
			t.Errorf("stopped = %+v", got)
		}
	})
}

func TestPublisherThatStopsStreaming_CancelsTheEndWhenTheFlagIsSetAgainWithinTheGrace(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		streamOfFive(e)
		e.h.setStreaming(5, false)
		time.Sleep(time.Second)
		e.h.setStreaming(5, true)
		time.Sleep(10 * time.Second)
		e.settle()
		if len(e.s.List()) != 1 {
			t.Errorf("List = %+v", e.s.List())
		}
	})
}

func TestPublisherThatStopsStreaming_DoesNotRunTheEndAfterCloseAndLeavesNoTimer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		streamOfFive(e)
		e.h.setStreaming(5, false)
		_ = e.s.Close(t.Context())
		time.Sleep(10 * time.Second)
		e.settle()
		if stopped.len() != 0 {
			t.Errorf("stopped = %+v", stopped.all())
		}
	})
}

func TestPublisherThatStopsStreaming_LeavesNoTimerWhenTheConnectionEnds(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		streamOfFive(e)
		e.h.setStreaming(5, false)
		e.h.disconnect()
		time.Sleep(10 * time.Second)
		e.settle()
		if stopped.len() != 0 {
			t.Errorf("stopped = %+v", stopped.all())
		}
	})
}

func TestPublisherThatStopsStreaming_DropsItsStreamsAfterTheGraceWhenItComesIntoViewNotStreaming(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.h.enter(5, new(false))
		time.Sleep(goneGrace)
		e.settle()
		if len(e.s.List()) != 0 {
			t.Errorf("List = %+v", e.s.List())
		}
	})
}

func TestPublisherThatStopsStreaming_KeepsAStreamWhenTheFlagSaysNothingAndTheStreamsOfOthers(t *testing.T) {
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
}

func TestPublisherThatStopsStreaming_EndsTheViewersSideOfAStreamThatIsGoneAfterTheGrace(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(5, new(true))
		v := e.watchAccepted()
		var closed collector[PeerClosedEvent]
		v.OnClosed(closed.add)
		e.h.setStreaming(5, false)
		time.Sleep(goneGrace)
		e.settle()
		if got := closed.all(); len(got) != 1 || got[0] != (PeerClosedEvent{Cause: PeerCauseStopped}) {
			t.Errorf("closed = %+v", got)
		}
	})
}

func TestPublisherThatStopsStreaming_KeepsTheRealReasonForAViewerWhenTheStopFollowsTheClear(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(5, new(true))
		v := e.watchAccepted()
		var closed collector[PeerClosedEvent]
		v.OnClosed(closed.add)
		e.h.setStreaming(5, false)
		e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "reason": "9"})
		time.Sleep(goneGrace)
		e.settle()
		if got := closed.all(); len(got) != 1 || got[0] != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 9}) {
			t.Errorf("closed = %+v", got)
		}
	})
}

// joinReply makes the fake host answer the join request itself (not the leave)
// with do.
func (e *env) joinReply(do func() ([]map[string]string, error)) {
	e.h.reply = func(s sent) ([]map[string]string, error, bool) {
		if s.name != "joinstreamrequest" || s.params["is_remove"] != "0" {
			return nil, nil, false
		}
		rows, err := do()

		return rows, err, true
	}
}

// The publisher accepts while the join request is still being sent, and the
// send then fails with the end of its context. The view is a live one, and the
// caller has it: before, the error was returned and the view was left behind,
// joined on the server, so that asking again returned ErrAlreadyWatching.
func TestWatch_DoesNotLeaveAViewBehindWhenTheAnswerLandsDuringAFailingSend(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		e.joinReply(func() ([]map[string]string, error) {
			e.respond(nil)

			return nil, fmt.Errorf("joinstreamrequest: %w", context.DeadlineExceeded)
		})
		r := <-e.startWatch(t.Context())
		if r.err != nil || r.view == nil || r.view.Closed() {
			t.Fatalf("view %v, err %v: a view the publisher accepted was dropped", r.view, r.err)
		}
		e.h.reply = nil
		_, err := e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.Is(err, ErrAlreadyWatching) {
			t.Errorf("watching again: %v", err)
		}
		err = r.view.Leave(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if join := e.h.commands("joinstreamrequest"); len(join) != 2 || join[1].params["is_remove"] != "1" {
			t.Errorf("sent %v", join)
		}
	})
}

// The wait ends, and the answer comes after: it finds no watch, so no view is
// made, the request was withdrawn, and asking again works.
func TestWatch_IgnoresAnAcceptanceThatComesAfterTheWaitEnded(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		r := <-e.startWatch(ctx)
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", r.err)
		}
		e.respond(nil)
		e.settle()
		join := e.h.commands("joinstreamrequest")
		if len(join) != 2 || join[1].params["is_remove"] != "1" {
			t.Fatalf("sent %v", join)
		}
		done := e.startWatch(t.Context())
		e.respond(nil)
		if r := <-done; r.err != nil {
			t.Errorf("asking again: %v", r.err)
		}
	})
}

// A join request that never left the client's flood throttle is not withdrawn:
// the server has nothing to withdraw. The client says so by returning the
// context's own error, not wrapped.
func TestWatch_DoesNotWithdrawARequestThatWasNeverSent(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		e.joinReply(func() ([]map[string]string, error) { return nil, context.DeadlineExceeded })
		r := <-e.startWatch(t.Context())
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", r.err)
		}
		e.settle()
		if join := e.h.commands("joinstreamrequest"); len(join) != 1 {
			t.Errorf("sent %v, want the request alone", join)
		}
		// Nothing is left behind.
		e.h.reply = nil
		done := e.startWatch(t.Context())
		e.respond(nil)
		if r := <-done; r.err != nil {
			t.Errorf("asking again: %v", r.err)
		}
	})
}

// One that was sent, and whose answer was awaited, may have been taken.
func TestWatch_WithdrawsARequestWhoseAnswerWasAwaited(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		e.joinReply(func() ([]map[string]string, error) {
			return nil, fmt.Errorf("joinstreamrequest: %w", context.DeadlineExceeded)
		})
		r := <-e.startWatch(t.Context())
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", r.err)
		}
		e.settle()
		if join := e.h.commands("joinstreamrequest"); len(join) != 2 || join[1].params["is_remove"] != "1" {
			t.Errorf("sent %v", join)
		}
	})
}

// While a view's leave is out, the stream still counts as watched.
func TestPeerClose_KeepsTheStreamWatchedUntilTheLeaveIsAnswered(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		v := e.watchAccepted()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name == "joinstreamrequest" && s.params["is_remove"] == "1" {
				time.Sleep(time.Second)
			}

			return nil, nil, false
		}
		left := make(chan error, 1)
		go func() { left <- v.Leave(t.Context()) }()
		e.settle()
		if !v.Closed() {
			t.Error("the view is not closed at once")
		}
		_, err := e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.Is(err, ErrAlreadyWatching) {
			t.Errorf("Watch during the leave: %v", err)
		}
		err = <-left
		if err != nil {
			t.Fatal(err)
		}
		done := e.startWatch(t.Context())
		e.respond(nil)
		if r := <-done; r.err != nil {
			t.Errorf("Watch after the leave: %v", r.err)
		}
	})
}

// A publisher goes on sending to a view that is over, as the server cannot
// remove it; that is not worth a report.
func TestPeerClose_IgnoresWhatThePublisherStillSends(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var errs collector[error]
		e.s.OnError(errs.add)
		v := e.watchAccepted()
		err := v.Leave(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e.h.notify(notify.StreamSignaling, fromFive(`{"cmd":"iceCandidate","args":{"sdp":"late"}}`))
		e.settle()
		if errs.len() != 0 {
			t.Errorf("errors = %v", errs.all())
		}
		// A new view of the stream hears its publisher again.
		done := e.startWatch(t.Context())
		e.respond(nil)
		v2 := (<-done).view
		var cands collector[IceCandidate]
		v2.OnCandidate(cands.add)
		e.h.notify(notify.StreamSignaling, fromFive(`{"cmd":"iceCandidate","args":{"sdp":"again"}}`))
		e.settle()
		if cands.len() != 1 {
			t.Errorf("candidates = %d", cands.len())
		}
	})
}
