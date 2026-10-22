package stream

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/notify"
)

const sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"

// ask is client clid asking to watch p.
func (e *env) ask(p *Published, clid int, msg string) {
	e.h.notify(notify.JoinStreamRequest, map[string]string{"id": string(p.ID()), "clid": strconv.Itoa(clid), "msg": msg})
}

// withdraw is client clid taking its request back.
func (e *env) withdraw(p *Published, clid int) {
	e.h.notify(notify.JoinStreamRequest,
		map[string]string{"id": string(p.ID()), "clid": strconv.Itoa(clid), "is_remove": "1"})
}

// requests collects the requests of a published stream.
func requests(p *Published) *collector[*JoinRequest] {
	c := new(collector[*JoinRequest])
	p.OnRequest(c.add)

	return c
}

func TestJoinRequests_EmitsARequestWithWhoAsked(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "let me in | please ü")
		e.settle()
		got := reqs.all()
		if len(got) != 1 {
			t.Fatalf("requests = %d", len(got))
		}
		r := got[0]
		want := Viewer{ClientID: 9, UID: "uid-9", Nickname: "client9"}
		if r.Viewer() != want || r.Message() != "let me in | please ü" {
			t.Errorf("request = %+v %q", r.Viewer(), r.Message())
		}
		if r.StreamID() != p.ID() || r.State() != RequestPending {
			t.Errorf("request = %v %v", r.StreamID(), r.State())
		}
	})
}

func TestJoinRequests_AsksTheServerWhoAClientOutOfViewIs(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name == "clientgetuidfromclid" {
				return []map[string]string{{"clid": s.params["clid"], "cluid": "far-uid", "nickname": "Far"}}, nil, true
			}

			return nil, nil, false
		}
		e.ask(p, 12, "")
		e.settle()
		if got := reqs.all(); len(got) != 1 || got[0].Viewer() != (Viewer{ClientID: 12, UID: "far-uid", Nickname: "Far"}) {
			t.Errorf("requests = %+v", got)
		}
	})
}

func TestJoinRequests_KnowsNoUidForAClientTheServerCannotNameAndStillAnnouncesIt(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.ClientInvalidID), s.name == "clientgetuidfromclid"
		}
		e.ask(p, 12, "")
		e.settle()
		if got := reqs.all(); len(got) != 1 || got[0].Viewer() != (Viewer{ClientID: 12}) {
			t.Errorf("requests = %+v", got)
		}
	})
}

func TestJoinRequests_RemembersADeniedClientThatWasOutOfViewByTheUidTheServerGave(t *testing.T) {
	runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name == "clientgetuidfromclid" {
				return []map[string]string{{"cluid": "far-uid", "nickname": "Far"}}, nil, true
			}

			return nil, nil, false
		}
		e.ask(p, 12, "")
		e.settle()
		err := reqs.all()[0].Deny(t.Context(), "no")
		if err != nil {
			t.Fatal(err)
		}
		e.ask(p, 12, "")
		e.settle()
		if reqs.len() != 1 {
			t.Errorf("requests = %d, want the second left unanswered", reqs.len())
		}
	})
}

func TestJoinRequests_AnnouncesRequestsInTheOrderTheyCameWhateverTheLookupsTake(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name != "clientgetuidfromclid" {
				return nil, nil, false
			}
			// The first lookup takes longest.
			if s.params["clid"] == "12" {
				time.Sleep(300 * time.Millisecond)
			}

			return []map[string]string{{"cluid": "uid-" + s.params["clid"]}}, nil, true
		}
		e.h.see(9, nil)
		e.ask(p, 12, "first")
		e.ask(p, 13, "second")
		e.ask(p, 9, "third, in view but behind")
		e.settle()
		time.Sleep(time.Second)
		e.settle()
		order := make([]string, 0, 3)
		for _, r := range reqs.all() {
			order = append(order, r.Message())
		}
		if strings.Join(order, "|") != "first|second|third, in view but behind" {
			t.Errorf("order = %v", order)
		}
	})
}

func TestJoinRequests_DoesNotAnnounceARequestWithdrawnWhileItsLookupWasOut(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name != "clientgetuidfromclid" {
				return nil, nil, false
			}
			time.Sleep(time.Second)

			return []map[string]string{{"cluid": "u"}}, nil, true
		}
		e.ask(p, 12, "")
		e.settle()
		e.withdraw(p, 12)
		time.Sleep(2 * time.Second)
		e.settle()
		if reqs.len() != 0 {
			t.Errorf("requests = %d", reqs.len())
		}
	})
}

func TestJoinRequests_KeepsARequestThatArrivesBeforeAHandlerForTheFirstOne(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		e.h.see(9, nil)
		e.ask(p, 9, "early")
		e.settle()
		first, second := requests(p), requests(p)
		e.settle()
		if first.len() != 1 || second.len() != 0 {
			t.Errorf("first %d, second %d", first.len(), second.len())
		}
	})
}

func TestJoinRequests_DoesNotRepeatARequestFromAViewerPendingOrConnected(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.ask(p, 9, "again")
		e.settle()
		if reqs.len() != 1 {
			t.Fatalf("requests = %d while pending", reqs.len())
		}
		_, err := reqs.all()[0].Accept(t.Context(), sdp, "")
		if err != nil {
			t.Fatal(err)
		}
		e.ask(p, 9, "once more")
		e.settle()
		if reqs.len() != 1 {
			t.Errorf("requests = %d after connecting", reqs.len())
		}
	})
}

func TestJoinRequests_AnswersAnAcceptedRequestWithTheOfferAndReturnsThePeer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		peer, err := reqs.all()[0].Accept(t.Context(), sdp, "welcome")
		if err != nil {
			t.Fatal(err)
		}
		res := e.h.commands("respondjoinstreamrequest")
		if len(res) != 1 {
			t.Fatalf("sent %d", len(res))
		}
		want := map[string]string{"id": string(p.ID()), "clid": "9", "msg": "welcome", "offer": sdp, "decision": "1"}
		for k, v := range want {
			if res[0].params[k] != v {
				t.Errorf("%s = %q, want %q", k, res[0].params[k], v)
			}
		}
		if peer.ClientID() != 9 || peer.StreamID() != p.ID() || peer.Closed() || len(p.Viewers()) != 1 {
			t.Errorf("peer = %+v", peer)
		}
		if reqs.all()[0].State() != RequestAccepted {
			t.Errorf("state = %v", reqs.all()[0].State())
		}
	})
}

func TestJoinRequests_AnswersADenialWithAnEmptyOfferAndTheReason(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		err := reqs.all()[0].Deny(t.Context(), "not today")
		if err != nil {
			t.Fatal(err)
		}
		res := e.h.commands("respondjoinstreamrequest")[0]
		if res.params["decision"] != "0" || res.params["offer"] != "" || res.params["msg"] != "not today" {
			t.Errorf("params = %v", res.params)
		}
		if !strings.Contains(res.line, " offer= ") {
			t.Errorf("the offer is not sent empty: %q", res.line)
		}
		if reqs.all()[0].State() != RequestDenied {
			t.Errorf("state = %v", reqs.all()[0].State())
		}
	})
}

func TestJoinRequests_AnswersOnceASecondAnswerFailsAndSendsNothing(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		r := reqs.all()[0]
		err := r.Deny(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Accept(t.Context(), sdp, "")
		if !errors.Is(err, ErrNotPending) {
			t.Errorf("Accept err = %v", err)
		}
		err = r.Deny(t.Context(), "")
		if !errors.Is(err, ErrNotPending) {
			t.Errorf("Deny err = %v", err)
		}
		if got := len(e.h.commands("respondjoinstreamrequest")); got != 1 {
			t.Errorf("sent %d", got)
		}
	})
}

func TestJoinRequests_AsksForANonEmptyOffer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		_, err := reqs.all()[0].Accept(t.Context(), "", "")
		if !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("err = %v", err)
		}
		if reqs.all()[0].State() != RequestPending {
			t.Error("the request was used up")
		}
	})
}

func TestJoinRequests_RefusesAnOfferTooLongAndLeavesTheRequestToBeAnsweredAgain(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		r := reqs.all()[0]
		var big *PayloadTooLargeError
		_, err := r.Accept(t.Context(), strings.Repeat("a", maxCommandLineBytes), "")
		if !errors.As(err, &big) || big.Command != "respondjoinstreamrequest" {
			t.Fatalf("err = %v", err)
		}
		if r.State() != RequestPending || len(p.Viewers()) != 0 {
			t.Errorf("state %v, viewers %d", r.State(), len(p.Viewers()))
		}
		_, err = r.Accept(t.Context(), sdp, "")
		if err != nil {
			t.Errorf("shortened: %v", err)
		}
	})
}

func TestJoinRequests_MarksARequestFailedAndClosesItsPeerWhenTheAnswerIsRefused(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.StreamJoinRequestRedacted), s.name == "respondjoinstreamrequest"
		}
		r := reqs.all()[0]
		_, err := r.Accept(t.Context(), sdp, "")
		if !errors.Is(err, errcode.StreamJoinRequestRedacted) {
			t.Fatalf("err = %v", err)
		}
		if r.State() != RequestFailed || len(p.Viewers()) != 0 {
			t.Errorf("state %v, viewers %d", r.State(), len(p.Viewers()))
		}
	})
}

func TestJoinRequests_DropsAPendingRequestTheViewerWithdrew(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		e.withdraw(p, 9)
		e.settle()
		r := reqs.all()[0]
		_, err := r.Accept(t.Context(), sdp, "")
		if !errors.Is(err, ErrNotPending) {
			t.Errorf("err = %v", err)
		}
		if r.State() != RequestWithdrawn {
			t.Errorf("state = %v", r.State())
		}
	})
}

func TestJoinRequests_AsksAgainAfterADenialSinceTheServerForgets(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		err := reqs.all()[0].Deny(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		e.ask(p, 9, "again")
		e.settle()
		if reqs.len() != 2 {
			t.Errorf("requests = %d, want 2", reqs.len())
		}
	})
}

func TestJoinRequests_LeavesADeniedClientUnansweredWhenRememberDeniedIsOn(t *testing.T) {
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
		before := e.h.count()
		e.ask(p, 9, "again")
		e.settle()
		if reqs.len() != 1 || e.h.count() != before {
			t.Errorf("requests %d, commands %d -> %d", reqs.len(), before, e.h.count())
		}
	})
}

func TestJoinRequests_DoesNotRememberADenialTheServerRefused(t *testing.T) {
	runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.StreamJoinRequestRedacted), s.name == "respondjoinstreamrequest"
		}
		err := reqs.all()[0].Deny(t.Context(), "")
		if err == nil {
			t.Fatal("no error")
		}
		e.ask(p, 9, "again")
		e.settle()
		if reqs.len() != 2 {
			t.Errorf("requests = %d, want 2", reqs.len())
		}
	})
}

func TestJoinRequests_RemembersNothingByDefault(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		for range 3 {
			e.ask(p, 9, "")
			e.settle()
			err := reqs.all()[reqs.len()-1].Deny(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
		}
		if reqs.len() != 3 {
			t.Errorf("requests = %d", reqs.len())
		}
	})
}

func TestJoinRequests_IgnoresARequestForAStreamItDoesNotPublish(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.notify(notify.JoinStreamRequest, map[string]string{"id": "other", "clid": "9"})
		e.h.notify(notify.JoinStreamRequest, map[string]string{"id": string(p.ID()), "clid": "0"})
		e.settle()
		if reqs.len() != 0 {
			t.Errorf("requests = %d", reqs.len())
		}
	})
}

func TestJoinRequests_SendsTheMessageGivenToAccept(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		_, err := reqs.all()[0].Accept(t.Context(), sdp, "hello ü")
		if err != nil {
			t.Fatal(err)
		}
		if got := e.h.commands("respondjoinstreamrequest")[0].params["msg"]; got != "hello ü" {
			t.Errorf("msg = %q", got)
		}
	})
}

func TestJoinRequests_ForgetsAPendingRequestWhenItsClientLeavesViewSoAReusedIdIsHeard(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "first")
		e.settle()
		e.h.leave(9)
		e.h.see(9, nil)
		e.ask(p, 9, "second")
		e.settle()
		if reqs.len() != 2 || reqs.all()[0].State() != RequestWithdrawn {
			t.Errorf("requests = %d, first %v", reqs.len(), reqs.all()[0].State())
		}
	})
}

func closingSetup(e *env) (*Published, *JoinRequest, *collector[RequestState]) {
	p := e.publish(PublishOptions{Name: "x"})
	reqs := requests(p)
	e.h.see(9, nil)
	e.ask(p, 9, "")
	e.settle()
	closed := new(collector[RequestState])
	r := reqs.all()[0]
	r.OnClosed(closed.add)

	return p, r, closed
}

func TestJoinRequestClosing_EmitsWithdrawnWhenTheViewerTakesTheRequestBackOrLeavesView(t *testing.T) {
	for name, act := range map[string]func(e *env, p *Published){
		"takes it back": func(e *env, p *Published) { e.withdraw(p, 9) },
		"leaves view":   func(e *env, _ *Published) { e.h.leave(9) },
		"leaves stream": func(e *env, p *Published) {
			e.h.notify(notify.StreamClientLeft, map[string]string{"id": string(p.ID()), "clid": "9"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, e *env) {
				p, r, closed := closingSetup(e)
				act(e, p)
				e.settle()
				if got := closed.all(); len(got) != 1 || got[0] != RequestWithdrawn || r.State() != RequestWithdrawn {
					t.Errorf("closed = %v, state %v", got, r.State())
				}
			})
		})
	}
}

func TestJoinRequestClosing_EmitsEndedWhenTheStreamStopsIsStoppedHereOrIsClosed(t *testing.T) {
	for name, act := range map[string]func(e *env, p *Published){
		"server stop": func(e *env, p *Published) {
			e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
		},
		"stop here":  func(e *env, p *Published) { _ = p.Stop(e.t.Context(), 0) },
		"close":      func(e *env, _ *Published) { _ = e.s.Close(e.t.Context()) },
		"disconnect": func(e *env, _ *Published) { e.h.disconnect() },
	} {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, e *env) {
				p, r, closed := closingSetup(e)
				act(e, p)
				e.settle()
				if got := closed.all(); len(got) != 1 || got[0] != RequestEnded || r.State() != RequestEnded {
					t.Errorf("closed = %v, state %v", got, r.State())
				}
				_, err := r.Accept(t.Context(), sdp, "")
				if !errors.Is(err, ErrNotPending) {
					t.Errorf("Accept err = %v", err)
				}
			})
		})
	}
}

func TestJoinRequestClosing_EmitsOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p, _, closed := closingSetup(e)
		e.withdraw(p, 9)
		e.withdraw(p, 9)
		e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
		e.settle()
		if closed.len() != 1 {
			t.Errorf("closed = %v", closed.all())
		}
	})
}

func TestJoinRequestClosing_EmitsNothingForARequestThatIsAcceptedOrDeniedThenTheStreamEnds(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.h.see(10, nil)
		e.ask(p, 9, "")
		e.ask(p, 10, "")
		e.settle()
		var closed collector[RequestState]
		for _, r := range reqs.all() {
			r.OnClosed(closed.add)
		}
		_, err := reqs.all()[0].Accept(t.Context(), sdp, "")
		if err != nil {
			t.Fatal(err)
		}
		err = reqs.all()[1].Deny(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
		e.settle()
		if closed.len() != 0 {
			t.Errorf("closed = %v", closed.all())
		}
	})
}

func TestJoinRequestClosing_EmitsNothingForARequestWhoseAnswerFailed(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p, r, closed := closingSetup(e)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.StreamNotFound), s.name == "respondjoinstreamrequest"
		}
		_, err := r.Accept(t.Context(), sdp, "")
		if _, ok := errors.AsType[*EndedError](err); !ok {
			t.Fatalf("err = %v, want *EndedError", err)
		}
		e.withdraw(p, 9)
		e.settle()
		if closed.len() != 0 {
			t.Errorf("closed = %v", closed.all())
		}
	})
}

func TestJoinRequestClosing_KeepsTheEventForAHandlerThatComesLateAndDeliversItToTheFirstOnly(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		e.withdraw(p, 9)
		e.settle()
		var first, second collector[RequestState]
		reqs.all()[0].OnClosed(first.add)
		reqs.all()[0].OnClosed(second.add)
		e.settle()
		if first.len() != 1 || second.len() != 0 {
			t.Errorf("first %d, second %d", first.len(), second.len())
		}
	})
}

func TestJoinRequestClosing_GivesARequestAskedAgainAfterAWithdrawalItsOwnEvent(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p, _, closed := closingSetup(e)
		e.withdraw(p, 9)
		e.ask(p, 9, "again")
		e.settle()
		if closed.len() != 1 {
			t.Fatalf("closed = %v", closed.all())
		}
		e.withdraw(p, 9)
		e.settle()
		if closed.len() != 1 {
			t.Errorf("the new request closed the old one's handler: %v", closed.all())
		}
	})
}

const video = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"

func audioSetup(e *env) (*Published, *JoinRequest, *collector[WarningEvent]) {
	p := e.publish(PublishOptions{Name: "x"})
	reqs := requests(p)
	e.h.see(9, nil)
	e.ask(p, 9, "")
	e.settle()
	warnings := new(collector[WarningEvent])
	e.s.OnWarning(warnings.add)

	return p, reqs.all()[0], warnings
}

func TestOffersWithoutAudio_WarnsOnAcceptAndStillSendsTheOfferUnchanged(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p, r, warnings := audioSetup(e)
		_, err := r.Accept(t.Context(), video, "")
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		got := warnings.all()
		if len(got) != 1 || got[0].Code != WarningOfferWithoutAudio || got[0].Message == "" {
			t.Fatalf("warnings = %+v", got)
		}
		if got[0].StreamID != p.ID() || got[0].ClientID != 9 {
			t.Errorf("warning = %+v", got[0])
		}
		if e.h.commands("respondjoinstreamrequest")[0].params["offer"] != video {
			t.Error("the offer was changed")
		}
	})
}

func TestOffersWithoutAudio_DoesNotWarnForAnOfferWithAnAudioSectionInAnyOrder(t *testing.T) {
	for _, offer := range []string{sdp, "v=0\r\nm=video 9 X 96\r\nm=audio 9 X 111\r\n", "m=audio\t9 X 1\r\n"} {
		run(t, func(t *testing.T, e *env) {
			_, r, warnings := audioSetup(e)
			_, err := r.Accept(t.Context(), offer, "")
			if err != nil {
				t.Fatal(err)
			}
			e.settle()
			if warnings.len() != 0 {
				t.Errorf("warned for %q", offer)
			}
		})
	}
}

func TestOffersWithoutAudio_WarnsOnARenegotiationOfferWithoutAudioAndSendsIt(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		_, r, warnings := audioSetup(e)
		peer, err := r.Accept(t.Context(), sdp, "")
		if err != nil {
			t.Fatal(err)
		}
		err = peer.SendOffer(t.Context(), video)
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		if warnings.len() != 1 {
			t.Fatalf("warnings = %d", warnings.len())
		}
		line := e.h.commands("streamsignaling")[0].params["json"]
		if want := `{"cmd":"offer","args":{"offer":"v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"}}`; line != want {
			t.Errorf("json = %q, want %q", line, want)
		}
	})
}

func TestOffersWithoutAudio_DoesNotWarnForADenialOrForAnOfferRefusedAsTooLong(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		_, r, warnings := audioSetup(e)
		_, err := r.Accept(t.Context(), strings.Repeat("v", maxCommandLineBytes), "")
		if err == nil {
			t.Fatal("no error")
		}
		err = r.Deny(t.Context(), "no")
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		if warnings.len() != 0 {
			t.Errorf("warnings = %+v", warnings.all())
		}
	})
}

func TestOffersWithoutAudio_KeepsWarningsForTheFirstHandlerBounded(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		peer, err := reqs.all()[0].Accept(t.Context(), video, "")
		if err != nil {
			t.Fatal(err)
		}
		for range maxKept + 4 {
			err := peer.SendOffer(t.Context(), video)
			if err != nil {
				t.Fatal(err)
			}
		}
		var warnings collector[WarningEvent]
		e.s.OnWarning(warnings.add)
		e.settle()
		if warnings.len() != maxKept {
			t.Errorf("warnings = %d, want %d", warnings.len(), maxKept)
		}
	})
}

// viewerID is the client the tests let in.
const viewerID = 9

func acceptViewer(t *testing.T, e *env, p *Published) *ViewerPeer {
	t.Helper()
	reqs := requests(p)
	e.h.see(viewerID, nil)
	e.ask(p, viewerID, "")
	e.settle()
	peer, err := reqs.all()[reqs.len()-1].Accept(t.Context(), sdp, "")
	if err != nil {
		t.Fatal(err)
	}

	return peer
}

func relay(p *Published, clid int, json string) map[string]string {
	return map[string]string{"id": string(p.ID()), "clid": strconv.Itoa(clid), "json": json}
}

func TestViewerPeer_DeliversAnAnswerAndCandidatesAndSendsCandidatesAndOffers(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var answers collector[string]
		var cands collector[IceCandidate]
		peer.OnAnswer(answers.add)
		peer.OnCandidate(cands.add)
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"answer","args":{"answer":"v=0"}}`))
		const candidate = `{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}`
		e.h.notify(notify.StreamSignaling, relay(p, 9, candidate))
		e.settle()
		if got := answers.all(); len(got) != 1 || got[0] != "v=0" {
			t.Errorf("answers = %v", got)
		}
		want := IceCandidate{Candidate: "candidate:1", SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}
		got := cands.all()
		if len(got) != 1 || got[0].Candidate != want.Candidate || *got[0].SDPMid != "0" || *got[0].SDPMLineIndex != 0 {
			t.Errorf("candidates = %+v", got)
		}
		err := peer.SendCandidate(t.Context(), want)
		if err != nil {
			t.Fatal(err)
		}
		sig := e.h.commands("streamsignaling")[0]
		if sig.params["id"] != string(p.ID()) || sig.params["clid"] != "9" ||
			sig.params["json"] != `{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}` {
			t.Errorf("sent = %v", sig.params)
		}
	})
}

func TestViewerPeer_KeepsWhatArrivesBeforeAHandlerForTheFirstHandlerOfEachEvent(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"answer","args":{"answer":"a1"}}`))
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"iceCandidate","args":{"sdp":"c1"}}`))
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"iceCandidate","args":{"sdp":"c2"}}`))
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"mute"}`))
		e.settle()
		var answers, more collector[string]
		var cands collector[IceCandidate]
		var raws collector[RawSignal]
		peer.OnAnswer(answers.add)
		peer.OnAnswer(more.add)
		peer.OnCandidate(cands.add)
		peer.OnSignal(raws.add)
		e.settle()
		if answers.len() != 1 || more.len() != 0 || cands.len() != 2 || cands.all()[1].Candidate != "c2" || raws.len() != 1 {
			t.Errorf("answers %d, more %d, candidates %d, raw %d", answers.len(), more.len(), cands.len(), raws.len())
		}
	})
}

func TestViewerPeer_HandsOverMessagesItHasNoNameForAndTextThatIsNoMessage(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var raws collector[RawSignal]
		peer.OnSignal(raws.add)
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"mute","args":{"on":true}}`))
		e.h.notify(notify.StreamSignaling, relay(p, 9, "not json"))
		e.settle()
		got := raws.all()
		if len(got) != 2 || got[0].Cmd != "mute" || string(got[0].Args) != `{"on":true}` {
			t.Fatalf("raw = %+v", got)
		}
		if got[1].Cmd != "" || got[1].JSON != "not json" || got[1].Args != nil {
			t.Errorf("raw = %+v", got[1])
		}
	})
}

func TestViewerPeer_SendsAMessageOfTheApplicationsOwn(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		err := peer.SendSignal(t.Context(), "mute", map[string]bool{"on": true})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.h.commands("streamsignaling")[0].params["json"]; got != `{"cmd":"mute","args":{"on":true}}` {
			t.Errorf("json = %q", got)
		}
		err = peer.SendSignal(t.Context(), "ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.h.commands("streamsignaling")[1].params["json"]; got != `{"cmd":"ping"}` {
			t.Errorf("json = %q", got)
		}
		err = peer.SendSignal(t.Context(), "x", make(chan int))
		if err == nil {
			t.Error("an unencodable argument was sent")
		}
	})
}

func TestViewerPeer_RefusesAMessageTooLongBeforeSending(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		before := e.h.count()
		err := peer.SendSignal(t.Context(), "big", strings.Repeat("x", maxCommandLineBytes))
		if _, ok := errors.AsType[*PayloadTooLargeError](err); !ok {
			t.Errorf("err = %v", err)
		}
		if e.h.count() != before {
			t.Error("sent a command")
		}
	})
}

func TestViewerPeer_ClosesWhenTheViewerLeavesHoweverItSaysSoOnce(t *testing.T) {
	for name, act := range map[string]func(e *env, p *Published){
		"leave request": func(e *env, p *Published) { e.withdraw(p, 9) },
		"client left": func(e *env, p *Published) {
			e.h.notify(notify.StreamClientLeft, map[string]string{"id": string(p.ID()), "clid": "9"})
		},
		"left view": func(e *env, _ *Published) { e.h.leave(9) },
	} {
		t.Run(name, func(t *testing.T) {
			run(t, func(t *testing.T, e *env) {
				p := e.publish(PublishOptions{Name: "x"})
				peer := acceptViewer(t, e, p)
				var closed collector[PeerClosedEvent]
				peer.OnClosed(closed.add)
				act(e, p)
				act(e, p)
				e.settle()
				// Leaving view closes only a request; a peer stays until it is told.
				if name == "left view" {
					return
				}
				if got := closed.all(); len(got) != 1 || got[0].Cause != PeerCauseLeft || !peer.Closed() || len(p.Viewers()) != 0 {
					t.Errorf("closed = %+v", got)
				}
				err := peer.SendCandidate(t.Context(), IceCandidate{Candidate: "c"})
				if !errors.Is(err, ErrClosed) {
					t.Errorf("send on a closed peer: %v", err)
				}
			})
		})
	}
}

func TestViewerPeer_DoesNotCloseWhenAnotherViewerLeaves(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		e.withdraw(p, 10)
		e.settle()
		if peer.Closed() {
			t.Error("closed")
		}
	})
}

func TestViewerPeer_ClosesWithoutSendingAnythingWhenTheApplicationClosesIt(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var closed collector[PeerClosedEvent]
		peer.OnClosed(closed.add)
		before := e.h.count()
		err := peer.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		err = peer.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		if e.h.count() != before || closed.len() != 1 || closed.all()[0].Cause != PeerCauseClosed {
			t.Errorf("sent %d, closed %+v", e.h.count()-before, closed.all())
		}
	})
}

func TestViewerPeer_IgnoresWhatAClosedViewerStillSendsWithoutAnError(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var errs collector[error]
		e.s.OnError(errs.add)
		err := peer.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"iceCandidate","args":{"sdp":"late"}}`))
		e.h.notify(notify.StreamSignaling, relay(p, 77, `{"cmd":"iceCandidate","args":{"sdp":"stranger"}}`))
		e.settle()
		if got := errs.all(); len(got) != 1 || !strings.Contains(got[0].Error(), "client 77") {
			t.Errorf("errors = %v", got)
		}
	})
}

func TestStoppingAStream_SendsStopstreamWithTheReasonEndsTheStreamHereAndTellsNobodyElse(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var ended collector[EndedEvent]
		var stopped collector[StoppedEvent]
		var closed collector[PeerClosedEvent]
		p.OnEnded(ended.add)
		e.s.OnStopped(stopped.add)
		peer.OnClosed(closed.add)
		err := p.Stop(t.Context(), 7)
		if err != nil {
			t.Fatal(err)
		}
		e.settle()
		stops := e.h.commands("stopstream")
		if len(stops) != 1 || stops[0].params["id"] != string(p.ID()) || stops[0].params["reason"] != "7" {
			t.Errorf("stops = %v", stops)
		}
		if !p.Ended() || len(e.s.List()) != 0 {
			t.Error("the stream is still there")
		}
		if got := ended.all(); len(got) != 1 || got[0] != (EndedEvent{Cause: EndCauseStopped, Reason: 7}) {
			t.Errorf("ended = %+v", got)
		}
		if got := stopped.all(); len(got) != 1 || got[0].Cause != EndCauseStopped || got[0].Reason != 7 {
			t.Errorf("stopped = %+v", got)
		}
		if got := closed.all(); len(got) != 1 || got[0] != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 7}) {
			t.Errorf("peer closed = %+v", got)
		}
		// Stopping again sends nothing.
		err = p.Stop(t.Context(), 0)
		if err != nil || len(e.h.commands("stopstream")) != 1 {
			t.Errorf("second stop: %v", err)
		}
	})
}

func TestStoppingAStream_CountsAStreamTheServerNoLongerKnowsAsStopped(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.StreamNotFound), s.name == "stopstream"
		}
		err := p.Stop(t.Context(), 0)
		if err != nil || !p.Ended() {
			t.Errorf("err %v, ended %v", err, p.Ended())
		}
	})
}

func TestStoppingAStream_LeavesTheStreamRunningWhenTheServerRefusesTheCommand(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "stopstream"
		}
		err := p.Stop(t.Context(), 0)
		if !errors.Is(err, errcode.PermissionsClientInsufficient) || p.Ended() {
			t.Errorf("err %v, ended %v", err, p.Ended())
		}
	})
}

func TestStoppingAStream_EndsOnTheServersWordWhoeverStoppedItWithTheReason(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var ended collector[EndedEvent]
		var closed collector[PeerClosedEvent]
		p.OnEnded(ended.add)
		peer.OnClosed(closed.add)
		e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID()), "clid": "1", "reason": "1"})
		e.settle()
		if got := ended.all(); len(got) != 1 || got[0] != (EndedEvent{Cause: EndCauseServer, Reason: 1}) {
			t.Errorf("ended = %+v", got)
		}
		if got := closed.all(); len(got) != 1 || got[0] != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 1}) {
			t.Errorf("closed = %+v", got)
		}
	})
}

func TestStoppingAStream_KeepsTheEndedEventForAHandlerThatComesLate(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
		e.settle()
		var ended collector[EndedEvent]
		p.OnEnded(ended.add)
		e.settle()
		if got := ended.all(); len(got) != 1 || got[0].Cause != EndCauseServer {
			t.Errorf("ended = %+v", got)
		}
	})
}

func TestEventsNobodyListensFor_KeepsErrorsForTheFirstHandlerAndThenDeliversThemLive(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.notify(notify.StreamSignaling, map[string]string{"id": "x", "clid": "3", "json": "{}"})
		e.settle()
		var errs collector[error]
		e.s.OnError(errs.add)
		e.settle()
		if errs.len() != 1 {
			t.Fatalf("errors = %v", errs.all())
		}
		e.h.notify(notify.StreamSignaling, map[string]string{"id": "y", "clid": "4", "json": "{}"})
		e.settle()
		if errs.len() != 2 {
			t.Errorf("errors = %v", errs.all())
		}
	})
}

func TestEventsNobodyListensFor_DropsTheOldestPastTheBoundAndReportsAnOverflowingPeerOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		peer := acceptViewer(t, e, p)
		var errs collector[error]
		e.s.OnError(errs.add)
		for i := range maxKept + 10 {
			e.h.notify(notify.StreamSignaling, relay(p, 9, fmt.Sprintf(`{"cmd":"iceCandidate","args":{"sdp":"c%d"}}`, i)))
		}
		e.settle()
		if got := errs.len(); got != 1 || !strings.Contains(errs.all()[0].Error(), "dropping the oldest candidate") {
			t.Errorf("errors = %v", errs.all())
		}
		var cands collector[IceCandidate]
		peer.OnCandidate(cands.add)
		e.settle()
		if got := cands.all(); len(got) != maxKept || got[0].Candidate != "c10" {
			t.Errorf("candidates = %d, first %v", len(got), got[0].Candidate)
		}
	})
}

func TestEventsNobodyListensFor_DoesNotLetAPanickingHandlerStopTheOthers(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var started collector[Info]
		e.s.OnStarted(func(Info) { panic("boom") })
		e.s.OnStarted(started.add)
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.h.notify(notify.StreamStarted, announcement("b", 5))
		e.settle()
		if started.len() != 2 {
			t.Errorf("started = %d", started.len())
		}
	})
}

func TestEventsNobodyListensFor_StopsDeliveringToAHandlerThatWasRemoved(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var started collector[Info]
		off := e.s.OnStarted(started.add)
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.settle()
		off()
		off()
		e.h.notify(notify.StreamStarted, announcement("b", 5))
		e.settle()
		if started.len() != 1 {
			t.Errorf("started = %d", started.len())
		}
	})
}

func TestEventsNobodyListensFor_HandsEachHandlerItsOwnCopy(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var first, second collector[Info]
		e.s.OnStarted(func(i Info) { *i.Bitrate = 0; first.add(i) })
		e.s.OnStarted(second.add)
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.settle()
		if got := second.all(); len(got) != 1 || *got[0].Bitrate != 58208 {
			t.Errorf("second saw %+v", got)
		}
	})
}

var _ = context.Background

// With the last handler removed, events are kept again for the next one.
func TestEventsNobodyListensFor_KeepsEventsAgainOnceTheLastHandlerIsRemoved(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var first, second collector[error]
		off := e.s.OnError(first.add)
		e.h.notify(notify.StreamSignaling, map[string]string{"id": "x", "clid": "3", "json": "{}"})
		e.settle()
		off()
		e.h.notify(notify.StreamSignaling, map[string]string{"id": "y", "clid": "4", "json": "{}"})
		e.settle()
		e.s.OnError(second.add)
		e.settle()
		if first.len() != 1 || second.len() != 1 || !strings.Contains(second.all()[0].Error(), "stream y") {
			t.Errorf("first %v, second %v", first.all(), second.all())
		}
	})
}
