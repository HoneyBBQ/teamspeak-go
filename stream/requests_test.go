package stream

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
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
	e.h.notify(notify.JoinStreamRequest, map[string]string{"id": string(p.ID()), "clid": strconv.Itoa(clid), "is_remove": "1"})
}

// requests collects the requests of a published stream.
func requests(p *Published) *collector[*JoinRequest] {
	c := new(collector[*JoinRequest])
	p.OnRequest(c.add)

	return c
}

func TestJoinRequests(t *testing.T) {
	t.Run("emits a request with who asked", func(t *testing.T) {
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
			if r.Viewer() != want || r.Message() != "let me in | please ü" || r.StreamID() != p.ID() || r.State() != RequestPending {
				t.Errorf("request = %+v %q %v", r.Viewer(), r.Message(), r.State())
			}
		})
	})
	t.Run("asks the server who a client out of view is", func(t *testing.T) {
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
	})
	t.Run("knows no uid for a client the server cannot name, and still announces it", func(t *testing.T) {
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
	})
	t.Run("remembers a denied client that was out of view by the uid the server gave", func(t *testing.T) {
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
			if err := reqs.all()[0].Deny(t.Context(), "no"); err != nil {
				t.Fatal(err)
			}
			e.ask(p, 12, "")
			e.settle()
			if reqs.len() != 1 {
				t.Errorf("requests = %d, want the second left unanswered", reqs.len())
			}
		})
	})
	t.Run("announces requests in the order they came, whatever the lookups take", func(t *testing.T) {
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
			var order []string
			for _, r := range reqs.all() {
				order = append(order, r.Message())
			}
			if strings.Join(order, "|") != "first|second|third, in view but behind" {
				t.Errorf("order = %v", order)
			}
		})
	})
	t.Run("does not announce a request withdrawn while its lookup was out", func(t *testing.T) {
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
	})
	t.Run("keeps a request that arrives before a handler, for the first one", func(t *testing.T) {
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
	})
	t.Run("does not repeat a request from a viewer pending or connected", func(t *testing.T) {
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
			if _, err := reqs.all()[0].Accept(t.Context(), sdp, ""); err != nil {
				t.Fatal(err)
			}
			e.ask(p, 9, "once more")
			e.settle()
			if reqs.len() != 1 {
				t.Errorf("requests = %d after connecting", reqs.len())
			}
		})
	})
	t.Run("answers an accepted request with the offer, and returns the peer", func(t *testing.T) {
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
			for k, v := range map[string]string{"id": string(p.ID()), "clid": "9", "msg": "welcome", "offer": sdp, "decision": "1"} {
				if res[0].params[k] != v {
					t.Errorf("%s = %q, want %q", k, res[0].params[k], v)
				}
			}
			if peer.ClientID() != 9 || peer.StreamID() != p.ID() || peer.Closed() || len(p.Viewers()) != 1 || reqs.all()[0].State() != RequestAccepted {
				t.Errorf("peer = %+v", peer)
			}
		})
	})
	t.Run("answers a denial with an empty offer and the reason", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if err := reqs.all()[0].Deny(t.Context(), "not today"); err != nil {
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
	})
	t.Run("answers once: a second answer fails, and sends nothing", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			r := reqs.all()[0]
			if err := r.Deny(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Accept(t.Context(), sdp, ""); !errors.Is(err, ErrNotPending) {
				t.Errorf("Accept err = %v", err)
			}
			if err := r.Deny(t.Context(), ""); !errors.Is(err, ErrNotPending) {
				t.Errorf("Deny err = %v", err)
			}
			if got := len(e.h.commands("respondjoinstreamrequest")); got != 1 {
				t.Errorf("sent %d", got)
			}
		})
	})
	t.Run("asks for a non-empty offer", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if _, err := reqs.all()[0].Accept(t.Context(), "", ""); !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("err = %v", err)
			}
			if reqs.all()[0].State() != RequestPending {
				t.Error("the request was used up")
			}
		})
	})
	t.Run("refuses an offer too long, and leaves the request to be answered again", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			r := reqs.all()[0]
			var big *PayloadTooLargeError
			if _, err := r.Accept(t.Context(), strings.Repeat("a", MaxCommandLineBytes), ""); !errors.As(err, &big) || big.Command != "respondjoinstreamrequest" {
				t.Fatalf("err = %v", err)
			}
			if r.State() != RequestPending || len(p.Viewers()) != 0 {
				t.Errorf("state %v, viewers %d", r.State(), len(p.Viewers()))
			}
			if _, err := r.Accept(t.Context(), sdp, ""); err != nil {
				t.Errorf("shortened: %v", err)
			}
		})
	})
	t.Run("marks a request failed and closes its peer when the answer is refused", func(t *testing.T) {
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
	})
	t.Run("drops a pending request the viewer withdrew", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			e.withdraw(p, 9)
			e.settle()
			r := reqs.all()[0]
			if _, err := r.Accept(t.Context(), sdp, ""); !errors.Is(err, ErrNotPending) {
				t.Errorf("err = %v", err)
			}
			if r.State() != RequestWithdrawn {
				t.Errorf("state = %v", r.State())
			}
		})
	})
	t.Run("asks again after a denial, since the server forgets", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if err := reqs.all()[0].Deny(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			e.ask(p, 9, "again")
			e.settle()
			if reqs.len() != 2 {
				t.Errorf("requests = %d, want 2", reqs.len())
			}
		})
	})
	t.Run("leaves a denied client unanswered when RememberDenied is on", func(t *testing.T) {
		runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if err := reqs.all()[0].Deny(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			before := e.h.count()
			e.ask(p, 9, "again")
			e.settle()
			if reqs.len() != 1 || e.h.count() != before {
				t.Errorf("requests %d, commands %d -> %d", reqs.len(), before, e.h.count())
			}
		})
	})
	t.Run("does not remember a denial the server refused", func(t *testing.T) {
		runWith(t, Options{RememberDenied: true}, nil, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.StreamJoinRequestRedacted), s.name == "respondjoinstreamrequest"
			}
			if err := reqs.all()[0].Deny(t.Context(), ""); err == nil {
				t.Fatal("no error")
			}
			e.ask(p, 9, "again")
			e.settle()
			if reqs.len() != 2 {
				t.Errorf("requests = %d, want 2", reqs.len())
			}
		})
	})
	t.Run("remembers nothing by default", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			for range 3 {
				e.ask(p, 9, "")
				e.settle()
				if err := reqs.all()[reqs.len()-1].Deny(t.Context(), ""); err != nil {
					t.Fatal(err)
				}
			}
			if reqs.len() != 3 {
				t.Errorf("requests = %d", reqs.len())
			}
		})
	})
	t.Run("ignores a request for a stream it does not publish", func(t *testing.T) {
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
	})
	t.Run("sends the message given to Accept", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			if _, err := reqs.all()[0].Accept(t.Context(), sdp, "hello ü"); err != nil {
				t.Fatal(err)
			}
			if got := e.h.commands("respondjoinstreamrequest")[0].params["msg"]; got != "hello ü" {
				t.Errorf("msg = %q", got)
			}
		})
	})
	t.Run("forgets a pending request when its client leaves view, so a reused id is heard", func(t *testing.T) {
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
	})
}

func TestJoinRequestClosing(t *testing.T) {
	setup := func(t *testing.T, e *env) (*Published, *JoinRequest, *collector[RequestCloseCause]) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		closed := new(collector[RequestCloseCause])
		r := reqs.all()[0]
		r.OnClosed(closed.add)

		return p, r, closed
	}
	t.Run("emits withdrawn when the viewer takes the request back, or leaves view", func(t *testing.T) {
		for name, act := range map[string]func(e *env, p *Published){
			"takes it back": func(e *env, p *Published) { e.withdraw(p, 9) },
			"leaves view":   func(e *env, _ *Published) { e.h.leave(9) },
			"leaves stream": func(e *env, p *Published) {
				e.h.notify(notify.StreamClientLeft, map[string]string{"id": string(p.ID()), "clid": "9"})
			},
		} {
			t.Run(name, func(t *testing.T) {
				run(t, func(t *testing.T, e *env) {
					p, r, closed := setup(t, e)
					act(e, p)
					e.settle()
					if got := closed.all(); len(got) != 1 || got[0] != CloseWithdrawn || r.State() != RequestWithdrawn {
						t.Errorf("closed = %v, state %v", got, r.State())
					}
				})
			})
		}
	})
	t.Run("emits ended when the stream stops, is stopped here or is closed", func(t *testing.T) {
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
					p, r, closed := setup(t, e)
					act(e, p)
					e.settle()
					if got := closed.all(); len(got) != 1 || got[0] != CloseEnded || r.State() != RequestEnded {
						t.Errorf("closed = %v, state %v", got, r.State())
					}
					if _, err := r.Accept(t.Context(), sdp, ""); !errors.Is(err, ErrNotPending) {
						t.Errorf("Accept err = %v", err)
					}
				})
			})
		}
	})
	t.Run("emits once", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p, _, closed := setup(t, e)
			e.withdraw(p, 9)
			e.withdraw(p, 9)
			e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
			e.settle()
			if closed.len() != 1 {
				t.Errorf("closed = %v", closed.all())
			}
		})
	})
	t.Run("emits nothing for a request that is accepted or denied, then the stream ends", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.h.see(10, nil)
			e.ask(p, 9, "")
			e.ask(p, 10, "")
			e.settle()
			var closed collector[RequestCloseCause]
			for _, r := range reqs.all() {
				r.OnClosed(closed.add)
			}
			if _, err := reqs.all()[0].Accept(t.Context(), sdp, ""); err != nil {
				t.Fatal(err)
			}
			if err := reqs.all()[1].Deny(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
			e.settle()
			if closed.len() != 0 {
				t.Errorf("closed = %v", closed.all())
			}
		})
	})
	t.Run("emits nothing for a request whose answer failed", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p, r, closed := setup(t, e)
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.StreamNotFound), s.name == "respondjoinstreamrequest"
			}
			_, err := r.Accept(t.Context(), sdp, "")
			var ended *EndedError
			if !errors.As(err, &ended) {
				t.Fatalf("err = %v, want *EndedError", err)
			}
			e.withdraw(p, 9)
			e.settle()
			if closed.len() != 0 {
				t.Errorf("closed = %v", closed.all())
			}
		})
	})
	t.Run("keeps the event for a handler that comes late, and delivers it to the first only", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			reqs := requests(p)
			e.h.see(9, nil)
			e.ask(p, 9, "")
			e.settle()
			e.withdraw(p, 9)
			e.settle()
			var first, second collector[RequestCloseCause]
			reqs.all()[0].OnClosed(first.add)
			reqs.all()[0].OnClosed(second.add)
			e.settle()
			if first.len() != 1 || second.len() != 0 {
				t.Errorf("first %d, second %d", first.len(), second.len())
			}
		})
	})
	t.Run("gives a request asked again after a withdrawal its own event", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p, _, closed := setup(t, e)
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
	})
}

func TestOffersWithoutAudio(t *testing.T) {
	const video = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
	setup := func(t *testing.T, e *env) (*Published, *JoinRequest, *collector[Warning]) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.see(9, nil)
		e.ask(p, 9, "")
		e.settle()
		warnings := new(collector[Warning])
		e.s.OnWarning(warnings.add)

		return p, reqs.all()[0], warnings
	}
	t.Run("warns on accept, and still sends the offer unchanged", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p, r, warnings := setup(t, e)
			if _, err := r.Accept(t.Context(), video, ""); err != nil {
				t.Fatal(err)
			}
			e.settle()
			got := warnings.all()
			if len(got) != 1 || got[0].Code != WarningOfferWithoutAudio || got[0].StreamID != p.ID() || got[0].ClientID != 9 || got[0].Message == "" {
				t.Errorf("warnings = %+v", got)
			}
			if e.h.commands("respondjoinstreamrequest")[0].params["offer"] != video {
				t.Error("the offer was changed")
			}
		})
	})
	t.Run("does not warn for an offer with an audio section, in any order", func(t *testing.T) {
		for _, offer := range []string{sdp, "v=0\r\nm=video 9 X 96\r\nm=audio 9 X 111\r\n", "m=audio\t9 X 1\r\n"} {
			run(t, func(t *testing.T, e *env) {
				_, r, warnings := setup(t, e)
				if _, err := r.Accept(t.Context(), offer, ""); err != nil {
					t.Fatal(err)
				}
				e.settle()
				if warnings.len() != 0 {
					t.Errorf("warned for %q", offer)
				}
			})
		}
	})
	t.Run("warns on a renegotiation offer without audio, and sends it", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			_, r, warnings := setup(t, e)
			peer, err := r.Accept(t.Context(), sdp, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.SendOffer(t.Context(), video); err != nil {
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
	})
	t.Run("does not warn for a denial, or for an offer refused as too long", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			_, r, warnings := setup(t, e)
			if _, err := r.Accept(t.Context(), strings.Repeat("v", MaxCommandLineBytes), ""); err == nil {
				t.Fatal("no error")
			}
			if err := r.Deny(t.Context(), "no"); err != nil {
				t.Fatal(err)
			}
			e.settle()
			if warnings.len() != 0 {
				t.Errorf("warnings = %+v", warnings.all())
			}
		})
	})
	t.Run("keeps warnings for the first handler, bounded", func(t *testing.T) {
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
				if err := peer.SendOffer(t.Context(), video); err != nil {
					t.Fatal(err)
				}
			}
			var warnings collector[Warning]
			e.s.OnWarning(warnings.add)
			e.settle()
			if warnings.len() != maxKept {
				t.Errorf("warnings = %d, want %d", warnings.len(), maxKept)
			}
		})
	})
}

func acceptViewer(t *testing.T, e *env, p *Published, clid int) *ViewerPeer {
	t.Helper()
	reqs := requests(p)
	e.h.see(teamspeak.ClientID(clid), nil)
	e.ask(p, clid, "")
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

func TestViewerPeer(t *testing.T) {
	t.Run("delivers an answer and candidates, and sends candidates and offers", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var answers collector[string]
			var cands collector[IceCandidate]
			peer.OnAnswer(answers.add)
			peer.OnCandidate(cands.add)
			e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"answer","args":{"answer":"v=0"}}`))
			e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}`))
			e.settle()
			if got := answers.all(); len(got) != 1 || got[0] != "v=0" {
				t.Errorf("answers = %v", got)
			}
			want := IceCandidate{Candidate: "candidate:1", SDPMid: ptr("0"), SDPMLineIndex: ptr(uint16(0))}
			if got := cands.all(); len(got) != 1 || got[0].Candidate != want.Candidate || *got[0].SDPMid != "0" || *got[0].SDPMLineIndex != 0 {
				t.Errorf("candidates = %+v", got)
			}
			if err := peer.SendCandidate(t.Context(), want); err != nil {
				t.Fatal(err)
			}
			sig := e.h.commands("streamsignaling")[0]
			if sig.params["id"] != string(p.ID()) || sig.params["clid"] != "9" ||
				sig.params["json"] != `{"cmd":"iceCandidate","args":{"sdp":"candidate:1","mid":"0","mLine":0}}` {
				t.Errorf("sent = %v", sig.params)
			}
		})
	})
	t.Run("keeps what arrives before a handler, for the first handler of each event", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
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
	})
	t.Run("hands over messages it has no name for, and text that is no message", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var raws collector[RawSignal]
			peer.OnSignal(raws.add)
			e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"mute","args":{"on":true}}`))
			e.h.notify(notify.StreamSignaling, relay(p, 9, "not json"))
			e.settle()
			got := raws.all()
			if len(got) != 2 || got[0].Cmd != "mute" || string(got[0].Args) != `{"on":true}` || got[1].Cmd != "" || got[1].JSON != "not json" || got[1].Args != nil {
				t.Errorf("raw = %+v", got)
			}
		})
	})
	t.Run("sends a message of the applications own", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			if err := peer.SendSignal(t.Context(), "mute", map[string]bool{"on": true}); err != nil {
				t.Fatal(err)
			}
			if got := e.h.commands("streamsignaling")[0].params["json"]; got != `{"cmd":"mute","args":{"on":true}}` {
				t.Errorf("json = %q", got)
			}
			if err := peer.SendSignal(t.Context(), "ping", nil); err != nil {
				t.Fatal(err)
			}
			if got := e.h.commands("streamsignaling")[1].params["json"]; got != `{"cmd":"ping"}` {
				t.Errorf("json = %q", got)
			}
			if err := peer.SendSignal(t.Context(), "x", make(chan int)); err == nil {
				t.Error("an unencodable argument was sent")
			}
		})
	})
	t.Run("refuses a message too long before sending", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			before := e.h.count()
			var big *PayloadTooLargeError
			if err := peer.SendSignal(t.Context(), "big", strings.Repeat("x", MaxCommandLineBytes)); !errors.As(err, &big) {
				t.Errorf("err = %v", err)
			}
			if e.h.count() != before {
				t.Error("sent a command")
			}
		})
	})
	t.Run("closes when the viewer leaves, however it says so, once", func(t *testing.T) {
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
					peer := acceptViewer(t, e, p, 9)
					var closed collector[PeerClosed]
					peer.OnClosed(closed.add)
					act(e, p)
					act(e, p)
					e.settle()
					// Leaving view closes only a request; a peer stays until it is told.
					if name == "left view" {
						return
					}
					if got := closed.all(); len(got) != 1 || got[0].Cause != CauseLeft || !peer.Closed() || len(p.Viewers()) != 0 {
						t.Errorf("closed = %+v", got)
					}
					if err := peer.SendCandidate(t.Context(), IceCandidate{Candidate: "c"}); !errors.Is(err, ErrClosed) {
						t.Errorf("send on a closed peer: %v", err)
					}
				})
			})
		}
	})
	t.Run("does not close when another viewer leaves", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			e.withdraw(p, 10)
			e.settle()
			if peer.Closed() {
				t.Error("closed")
			}
		})
	})
	t.Run("closes without sending anything when the application closes it", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var closed collector[PeerClosed]
			peer.OnClosed(closed.add)
			before := e.h.count()
			if err := peer.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := peer.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.settle()
			if e.h.count() != before || closed.len() != 1 || closed.all()[0].Cause != CauseClosed {
				t.Errorf("sent %d, closed %+v", e.h.count()-before, closed.all())
			}
		})
	})
	t.Run("ignores what a closed viewer still sends, without an error", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var errs collector[error]
			e.s.OnError(errs.add)
			if err := peer.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.h.notify(notify.StreamSignaling, relay(p, 9, `{"cmd":"iceCandidate","args":{"sdp":"late"}}`))
			e.h.notify(notify.StreamSignaling, relay(p, 77, `{"cmd":"iceCandidate","args":{"sdp":"stranger"}}`))
			e.settle()
			if got := errs.all(); len(got) != 1 || !strings.Contains(got[0].Error(), "client 77") {
				t.Errorf("errors = %v", got)
			}
		})
	})
}

func TestStoppingAStream(t *testing.T) {
	t.Run("sends stopstream with the reason, ends the stream here, and tells nobody else", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var ended collector[Ended]
			var stopped collector[StoppedEvent]
			var closed collector[PeerClosed]
			p.OnEnded(ended.add)
			e.s.OnStopped(stopped.add)
			peer.OnClosed(closed.add)
			if err := p.Stop(t.Context(), 7); err != nil {
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
			if got := ended.all(); len(got) != 1 || got[0] != (Ended{Cause: CauseStopped, Reason: 7}) {
				t.Errorf("ended = %+v", got)
			}
			if got := stopped.all(); len(got) != 1 || got[0].Cause != CauseStopped || got[0].Reason != 7 {
				t.Errorf("stopped = %+v", got)
			}
			if got := closed.all(); len(got) != 1 || got[0] != (PeerClosed{Cause: CauseStopped, Reason: 7}) {
				t.Errorf("peer closed = %+v", got)
			}
			// Stopping again sends nothing.
			if err := p.Stop(t.Context(), 0); err != nil || len(e.h.commands("stopstream")) != 1 {
				t.Errorf("second stop: %v", err)
			}
		})
	})
	t.Run("counts a stream the server no longer knows as stopped", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.StreamNotFound), s.name == "stopstream"
			}
			if err := p.Stop(t.Context(), 0); err != nil || !p.Ended() {
				t.Errorf("err %v, ended %v", err, p.Ended())
			}
		})
	})
	t.Run("leaves the stream running when the server refuses the command", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "stopstream"
			}
			if err := p.Stop(t.Context(), 0); !errors.Is(err, errcode.PermissionsClientInsufficient) || p.Ended() {
				t.Errorf("err %v, ended %v", err, p.Ended())
			}
		})
	})
	t.Run("ends on the servers word, whoever stopped it, with the reason", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
			var ended collector[Ended]
			var closed collector[PeerClosed]
			p.OnEnded(ended.add)
			peer.OnClosed(closed.add)
			e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID()), "clid": "1", "reason": "1"})
			e.settle()
			if got := ended.all(); len(got) != 1 || got[0] != (Ended{Cause: CauseServer, Reason: 1}) {
				t.Errorf("ended = %+v", got)
			}
			if got := closed.all(); len(got) != 1 || got[0] != (PeerClosed{Cause: CauseStopped, Reason: 1}) {
				t.Errorf("closed = %+v", got)
			}
		})
	})
	t.Run("keeps the ended event for a handler that comes late", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			e.h.notify(notify.StreamStopped, map[string]string{"id": string(p.ID())})
			e.settle()
			var ended collector[Ended]
			p.OnEnded(ended.add)
			e.settle()
			if got := ended.all(); len(got) != 1 || got[0].Cause != CauseServer {
				t.Errorf("ended = %+v", got)
			}
		})
	})
}

func TestEventsNobodyListensFor(t *testing.T) {
	t.Run("keeps errors for the first handler, and then delivers them live", func(t *testing.T) {
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
	})
	t.Run("drops the oldest past the bound, and reports an overflowing peer once", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "x"})
			peer := acceptViewer(t, e, p, 9)
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
	})
	t.Run("does not let a panicking handler stop the others", func(t *testing.T) {
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
	})
	t.Run("stops delivering to a handler that was removed", func(t *testing.T) {
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
	})
	t.Run("hands each handler its own copy", func(t *testing.T) {
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
	})
}

var _ = context.Background
