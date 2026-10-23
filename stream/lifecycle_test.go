package stream

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/notify"
)

// A 5635 on a join request proves the stream is gone: it leaves the list, with
// the same events as any other end, and no further request goes out for it.
func TestWatch_EndsTheStreamLocallyWhenTheServerSaysItDoesNotExist(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		e.streamOf5()
		e.joinReply(func() ([]map[string]string, error) { return nil, serverError(errcode.StreamNotFound) })
		r := <-e.startWatch(t.Context())
		var ended *EndedError
		if !errors.As(r.err, &ended) {
			t.Fatalf("Watch err = %v, want *EndedError", r.err)
		}
		if len(e.s.List()) != 0 {
			t.Errorf("List = %+v", e.s.List())
		}
		if got := stopped.all(); len(got) != 1 || got[0].Cause != EndCauseGone {
			t.Errorf("stopped = %+v", got)
		}
		_, err := e.s.Watch(t.Context(), "a", WatchOptions{})
		if !errors.As(err, &ended) {
			t.Errorf("second Watch err = %v", err)
		}
		if got := len(e.h.commands("joinstreamrequest")); got != 1 {
			t.Errorf("joins = %d, want 1", got)
		}
	})
}

// A stop heard before the answer to the setupstream: the answer does not adopt
// a stream that is over.
func TestPublish_DoesNotAdoptAStreamStoppedBeforeItsAnswer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		done := e.publishAsync()
		row := announcement("dead", 1)
		ps := e.h.takeSetup(t, 0)
		row["return_code"] = ps.returnCode
		e.h.notify(notify.StreamStarted, row)
		e.h.notify(notify.StreamStopped, map[string]string{"id": "dead", "reason": "3"})
		ps.result <- setupResult{rows: []map[string]string{row}}
		err := <-done
		var ended *EndedError
		if !errors.As(err, &ended) || ended.StreamID != "dead" {
			t.Fatalf("Publish err = %v", err)
		}
		e.settle()
		if len(e.s.List()) != 0 {
			t.Errorf("List = %+v", e.s.List())
		}
	})
}

// A timer that was stopped can still fire, after the client has been given a
// newer wait: it must not end the streams ahead of that one.
func TestGone_AStaleTimerDoesNotEndAStreamEarly(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.streamOf5()
		e.h.setStreaming(5, false)
		e.settle()
		e.s.goneFired(5, &goneTimer{})
		e.settle()
		if len(e.s.List()) != 1 {
			t.Fatalf("a stale timer ended the stream: %+v", e.s.List())
		}
		time.Sleep(goneGrace + time.Second)
		e.settle()
		if len(e.s.List()) != 0 {
			t.Errorf("the current timer did not end it: %+v", e.s.List())
		}
	})
}

// A reconnect may be given the client id the last connection had: the lagging
// disconnected event of the old one still ends what the old one started.
func TestLaggingDisconnect_EndsWhatTheOldConnectionStartedEvenUnderTheSameClientID(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		old := e.publish(PublishOptions{Name: "old"})
		e.streamOf5()
		watching := e.startWatch(t.Context())
		e.h.reconnectQuietly(e.h.self)
		fresh := e.publish(PublishOptions{Name: "fresh"})
		e.h.deliverDisconnected()
		e.settle()
		if !old.Ended() || fresh.Ended() {
			t.Errorf("old ended %v, fresh ended %v", old.Ended(), fresh.Ended())
		}
		if r := <-watching; !errors.Is(r.err, teamspeak.ErrNotConnected) {
			t.Errorf("Watch = %v, %v", r.view, r.err)
		}
	})
}

// A lookup answers for the request it was made for, not for the next request of
// a client id that was reused.
func TestJoinRequests_AStaleLookupDoesNotAnnounceTheWrongViewer(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		calls := 0
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name != "clientgetuidfromclid" {
				return nil, nil, false
			}
			calls++
			if calls == 1 {
				time.Sleep(time.Second)

				return []map[string]string{{"cluid": "old"}}, nil, true
			}

			return []map[string]string{{"cluid": "new"}}, nil, true
		}
		e.ask(p, 12, "old")
		e.settle()
		e.h.leave(12)
		e.ask(p, 12, "new")
		time.Sleep(2 * time.Second)
		e.settle()
		got := reqs.all()
		if len(got) != 1 || got[0].Viewer().UID != "new" || got[0].Message() != "new" {
			t.Errorf("requests = %+v", got)
		}
	})
}

// The lookups run side by side: one that is slow does not hold up the others,
// only their announcement.
func TestJoinRequests_RunsTheLookupsSideBySideAndAnnouncesInOrder(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name != "clientgetuidfromclid" {
				return nil, nil, false
			}
			time.Sleep(5 * time.Second)

			return []map[string]string{{"cluid": "u" + s.params["clid"]}}, nil, true
		}
		start := time.Now()
		for clid := 20; clid < 24; clid++ {
			e.ask(p, clid, strconv.Itoa(clid))
		}
		time.Sleep(6 * time.Second)
		e.settle()
		order := make([]string, 0, 4)
		for _, r := range reqs.all() {
			order = append(order, r.Message())
		}
		if strings.Join(order, ",") != "20,21,22,23" {
			t.Errorf("order = %v", order)
		}
		if elapsed := time.Since(start); elapsed >= 10*time.Second {
			t.Errorf("took %v, the lookups ran one after another", elapsed)
		}
	})
}

// Only so many lookups run at once.
func TestJoinRequests_BoundsTheLookupsOutAtOnce(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		p := e.publish(PublishOptions{Name: "x"})
		reqs := requests(p)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			if s.name != "clientgetuidfromclid" {
				return nil, nil, false
			}
			time.Sleep(5 * time.Second)

			return []map[string]string{{"cluid": "u"}}, nil, true
		}
		for clid := 20; clid < 20+3*maxLookups; clid++ {
			e.ask(p, clid, "")
		}
		time.Sleep(time.Second)
		e.settle()
		if got := len(e.h.commands("clientgetuidfromclid")); got != maxLookups {
			t.Errorf("lookups out = %d, want %d", got, maxLookups)
		}
		time.Sleep(30 * time.Second)
		e.settle()
		if reqs.len() != 3*maxLookups {
			t.Errorf("requests = %d", reqs.len())
		}
	})
}
