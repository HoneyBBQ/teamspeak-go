package stream

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/notify"
)

func TestUnsupportedServer(t *testing.T) {
	t.Run("refuses publish and watch before sending anything", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.family, h.version = client.ServerFamilyTS3, "3.13.8" },
			func(t *testing.T, e *env) {
				var unsupported *UnsupportedError
				_, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"})
				if !errors.As(err, &unsupported) {
					t.Fatalf("Publish err = %v, want *UnsupportedError", err)
				}
				_, err = e.s.WatchInfo(t.Context(), Info{ID: "a", ClientID: 3}, WatchOptions{})
				if !errors.As(err, &unsupported) {
					t.Fatalf("WatchInfo err = %v, want *UnsupportedError", err)
				}
				if e.h.count() != 0 {
					t.Errorf("sent %d commands, want none", e.h.count())
				}
				if e.s.Supported() {
					t.Error("Supported = true on TeamSpeak 3")
				}
			})
	})
	t.Run("names what the server is", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.family, h.version = client.ServerFamilyTS3, "3.13.8" },
			func(t *testing.T, e *env) {
				_, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"})
				var u *UnsupportedError
				if !errors.As(err, &u) || u.Family != client.ServerFamilyTS3 || u.Version != "3.13.8" {
					t.Fatalf("err = %#v", err)
				}
				if !strings.Contains(err.Error(), "ts3") && !strings.Contains(err.Error(), "TS3") {
					t.Errorf("message %q does not name the family", err)
				}
			})
	})
	t.Run("treats a server not yet known as unsupported", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.family, h.version, h.status = client.ServerFamilyUnknown, "", client.StatusDisconnected },
			func(t *testing.T, e *env) {
				_, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"})
				var u *UnsupportedError
				if !errors.As(err, &u) || u.Family != client.ServerFamilyUnknown {
					t.Fatalf("err = %v", err)
				}
				if !strings.Contains(err.Error(), "unknown server") {
					t.Errorf("message %q", err)
				}
			})
	})
	t.Run("sends nothing when a client seems to stream", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.family = client.ServerFamilyTS3 }, func(t *testing.T, e *env) {
			e.h.enter(7, ptr(true))
			e.h.setStreaming(8, true)
			e.settle()
			if e.h.count() != 0 {
				t.Errorf("sent %d commands", e.h.count())
			}
		})
	})
}

func TestDiscovery(t *testing.T) {
	t.Run("asks once for a client that comes into view streaming", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(7, ptr(true))
			e.h.setStreaming(7, true)
			e.settle()
			asks := e.h.commands("requeststreaminfo")
			if len(asks) != 1 || asks[0].params["clid"] != "7" {
				t.Fatalf("asked %v", asks)
			}
		})
	})
	t.Run("asks for the clients already in view when it attaches", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.see(7, ptr(true)); h.see(8, ptr(false)); h.see(9, nil) },
			func(t *testing.T, e *env) {
				e.settle()
				asks := e.h.commands("requeststreaminfo")
				if len(asks) != 1 || asks[0].params["clid"] != "7" {
					t.Fatalf("asked %v", asks)
				}
			})
	})
	t.Run("asks for them again once connected", func(t *testing.T) {
		runWith(t, Options{}, func(h *fakeHost) { h.see(7, ptr(true)); h.status = client.StatusConnecting },
			func(t *testing.T, e *env) {
				e.settle()
				if e.h.count() != 0 {
					t.Fatalf("asked while connecting: %v", e.h.log)
				}
				e.h.connect()
				e.settle()
				if len(e.h.commands("requeststreaminfo")) != 1 {
					t.Errorf("asked %d times after connecting", len(e.h.commands("requeststreaminfo")))
				}
			})
	})
	t.Run("asks again when the flag clears and later comes back", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(7, ptr(true))
			e.h.setStreaming(7, false)
			e.h.setStreaming(7, true)
			e.settle()
			if got := len(e.h.commands("requeststreaminfo")); got != 2 {
				t.Errorf("asked %d times, want 2", got)
			}
		})
	})
	t.Run("asks again for a client that went out of view and came back", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(7, ptr(true))
			e.h.leave(7)
			e.h.enter(7, ptr(true))
			e.settle()
			if got := len(e.h.commands("requeststreaminfo")); got != 2 {
				t.Errorf("asked %d times, want 2", got)
			}
		})
	})
	t.Run("does not ask about itself, a clid of 0, or before it is connected", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.enter(1, ptr(true))
			e.h.enter(0, ptr(true))
			e.h.mu.Lock()
			e.h.status = client.StatusConnecting
			e.h.mu.Unlock()
			e.h.enter(9, ptr(true))
			e.settle()
			if e.h.count() != 0 {
				t.Errorf("sent %v", e.h.log)
			}
		})
	})
	t.Run("learns every stream of a client, one notification each, and tolerates an empty answer", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var started collector[Info]
			e.s.OnStarted(started.add)
			e.h.notify(notify.StreamInfo, map[string]string{"clid": "7", "id": "a", "name": "one", "return_code": "4"})
			e.h.notify(notify.StreamInfo, map[string]string{"clid": "7", "id": "b", "name": "two"})
			e.h.notify(notify.StreamInfo, map[string]string{"return_code": "5"})
			e.settle()
			if got := started.all(); len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
				t.Errorf("started = %+v", got)
			}
			if len(e.s.List()) != 2 {
				t.Errorf("List = %+v", e.s.List())
			}
		})
	})
	t.Run("reports an error nobody awaits, and asks again next time", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var errs collector[error]
			e.s.OnError(errs.add)
			refused := serverError(errcode.PermissionsClientInsufficient)
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				if s.name == "requeststreaminfo" {
					return nil, refused, true
				}

				return nil, nil, false
			}
			e.h.enter(7, ptr(true))
			e.settle()
			if got := errs.all(); len(got) != 1 || !errors.Is(got[0], refused) {
				t.Fatalf("errors = %v", got)
			}
			e.h.setStreaming(7, true)
			e.settle()
			if got := len(e.h.commands("requeststreaminfo")); got != 2 {
				t.Errorf("asked %d times, want 2", got)
			}
		})
	})
	t.Run("does not report a connection that is gone", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var errs collector[error]
			e.s.OnError(errs.add)
			e.h.reply = func(s sent) ([]map[string]string, error, bool) {
				return nil, teamspeak.ErrNotConnected, s.name == "requeststreaminfo"
			}
			e.h.enter(7, ptr(true))
			e.settle()
			if errs.len() != 0 {
				t.Errorf("errors = %v", errs.all())
			}
		})
	})
}

func TestKnownStreams(t *testing.T) {
	t.Run("merges the announcement and the info, and reports a change as updated", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var started, updated collector[Info]
			e.s.OnStarted(started.add)
			e.s.OnUpdated(updated.add)
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.notify(notify.StreamInfo, map[string]string{"id": "a", "viewer": "2"})
			e.h.notify(notify.StreamInfo, map[string]string{"id": "a", "viewer": "2"})
			e.settle()
			if started.len() != 1 || updated.len() != 1 {
				t.Fatalf("started %d, updated %d", started.len(), updated.len())
			}
			info, ok := e.s.Get("a")
			if !ok || info.Viewers == nil || *info.Viewers != 2 || info.Name != "Demo" || info.ClientID != 5 {
				t.Errorf("info = %+v", info)
			}
			if info.Source == nil || *info.Source != SourceScreen || info.Accessibility == nil || *info.Accessibility != AccessibilityPublic {
				t.Errorf("info = %+v", info)
			}
		})
	})
	t.Run("keeps the other streams of a client when one stops", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var stopped collector[StoppedEvent]
			e.s.OnStopped(stopped.add)
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.notify(notify.StreamStarted, announcement("b", 5))
			e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "clid": "5", "reason": "3"})
			e.settle()
			if got := stopped.all(); len(got) != 1 || got[0].Info.ID != "a" || got[0].Cause != CauseServer || got[0].Reason != 3 {
				t.Errorf("stopped = %+v", got)
			}
			if list := e.s.List(); len(list) != 1 || list[0].ID != "b" {
				t.Errorf("List = %+v", list)
			}
		})
	})
	t.Run("keeps a stream when its publisher changes channel or leaves view", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.leave(5)
			e.settle()
			time.Sleep(10 * time.Second)
			if _, ok := e.s.Get("a"); !ok {
				t.Error("the stream was forgotten")
			}
		})
	})
	t.Run("reports a viewer joining and leaving", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var joined, left collector[ViewerEvent]
			e.s.OnViewerJoined(joined.add)
			e.s.OnViewerLeft(left.add)
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.h.notify(notify.StreamClientJoined, map[string]string{"id": "a", "clid": "9"})
			e.h.notify(notify.StreamClientLeft, map[string]string{"id": "a", "clid": "9"})
			e.h.notify(notify.StreamClientJoined, map[string]string{"id": "unknown", "clid": "9"})
			e.settle()
			if joined.len() != 1 || left.len() != 1 || joined.all()[0].ClientID != 9 || joined.all()[0].Info.ID != "a" {
				t.Errorf("joined %+v, left %+v", joined.all(), left.all())
			}
		})
	})
	t.Run("hands out copies", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.h.notify(notify.StreamStarted, announcement("a", 5))
			e.settle()
			got := e.s.List()
			*got[0].Bitrate = 1
			again, _ := e.s.Get("a")
			if *again.Bitrate != 58208 {
				t.Errorf("a change to a copy reached the Streams: bitrate %d", *again.Bitrate)
			}
		})
	})
}

func TestPublish(t *testing.T) {
	t.Run("sends setupstream with all seven parameters and resolves on the announcement", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			p := e.publish(PublishOptions{Name: "my stream"})
			setup := e.h.commands("setupstream")
			if len(setup) != 1 {
				t.Fatalf("sent %d setupstream", len(setup))
			}
			want := "setupstream name=my\\sstream type=2 bitrate=1500000 accessibility=1 mode=1 viewer_limit=0 audio=0"
			if setup[0].line != want {
				t.Errorf("line = %q, want %q", setup[0].line, want)
			}
			if p.ID() != "pub-1" || p.Ended() || p.Info().Name != "Demo" {
				t.Errorf("published = %v %v %+v", p.ID(), p.Ended(), p.Info())
			}
		})
	})
	t.Run("sends the options as given", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			e.publish(PublishOptions{
				Name: "n", Source: ptr(SourceWindow), Bitrate: ptr(0), Accessibility: ptr(AccessibilityPrivate),
				ViewerLimit: 65535, Audio: true,
			})
			want := "setupstream name=n type=3 bitrate=0 accessibility=3 mode=1 viewer_limit=65535 audio=1"
			if got := e.h.commands("setupstream")[0].line; got != want {
				t.Errorf("line = %q, want %q", got, want)
			}
		})
	})
	t.Run("refuses options out of range without sending", func(t *testing.T) {
		for name, opts := range map[string]PublishOptions{
			"unknown source":        {Source: ptr(Source(9))},
			"unknown accessibility": {Accessibility: ptr(Accessibility(4))},
			"negative bitrate":      {Bitrate: ptr(-1)},
			"huge bitrate":          {Bitrate: ptr(2_147_483_648)},
			"negative viewer limit": {ViewerLimit: -1},
			"huge viewer limit":     {ViewerLimit: 65536},
		} {
			t.Run(name, func(t *testing.T) {
				run(t, func(t *testing.T, e *env) {
					_, err := e.s.Publish(t.Context(), opts)
					if !errors.Is(err, ErrInvalidOptions) {
						t.Errorf("err = %v, want ErrInvalidOptions", err)
					}
					if e.h.count() != 0 {
						t.Error("sent a command")
					}
				})
			})
		}
	})
	t.Run("refuses a name too long to send, without sending", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			_, err := e.s.Publish(t.Context(), PublishOptions{Name: strings.Repeat("x", 9200)})
			var big *PayloadTooLargeError
			if !errors.As(err, &big) || big.Command != "setupstream" || big.Limit != MaxCommandLineBytes || big.Size <= big.Limit {
				t.Fatalf("err = %v", err)
			}
			if e.h.count() != 0 {
				t.Error("sent a command")
			}
		})
	})
	t.Run("matches each announcement to its call when several are made, in any order", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			got := make(chan *Published, 2)
			for range 2 {
				go func() {
					p, err := e.s.Publish(t.Context(), PublishOptions{Name: "same"})
					if err != nil {
						t.Error(err)
					}
					got <- p
				}()
				e.settle()
			}
			// The second command is announced first.
			e.h.announce(t, announcement("second", 1), 1)
			e.h.announce(t, announcement("first", 1), 0)
			e.settle()
			ids := map[ID]bool{(<-got).ID(): true, (<-got).ID(): true}
			if !ids["first"] || !ids["second"] {
				t.Errorf("ids = %v", ids)
			}
		})
	})
	t.Run("hands the first call the stream the first command started", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			first := make(chan *Published, 1)
			go func() { p, _ := e.s.Publish(t.Context(), PublishOptions{Name: "same"}); first <- p }()
			e.settle()
			go func() { _, _ = e.s.Publish(t.Context(), PublishOptions{Name: "same"}) }()
			e.settle()
			e.h.announce(t, announcement("B", 1), 1)
			e.h.announce(t, announcement("A", 1), 0)
			e.settle()
			if p := <-first; p.ID() != "A" {
				t.Errorf("first call got %s, want A", p.ID())
			}
		})
	})
	t.Run("does not take another client's stream for its own", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "Demo"}); done <- err }()
			e.settle()
			e.h.notify(notify.StreamStarted, announcement("foreign", 9))
			e.settle()
			select {
			case err := <-done:
				t.Fatalf("Publish returned %v on a foreign stream", err)
			default:
			}
			e.h.announce(t, announcement("mine", 1), 0)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, ok := e.s.Get("foreign"); !ok {
				t.Error("the foreign stream is not known")
			}
		})
	})
	t.Run("fails with the server's refusal, and then publishes again", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			refused := serverError(errcode.PermissionsClientInsufficient)
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			e.h.failSetup(t, refused, 0)
			if err := <-done; !errors.Is(err, errcode.PermissionsClientInsufficient) {
				t.Fatalf("err = %v", err)
			}
			if p := e.publish(PublishOptions{Name: "x"}); p == nil {
				t.Error("no stream")
			}
		})
	})
	t.Run("stops waiting when the context ends", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(ctx, PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v", err)
			}
		})
	})
	t.Run("rejects while pending when the connection ends", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			e.h.disconnect()
			if err := <-done; !errors.Is(err, teamspeak.ErrNotConnected) {
				t.Errorf("err = %v", err)
			}
		})
	})
	t.Run("takes ten seconds without a deadline, and keeps the command open five more", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			start := time.Now()
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			err := <-done
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 10*time.Second {
				t.Fatalf("err = %v after %v", err, time.Since(start))
			}
			if e.h.pendingSetups() != 1 {
				t.Fatalf("the command was cancelled with the caller")
			}
			time.Sleep(5*time.Second - time.Millisecond)
			if e.h.pendingSetups() != 1 {
				t.Fatal("the command ended before the window did")
			}
			time.Sleep(time.Millisecond)
			e.settle()
			if e.h.pendingSetups() != 0 {
				t.Error("the command outlived the window")
			}
		})
	})
	t.Run("uses the callers deadline, and keeps the command open five more", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := e.s.Publish(ctx, PublishOptions{Name: "x"})
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 30*time.Millisecond {
				t.Fatalf("err = %v after %v", err, time.Since(start))
			}
			time.Sleep(4 * time.Second)
			if e.h.pendingSetups() != 1 {
				t.Error("the command ended with the caller")
			}
		})
	})
}

func TestPublishGivingUp(t *testing.T) {
	gaveUp := func(t *testing.T, e *env) (cancel func(), done chan error) {
		ctx, cancelCtx := context.WithCancel(t.Context())
		done = make(chan error, 1)
		go func() { _, err := e.s.Publish(ctx, PublishOptions{Name: "x"}); done <- err }()
		e.settle()
		cancelCtx()
		<-done

		return cancelCtx, done
	}
	t.Run("stops a stream a call that gave up started, known from the answer only", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			gaveUp(t, e)
			e.h.announceAfterError(t, announcement("late", 1), 0)
			e.settle()
			stops := e.h.commands("stopstream")
			if len(stops) != 1 || stops[0].params["id"] != "late" {
				t.Fatalf("stops = %v", stops)
			}
			if len(e.s.List()) != 0 {
				t.Errorf("List = %+v", e.s.List())
			}
		})
	})
	t.Run("reports a stream stopped when it was reported started", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			var started collector[Info]
			var stopped collector[StoppedEvent]
			e.s.OnStarted(started.add)
			e.s.OnStopped(stopped.add)
			gaveUp(t, e)
			e.h.announce(t, announcement("late", 1), 0)
			e.settle()
			if started.len() != 1 || stopped.len() != 1 || stopped.all()[0].Cause != CauseStopped {
				t.Errorf("started %d, stopped %+v", started.len(), stopped.all())
			}
			if len(e.h.commands("stopstream")) != 1 {
				t.Errorf("stops = %v", e.h.commands("stopstream"))
			}
		})
	})
	t.Run("does not bring a stopped orphan back with a later row about it", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			gaveUp(t, e)
			e.h.announce(t, announcement("late", 1), 0)
			e.settle()
			e.h.notify(notify.StreamInfo, map[string]string{"id": "late", "clid": "1", "name": "Demo"})
			e.settle()
			if len(e.s.List()) != 0 {
				t.Errorf("List = %+v", e.s.List())
			}
			// Its stop ends the memory of it.
			e.h.notify(notify.StreamStopped, map[string]string{"id": "late"})
			e.h.notify(notify.StreamInfo, map[string]string{"id": "late", "clid": "1"})
			e.settle()
			if len(e.s.List()) != 1 {
				t.Errorf("List = %+v", e.s.List())
			}
		})
	})
	t.Run("does not stop anything when the server refused the command", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			gaveUp(t, e)
			e.h.failSetup(t, serverError(errcode.PermissionsClientInsufficient), 0)
			e.settle()
			if got := e.h.commands("stopstream"); len(got) != 0 {
				t.Errorf("stops = %v", got)
			}
		})
	})
	t.Run("leaves a stream announced after the window for good", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			gaveUp(t, e)
			time.Sleep(6 * time.Second)
			e.settle()
			e.h.notify(notify.StreamStarted, announcement("too-late", 1))
			e.settle()
			if got := e.h.commands("stopstream"); len(got) != 0 {
				t.Errorf("stops = %v", got)
			}
			if _, ok := e.s.Get("too-late"); !ok {
				t.Error("the stream is not in the list")
			}
		})
	})
	t.Run("stops nothing for an answer after the connection ended", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			e.h.disconnect()
			<-done
			e.h.connect()
			e.h.announce(t, announcement("old", 1), 0)
			e.settle()
			if got := e.h.commands("stopstream"); len(got) != 0 {
				t.Errorf("stops = %v", got)
			}
		})
	})
	t.Run("stops the stream a Publish started when closed before the announcement", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			if err := e.s.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, ErrClosed) {
				t.Fatalf("err = %v", err)
			}
			e.h.announce(t, announcement("after", 1), 0)
			e.settle()
			if got := e.h.commands("stopstream"); len(got) != 1 || got[0].params["id"] != "after" {
				t.Errorf("stops = %v", got)
			}
		})
	})
	t.Run("stops nothing for a Publish answered after Close when the connection is gone", func(t *testing.T) {
		run(t, func(t *testing.T, e *env) {
			done := make(chan error, 1)
			go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
			e.settle()
			e.h.disconnect()
			if err := e.s.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			<-done
			e.h.announce(t, announcement("after", 1), 0)
			e.settle()
			if got := e.h.commands("stopstream"); len(got) != 0 {
				t.Errorf("stops = %v", got)
			}
		})
	})
}

func TestPublishedSettlesOnce(t *testing.T) {
	// A caller whose context ends in the instant the answer lands still gets
	// the stream, and the stream is not stopped as an orphan.
	run(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithCancel(t.Context())
		type result struct {
			p   *Published
			err error
		}
		done := make(chan result, 1)
		go func() { p, err := e.s.Publish(ctx, PublishOptions{Name: "x"}); done <- result{p, err} }()
		e.settle()
		e.h.announce(t, announcement("s", 1), 0)
		cancel()
		r := <-done
		e.settle()
		if r.err != nil {
			if !errors.Is(r.err, context.Canceled) {
				t.Fatalf("err = %v", r.err)
			}
			// It gave up first: then the stream was stopped, not leaked.
			if len(e.h.commands("stopstream")) != 1 {
				t.Errorf("gave up but did not stop: %v", e.h.commands("stopstream"))
			}

			return
		}
		if r.p.ID() != "s" || len(e.h.commands("stopstream")) != 0 {
			t.Errorf("got %v, stops %v", r.p.ID(), e.h.commands("stopstream"))
		}
	})
}

var _ = strconv.Itoa
