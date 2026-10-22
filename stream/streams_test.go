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

func TestUnsupportedServer_RefusesPublishAndWatchBeforeSendingAnything(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) { h.family, h.version = client.ServerFamilyTS3, "3.13.8" },
		func(t *testing.T, e *env) {
			var unsupported *UnsupportedError
			_, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"})
			if !errors.As(err, &unsupported) {
				t.Fatalf("Publish err = %v, want *UnsupportedError", err)
			}
			_, err = e.s.Watch(t.Context(), "a", WatchOptions{ClientID: 3})
			if !errors.As(err, &unsupported) {
				t.Fatalf("Watch err = %v, want *UnsupportedError", err)
			}
			if e.h.count() != 0 {
				t.Errorf("sent %d commands, want none", e.h.count())
			}
			if e.s.Supported() {
				t.Error("Supported = true on TeamSpeak 3")
			}
		})
}

func TestUnsupportedServer_NamesWhatTheServerIs(t *testing.T) {
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
}

func TestUnsupportedServer_TreatsAServerNotYetKnownAsUnsupported(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) {
		h.family, h.version, h.status = client.ServerFamilyUnknown, "", client.StatusDisconnected
	},
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
}

func TestUnsupportedServer_SendsNothingWhenAClientSeemsToStream(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) { h.family = client.ServerFamilyTS3 }, func(t *testing.T, e *env) {
		e.h.enter(7, new(true))
		e.h.setStreaming(8, true)
		e.settle()
		if e.h.count() != 0 {
			t.Errorf("sent %d commands", e.h.count())
		}
	})
}

func TestDiscovery_AsksOnceForAClientThatComesIntoViewStreaming(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(7, new(true))
		e.h.setStreaming(7, true)
		e.settle()
		asks := e.h.commands("requeststreaminfo")
		if len(asks) != 1 || asks[0].params["clid"] != "7" {
			t.Fatalf("asked %v", asks)
		}
	})
}

func TestDiscovery_AsksForTheClientsAlreadyInViewWhenItAttaches(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) { h.see(7, new(true)); h.see(8, new(false)); h.see(9, nil) },
		func(t *testing.T, e *env) {
			e.settle()
			asks := e.h.commands("requeststreaminfo")
			if len(asks) != 1 || asks[0].params["clid"] != "7" {
				t.Fatalf("asked %v", asks)
			}
		})
}

func TestDiscovery_AsksForThemAgainOnceConnected(t *testing.T) {
	runWith(t, Options{}, func(h *fakeHost) { h.see(7, new(true)); h.status = client.StatusConnecting },
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
}

func TestDiscovery_AsksAgainWhenTheFlagClearsAndLaterComesBack(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(7, new(true))
		e.h.setStreaming(7, false)
		e.h.setStreaming(7, true)
		e.settle()
		if got := len(e.h.commands("requeststreaminfo")); got != 2 {
			t.Errorf("asked %d times, want 2", got)
		}
	})
}

func TestDiscovery_AsksAgainForAClientThatWentOutOfViewAndCameBack(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(7, new(true))
		e.h.leave(7)
		e.h.enter(7, new(true))
		e.settle()
		if got := len(e.h.commands("requeststreaminfo")); got != 2 {
			t.Errorf("asked %d times, want 2", got)
		}
	})
}

func TestDiscovery_DoesNotAskAboutItselfAClidOf0OrBeforeItIsConnected(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.enter(1, new(true))
		e.h.enter(0, new(true))
		e.h.mu.Lock()
		e.h.status = client.StatusConnecting
		e.h.mu.Unlock()
		e.h.enter(9, new(true))
		e.settle()
		if e.h.count() != 0 {
			t.Errorf("sent %v", e.h.log)
		}
	})
}

func TestDiscovery_LearnsEveryStreamOfAClientOneNotificationEachAndToleratesAnEmptyAnswer(t *testing.T) {
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
}

func TestDiscovery_ReportsAnErrorNobodyAwaitsAndAsksAgainNextTime(t *testing.T) {
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
		e.h.enter(7, new(true))
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
}

func TestDiscovery_DoesNotReportAConnectionThatIsGone(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var errs collector[error]
		e.s.OnError(errs.add)
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, teamspeak.ErrNotConnected, s.name == "requeststreaminfo"
		}
		e.h.enter(7, new(true))
		e.settle()
		if errs.len() != 0 {
			t.Errorf("errors = %v", errs.all())
		}
	})
}

func TestKnownStreams_MergesTheAnnouncementAndTheInfoAndReportsAChangeAsUpdated(t *testing.T) {
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
		if info.Source == nil || *info.Source != SourceScreen {
			t.Errorf("source = %v", info.Source)
		}
		if info.Accessibility == nil || *info.Accessibility != AccessibilityPublic {
			t.Errorf("accessibility = %v", info.Accessibility)
		}
	})
}

func TestKnownStreams_KeepsTheOtherStreamsOfAClientWhenOneStops(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var stopped collector[StoppedEvent]
		e.s.OnStopped(stopped.add)
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.h.notify(notify.StreamStarted, announcement("b", 5))
		e.h.notify(notify.StreamStopped, map[string]string{"id": "a", "clid": "5", "reason": "3"})
		e.settle()
		got := stopped.all()
		if len(got) != 1 || got[0].Info.ID != "a" || got[0].Cause != EndCauseServer || got[0].Reason != 3 {
			t.Errorf("stopped = %+v", got)
		}
		if list := e.s.List(); len(list) != 1 || list[0].ID != "b" {
			t.Errorf("List = %+v", list)
		}
	})
}

func TestKnownStreams_KeepsAStreamWhenItsPublisherChangesChannelOrLeavesView(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.notify(notify.StreamStarted, announcement("a", 5))
		e.h.leave(5)
		e.settle()
		time.Sleep(10 * time.Second)
		if _, ok := e.s.Get("a"); !ok {
			t.Error("the stream was forgotten")
		}
	})
}

func TestKnownStreams_ReportsAViewerJoiningAndLeaving(t *testing.T) {
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
}

func TestKnownStreams_HandsOutCopies(t *testing.T) {
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
}

func TestPublish_SendsSetupstreamWithAllSevenParametersAndResolvesOnTheAnnouncement(t *testing.T) {
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
}

func TestPublish_SendsTheOptionsAsGiven(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.publish(PublishOptions{
			Name: "n", Source: new(SourceWindow), Bitrate: new(0), Accessibility: new(AccessibilityPrivate),
			ViewerLimit: 65535, Audio: true,
		})
		want := "setupstream name=n type=3 bitrate=0 accessibility=3 mode=1 viewer_limit=65535 audio=1"
		if got := e.h.commands("setupstream")[0].line; got != want {
			t.Errorf("line = %q, want %q", got, want)
		}
	})
}

func TestPublish_RefusesOptionsOutOfRangeWithoutSending(t *testing.T) {
	for name, opts := range map[string]PublishOptions{
		"unknown source":        {Source: new(Source(9))},
		"unknown accessibility": {Accessibility: new(Accessibility(4))},
		"negative bitrate":      {Bitrate: new(-1)},
		"huge bitrate":          {Bitrate: new(2_147_483_648)},
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
}

func TestPublish_RefusesANameTooLongToSendWithoutSending(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		_, err := e.s.Publish(t.Context(), PublishOptions{Name: strings.Repeat("x", 9200)})
		var big *PayloadTooLargeError
		if !errors.As(err, &big) || big.Command != "setupstream" || big.Size <= big.Limit {
			t.Fatalf("err = %v", err)
		}
		if big.Limit != maxCommandLineBytes {
			t.Errorf("limit = %d", big.Limit)
		}
		if e.h.count() != 0 {
			t.Error("sent a command")
		}
	})
}

func TestPublish_MatchesEachAnnouncementToItsCallWhenSeveralAreMadeInAnyOrder(t *testing.T) {
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
}

func TestPublish_HandsTheFirstCallTheStreamTheFirstCommandStarted(t *testing.T) {
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
}

func TestPublish_DoesNotTakeAnotherClientsStreamForItsOwn(t *testing.T) {
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
		err := <-done
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := e.s.Get("foreign"); !ok {
			t.Error("the foreign stream is not known")
		}
	})
}

func TestPublish_FailsWithTheServersRefusalAndThenPublishesAgain(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		refused := serverError(errcode.PermissionsClientInsufficient)
		done := make(chan error, 1)
		go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
		e.settle()
		e.h.failSetup(t, refused, 0)
		err := <-done
		if !errors.Is(err, errcode.PermissionsClientInsufficient) {
			t.Fatalf("err = %v", err)
		}
		if p := e.publish(PublishOptions{Name: "x"}); p == nil {
			t.Error("no stream")
		}
	})
}

func TestPublish_StopsWaitingWhenTheContextEnds(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { _, err := e.s.Publish(ctx, PublishOptions{Name: "x"}); done <- err }()
		e.settle()
		cancel()
		err := <-done
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPublish_RejectsWhilePendingWhenTheConnectionEnds(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		done := make(chan error, 1)
		go func() { _, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- err }()
		e.settle()
		e.h.disconnect()
		err := <-done
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPublish_TakesTenSecondsWithoutADeadlineAndKeepsTheCommandOpenFiveMore(t *testing.T) {
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
}

func TestPublish_UsesTheCallersDeadlineAndKeepsTheCommandOpenFiveMore(t *testing.T) {
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
}

// giveUp publishes a stream and cancels the call once its command is out.
func giveUp(t *testing.T, e *env) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := e.s.Publish(ctx, PublishOptions{Name: "x"}); done <- err }()
	e.settle()
	cancel()
	<-done
}

func TestPublishGivingUp_StopsAStreamACallThatGaveUpStartedKnownFromTheAnswerOnly(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		giveUp(t, e)
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
}

func TestPublishGivingUp_ReportsAStreamStoppedWhenItWasReportedStarted(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		var started collector[Info]
		var stopped collector[StoppedEvent]
		e.s.OnStarted(started.add)
		e.s.OnStopped(stopped.add)
		giveUp(t, e)
		e.h.announce(t, announcement("late", 1), 0)
		e.settle()
		if started.len() != 1 || stopped.len() != 1 || stopped.all()[0].Cause != EndCauseStopped {
			t.Errorf("started %d, stopped %+v", started.len(), stopped.all())
		}
		if len(e.h.commands("stopstream")) != 1 {
			t.Errorf("stops = %v", e.h.commands("stopstream"))
		}
	})
}

func TestPublishGivingUp_DoesNotBringAStoppedOrphanBackWithALaterRowAboutIt(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		giveUp(t, e)
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
}

func TestPublishGivingUp_DoesNotStopAnythingWhenTheServerRefusedTheCommand(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		giveUp(t, e)
		e.h.failSetup(t, serverError(errcode.PermissionsClientInsufficient), 0)
		e.settle()
		if got := e.h.commands("stopstream"); len(got) != 0 {
			t.Errorf("stops = %v", got)
		}
	})
}

func TestPublishGivingUp_LeavesAStreamAnnouncedAfterTheWindowForGood(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		giveUp(t, e)
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
}

func TestPublishGivingUp_StopsNothingForAnAnswerAfterTheConnectionEnded(t *testing.T) {
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
}

// closeAsync closes the Streams in the background and returns where its result
// will be.
func (e *env) closeAsync(ctx context.Context) chan error {
	done := make(chan error, 1)
	go func() { done <- e.s.Close(ctx) }()
	e.settle()

	return done
}

// publishAsync calls Publish in the background and lets it send its command.
func (e *env) publishAsync() chan error {
	done := make(chan error, 1)
	go func() { _, err := e.s.Publish(e.t.Context(), PublishOptions{Name: "x"}); done <- err }()
	e.settle()

	return done
}

func TestPublishGivingUp_StopsTheStreamAPublishStartedWhenClosedBeforeTheAnnouncement(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		published := e.publishAsync()
		closed := e.closeAsync(t.Context())
		err := <-published
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v", err)
		}
		select {
		case early := <-closed:
			t.Fatalf("Close returned %v while the command was still open", early)
		default:
		}
		e.h.announce(t, announcement("after", 1), 0)
		err = <-closed
		if err != nil {
			t.Fatal(err)
		}
		if got := e.h.commands("stopstream"); len(got) != 1 || got[0].params["id"] != "after" {
			t.Errorf("stops = %v", got)
		}
	})
}

// The stop of a stream that turns up after Close is one of the commands Close
// waits for, and its failure is part of what Close returns.
func TestPublishGivingUp_CloseReturnsTheFailureOfTheStopItWaitedFor(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.reply = func(s sent) ([]map[string]string, error, bool) {
			return nil, serverError(errcode.PermissionsClientInsufficient), s.name == "stopstream"
		}
		published := e.publishAsync()
		closed := e.closeAsync(t.Context())
		<-published
		e.h.announce(t, announcement("after", 1), 0)
		err := <-closed
		if !errors.Is(err, errcode.PermissionsClientInsufficient) {
			t.Errorf("Close = %v", err)
		}
	})
}

// Close waits no longer than its context, for a command that never gets its
// announcement.
func TestPublishGivingUp_CloseWaitsForTheCommandOnlyAsLongAsItsContext(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		published := e.publishAsync()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		start := time.Now()
		err := e.s.Close(ctx)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
			t.Errorf("Close = %v after %v", err, time.Since(start))
		}
		<-published
	})
}

func TestPublishGivingUp_StopsNothingForAPublishAnsweredAfterCloseWhenTheConnectionIsGone(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		published := e.publishAsync()
		e.h.disconnect()
		closed := e.closeAsync(t.Context())
		<-published
		e.h.announce(t, announcement("after", 1), 0)
		err := <-closed
		if err != nil {
			t.Fatal(err)
		}
		if got := e.h.commands("stopstream"); len(got) != 0 {
			t.Errorf("stops = %v", got)
		}
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

// The client delivers its disconnected event after the fact. A Publish that
// started on the connection that is up by then belongs to it: before, the
// event failed it and left the stream it started running.
func TestLaggingDisconnect_DoesNotFailAPublishSentOnTheNextConnection(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		e.h.reconnectQuietly(2)
		type result struct {
			p   *Published
			err error
		}
		done := make(chan result, 1)
		go func() { p, err := e.s.Publish(t.Context(), PublishOptions{Name: "x"}); done <- result{p, err} }()
		e.settle()
		e.h.deliverDisconnected()
		e.settle()
		e.h.announce(t, announcement("on-b", 2), 0)
		r := <-done
		if r.err != nil || r.p.ID() != "on-b" || r.p.Ended() {
			t.Fatalf("Publish = %v, %v", r.p, r.err)
		}
		e.settle()
		if got := e.h.commands("stopstream"); len(got) != 0 {
			t.Errorf("stops = %v", got)
		}
	})
}

func TestLaggingDisconnect_StillFailsAPublishSentOnTheConnectionThatEnded(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		published := e.publishAsync()
		e.h.reconnectQuietly(2)
		e.h.deliverDisconnected()
		err := <-published
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestLaggingDisconnect_KeepsWhatTheNextConnectionStarted(t *testing.T) {
	run(t, func(t *testing.T, e *env) {
		old := e.publish(PublishOptions{Name: "old"})
		e.streamOf5()
		e.h.reconnectQuietly(2)
		fresh := e.publish(PublishOptions{Name: "fresh"})
		watching := e.startWatch(t.Context())
		var ended collector[EndedEvent]
		old.OnEnded(ended.add)
		fresh.OnEnded(ended.add)
		e.h.deliverDisconnected()
		e.settle()
		if !old.Ended() || fresh.Ended() || ended.len() != 1 || ended.all()[0].Cause != EndCauseDisconnected {
			t.Errorf("old ended %v, fresh ended %v, events %+v", old.Ended(), fresh.Ended(), ended.all())
		}
		e.respond(nil)
		if r := <-watching; r.err != nil {
			t.Errorf("Watch = %v", r.err)
		}
	})
}
