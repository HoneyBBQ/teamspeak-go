//go:build integration

package stream

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// pair is a publisher on a, a viewer on b, and one accepted viewer.
type pair struct {
	publisher, viewer *Streams
	pub               *Published
	peer              *ViewerPeer
	view              *View
}

func isID(id ID) func(Info) bool { return func(i Info) bool { return i.ID == id } }

// publishAndSee publishes a stream from a and waits for b to learn of it.
func publishAndSee(t *testing.T, l *live, name string, opts Options) (*Streams, *Streams, *Published, Info) {
	t.Helper()
	publisher := attach(t, l.a, opts)
	viewer := attach(t, l.b, Options{})
	started := listen(viewer.OnStarted, nil)
	pub, err := publisher.Publish(timeout(t, 15*time.Second), PublishOptions{Name: name})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	return publisher, viewer, pub, await(t, started, "started")
}

func connectedPair(t *testing.T, l *live) pair {
	t.Helper()
	publisher, viewer, pub, info := publishAndSee(t, l, "pair", Options{})
	requests := listen(pub.OnRequest, nil)
	type result struct {
		view *View
		err  error
	}
	watching := make(chan result, 1)
	go func() {
		v, err := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{Message: "pair"})
		watching <- result{v, err}
	}()
	request := await(t, requests, "request")
	peer, err := request.Accept(t.Context(), sdpLike(2500), "")
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	r := await(t, watching, "view")
	if r.err != nil {
		t.Fatalf("Watch: %v", r.err)
	}

	return pair{publisher, viewer, pub, peer, r.view}
}

func TestLive_SeesAStreamStartInItsChannel(t *testing.T) {
	l := requireTS6(t)
	publisher := attach(t, l.a, Options{})
	viewer := attach(t, l.b, Options{})
	started := listen(viewer.OnStarted, nil)
	pub, err := publisher.Publish(t.Context(), PublishOptions{
		Name: "Demo | stream", Source: new(SourceWindow), Audio: true, ViewerLimit: 4,
		Accessibility: new(AccessibilityContacts),
	})
	if err != nil {
		t.Fatal(err)
	}
	info := await(t, started, "started")
	if info.ID != pub.ID() || info.ClientID != l.a.ClientID() || info.Name != "Demo | stream" || !info.Audio {
		t.Errorf("info = %+v", info)
	}
	if *info.Source != SourceWindow || *info.Accessibility != AccessibilityContacts || *info.ViewerLimit != 4 {
		t.Errorf("info = %+v", info)
	}
	if got, ok := publisher.Get(pub.ID()); !ok || got.Name != "Demo | stream" {
		t.Errorf("publisher.Get = %+v", got)
	}
}

func TestLive_FindsAStreamThatWasRunningBeforeTheClientCame(t *testing.T) {
	l := requireTS6(t)
	publisher := attach(t, l.a, Options{})
	pub, err := publisher.Publish(t.Context(), PublishOptions{Name: "already running", Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	late := connectLive(t, "go-stream-late", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"))
	t.Cleanup(func() { _ = late.Disconnect(context.WithoutCancel(t.Context())) })
	seen := attach(t, late, Options{})
	deadline := time.Now().Add(eventTimeout)
	for time.Now().Before(deadline) {
		if _, ok := seen.Get(pub.ID()); ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	info, ok := seen.Get(pub.ID())
	if !ok || info.Name != "already running" || info.ClientID != l.a.ClientID() || !info.Audio {
		t.Fatalf("info = %+v, %v", info, ok)
	}
	if info.Viewers == nil || *info.Viewers != 0 {
		t.Errorf("viewers = %v", info.Viewers)
	}
}

func TestLive_FindsAStreamWhenTheClientMovesIntoItsChannel(t *testing.T) {
	l := requireTS6(t)
	if l.other == 0 {
		t.Skip("no second channel")
	}
	late := connectLive(t, "go-stream-mover", os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL"))
	t.Cleanup(func() { _ = late.Disconnect(context.WithoutCancel(t.Context())) })
	seen := attach(t, late, Options{})
	pub, err := attach(t, l.a, Options{}).Publish(t.Context(), PublishOptions{Name: "in alpha"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, ok := seen.Get(pub.ID()); ok {
		t.Fatal("known before moving")
	}
	started := listen(seen.OnStarted, isID(pub.ID()))
	err = late.MoveClient(t.Context(), late.ClientID(), l.alpha, teamspeak.ClientMoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	await(t, started, "started")
}

func TestLive_KnowsEveryStreamOfAClientAndStoppingOneLeavesTheOther(t *testing.T) {
	l := requireTS6(t)
	publisher := attach(t, l.a, Options{})
	one, err := publisher.Publish(t.Context(), PublishOptions{Name: "one"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := publisher.Publish(t.Context(), PublishOptions{Name: "two", Source: new(SourceCamera)})
	if err != nil {
		t.Fatal(err)
	}
	if one.ID() == two.ID() {
		t.Fatal("the same id twice")
	}
	late := connectLive(t, "go-stream-late2", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"))
	t.Cleanup(func() { _ = late.Disconnect(context.WithoutCancel(t.Context())) })
	seen := attach(t, late, Options{})
	stopped := listen(seen.OnStopped, nil)
	deadline := time.Now().Add(eventTimeout)
	for len(seen.List()) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if len(seen.List()) != 2 {
		t.Fatalf("List = %+v", seen.List())
	}
	err = one.Stop(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if e := await(t, stopped, "stopped"); e.Info.ID != one.ID() {
		t.Errorf("stopped %s", e.Info.ID)
	}
	if list := seen.List(); len(list) != 1 || list[0].Name != "two" || two.Ended() {
		t.Errorf("List = %+v", list)
	}
}

func TestLive_CarriesTheOfferTheAnswerAndTheCandidatesBothWaysByteForByte(t *testing.T) {
	l := requireTS6(t)
	publisher, viewer, pub, info := publishAndSee(t, l, "signalling", Options{})
	_ = publisher
	requests := listen(pub.OnRequest, nil)
	var view *View
	done := make(chan error, 1)
	go func() {
		var err error
		view, err = viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{Message: "let me in | please ü"})
		done <- err
	}()
	request := await(t, requests, "request")
	v := request.Viewer()
	if v.ClientID != l.b.ClientID() || v.UID != l.b.UID() || request.Message() != "let me in | please ü" {
		t.Errorf("request = %+v %q", v, request.Message())
	}
	offer := sdpLike(3000)
	peer, err := request.Accept(t.Context(), offer, "")
	if err != nil {
		t.Fatal(err)
	}
	err = <-done
	if err != nil {
		t.Fatal(err)
	}
	if view.Offer() != offer {
		t.Error("the offer changed on the way")
	}
	const n = 12
	fromViewer := listen(peer.OnCandidate, nil)
	fromPublisher := listen(view.OnCandidate, nil)
	answered := listen(peer.OnAnswer, nil)
	answer := sdpLike(2800)
	err = view.Answer(t.Context(), answer)
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, answered, "answer"); got != answer {
		t.Error("the answer changed on the way")
	}
	for i := range n {
		err := view.SendCandidate(t.Context(), candidate(i))
		if err != nil {
			t.Fatal(err)
		}
		err = peer.SendCandidate(t.Context(), candidate(100+i))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range n {
		if got := await(t, fromViewer, "candidate"); got.Candidate != candidate(i).Candidate || *got.SDPMid != "0" {
			t.Errorf("from viewer #%d = %+v", i, got)
		}
		if got := await(t, fromPublisher, "candidate"); got.Candidate != candidate(100+i).Candidate {
			t.Errorf("from publisher #%d = %+v", i, got)
		}
	}
	if len(pub.Viewers()) != 1 {
		t.Errorf("viewers = %d", len(pub.Viewers()))
	}
}

func TestLive_DeliversWhatThePublisherSendsRightBehindTheOfferToAHandlerAddedLater(t *testing.T) {
	l := requireTS6(t)
	_, viewer, pub, info := publishAndSee(t, l, "early", Options{})
	requests := listen(pub.OnRequest, nil)
	done := make(chan *View, 1)
	go func() {
		v, err := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{})
		if err != nil {
			t.Error(err)
		}
		done <- v
	}()
	peer, err := await(t, requests, "request").Accept(t.Context(), sdpLike(1500), "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		err := peer.SendCandidate(t.Context(), candidate(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	view := await(t, done, "view")
	time.Sleep(500 * time.Millisecond)
	seen := listen(view.OnCandidate, nil)
	for i := range 8 {
		if got := await(t, seen, "candidate"); got.Candidate != candidate(i).Candidate {
			t.Errorf("#%d = %q", i, got.Candidate)
		}
	}
}

func TestLive_HandsAMessageItHasNoNameForToTheOtherEndAsARawSignal(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	raw := listen(p.view.OnSignal, nil)
	err := p.peer.SendSignal(t.Context(), "custom", map[string]string{"note": "a b | c"})
	if err != nil {
		t.Fatal(err)
	}
	got := await(t, raw, "signal")
	if got.Cmd != "custom" || string(got.Args) != `{"note":"a b | c"}` {
		t.Errorf("signal = %+v", got)
	}
}

func TestLive_TellsTheViewerWhyARequestWasDeniedAndLetsItAskAgain(t *testing.T) {
	l := requireTS6(t)
	_, viewer, pub, info := publishAndSee(t, l, "private", Options{})
	requests := listen(pub.OnRequest, nil)
	denied := make(chan error, 1)
	go func() { _, werr := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{}); denied <- werr }()
	err := await(t, requests, "request").Deny(t.Context(), "Denied | not today")
	if err != nil {
		t.Fatal(err)
	}
	var d *JoinDeniedError
	err = await(t, denied, "refusal")
	if !errors.As(err, &d) || d.Message != "Denied | not today" {
		t.Fatalf("err = %v", err)
	}
	// The server forgets a denial.
	second := make(chan *View, 1)
	go func() {
		v, werr := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{})
		if werr != nil {
			t.Error(werr)
		}
		second <- v
	}()
	_, err = await(t, requests, "second request").Accept(t.Context(), sdpLike(500), "")
	if err != nil {
		t.Fatal(err)
	}
	if v := await(t, second, "view"); v.Offer() != sdpLike(500) {
		t.Error("offer changed")
	}
}

func TestLive_LeavesARememberedDenialUnanswered(t *testing.T) {
	l := requireTS6(t)
	_, viewer, pub, info := publishAndSee(t, l, "remembered", Options{RememberDenied: true})
	requests := listen(pub.OnRequest, nil)
	denied := make(chan error, 1)
	go func() { _, err := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{}); denied <- err }()
	err := await(t, requests, "request").Deny(t.Context(), "no")
	if err != nil {
		t.Fatal(err)
	}
	_ = await(t, denied, "refusal")
	// Ask again: the server relays it, and the publisher says nothing.
	ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
	defer cancel()
	_, err = viewer.Watch(ctx, info.ID, WatchOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	awaitNone(t, requests, "request", 200*time.Millisecond)
}

func TestLive_WarnsAboutAnOfferWithoutAudioAndStillLetsTheViewerIn(t *testing.T) {
	l := requireTS6(t)
	publisher, viewer, pub, info := publishAndSee(t, l, "video only", Options{})
	requests := listen(pub.OnRequest, nil)
	warned := listen(publisher.OnWarning, nil)
	done := make(chan *View, 1)
	go func() {
		v, err := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{})
		if err != nil {
			t.Error(err)
		}
		done <- v
	}()
	request := await(t, requests, "request")
	const offer = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=sendonly\r\n"
	_, err := request.Accept(t.Context(), offer, "")
	if err != nil {
		t.Fatal(err)
	}
	w := await(t, warned, "warning")
	if w.Code != WarningOfferWithoutAudio || w.StreamID != pub.ID() || w.ClientID != l.b.ClientID() {
		t.Errorf("warning = %+v", w)
	}
	if request.State() != RequestAccepted || await(t, done, "view").Offer() != offer {
		t.Error("the viewer was not let in with the offer as sent")
	}
}

func TestLive_TellsThePublisherARequestWasWithdrawnAndOneTheStreamEndedOn(t *testing.T) {
	l := requireTS6(t)
	_, viewer, pub, info := publishAndSee(t, l, "withdrawn", Options{})
	requests := listen(pub.OnRequest, nil)
	// The viewer gives up waiting, which withdraws the request.
	ctx, cancel := context.WithTimeout(t.Context(), 800*time.Millisecond)
	defer cancel()
	gaveUp := make(chan error, 1)
	go func() { _, err := viewer.Watch(ctx, info.ID, WatchOptions{}); gaveUp <- err }()
	request := await(t, requests, "request")
	closed := listen(request.OnClosed, nil)
	if got := await(t, closed, "closed"); got != RequestWithdrawn || request.State() != RequestWithdrawn {
		t.Errorf("closed = %v, state %v", got, request.State())
	}
	_, err := request.Accept(t.Context(), sdpLike(100), "")
	if !errors.Is(err, ErrNotPending) {
		t.Errorf("Accept: %v", err)
	}
	<-gaveUp

	// A request pending when the stream stops ends with it.
	waiting := make(chan error, 1)
	go func() { _, werr := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{}); waiting <- werr }()
	second := await(t, requests, "second request")
	ended := listen(second.OnClosed, nil)
	err = pub.Stop(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, ended, "closed"); got != RequestEnded {
		t.Errorf("closed = %v", got)
	}
	<-waiting
}

func TestLive_ClosesThePublishersPeerWhenTheViewerLeaves(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	closed := listen(p.peer.OnClosed, nil)
	err := p.view.Leave(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, closed, "closed"); got != (PeerClosedEvent{Cause: PeerCauseLeft}) {
		t.Errorf("closed = %+v", got)
	}
	if len(p.pub.Viewers()) != 0 || !p.view.Closed() {
		t.Error("the viewer is still there")
	}
}

func TestLive_EndsTheViewersSideWithTheReasonWhenThePublisherStops(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	viewClosed := listen(p.view.OnClosed, nil)
	stopped := listen(p.viewer.OnStopped, nil)
	ended := listen(p.pub.OnEnded, nil)
	err := p.pub.Stop(t.Context(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, viewClosed, "closed"); got != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 3}) {
		t.Errorf("view closed = %+v", got)
	}
	if got := await(t, stopped, "stopped"); got.Reason != 3 || got.Cause != EndCauseServer {
		t.Errorf("stopped = %+v", got)
	}
	if got := await(t, ended, "ended"); got != (EndedEvent{Cause: EndCauseStopped, Reason: 3}) {
		t.Errorf("ended = %+v", got)
	}
	if !p.peer.Closed() || len(p.viewer.List()) != 0 {
		t.Error("something is left")
	}
}

func TestLive_AsksForAStreamThatHasEndedAndIsToldSo(t *testing.T) {
	l := requireTS6(t)
	_, viewer, pub, info := publishAndSee(t, l, "short", Options{})
	err := pub.Stop(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = viewer.Watch(timeout(t, 10*time.Second), info.ID, WatchOptions{})
	var ended *EndedError
	if !errors.As(err, &ended) || !errors.Is(err, errcode.StreamNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestLive_ReportsASecondRequestToWatchAsTheServers5638(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	other := attach(t, l.b, Options{})
	info, _ := p.viewer.Get(p.pub.ID())
	_, err := other.Watch(timeout(t, 10*time.Second), info.ID, WatchOptions{})
	if !errors.Is(err, errcode.StreamAlreadyJoined) {
		t.Errorf("err = %v", err)
	}
}

func TestLive_KeepsTheStreamAndItsSignallingWhenThePublisherChangesChannel(t *testing.T) {
	l := requireTS6(t)
	if l.other == 0 {
		t.Skip("no second channel")
	}
	p := connectedPair(t, l)
	err := l.a.MoveClient(t.Context(), l.a.ClientID(), l.other, teamspeak.ClientMoveOptions{Password: l.otherPassword})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	if p.view.Closed() || p.peer.Closed() || len(p.viewer.List()) != 1 {
		t.Fatal("the stream ended with the move")
	}
	arrived := listen(p.peer.OnCandidate, nil)
	err = p.view.SendCandidate(t.Context(), candidate(5))
	if err != nil {
		t.Fatal(err)
	}
	await(t, arrived, "candidate")
	// The viewer, still a participant, hears the stop from the other channel.
	closed := listen(p.view.OnClosed, nil)
	err = p.pub.Stop(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, closed, "closed"); got.Cause != PeerCauseStopped {
		t.Errorf("closed = %+v", got)
	}
}

func TestLive_EndsTheViewersSideWhenThePublisherDisconnects(t *testing.T) {
	l := requireTS6(t)
	gone := connectLive(t, "go-stream-gone", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"))
	t.Cleanup(func() { _ = gone.Disconnect(context.WithoutCancel(t.Context())) })
	publisher := attach(t, gone, Options{})
	viewer := attach(t, l.b, Options{})
	started := listen(viewer.OnStarted, nil)
	pub, err := publisher.Publish(t.Context(), PublishOptions{Name: "going away"})
	if err != nil {
		t.Fatal(err)
	}
	info := await(t, started, "started")
	requests := listen(pub.OnRequest, nil)
	done := make(chan *View, 1)
	go func() {
		v, _ := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{})
		done <- v
	}()
	_, err = await(t, requests, "request").Accept(t.Context(), sdpLike(800), "")
	if err != nil {
		t.Fatal(err)
	}
	view := await(t, done, "view")
	closed := listen(view.OnClosed, nil)
	ended := listen(pub.OnEnded, nil)
	err = gone.Disconnect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The server reports a publisher that went away as reason 1.
	if got := await(t, closed, "closed"); got != (PeerClosedEvent{Cause: PeerCauseStopped, Reason: 1}) {
		t.Errorf("closed = %+v", got)
	}
	if got := await(t, ended, "ended"); got.Cause != EndCauseDisconnected {
		t.Errorf("ended = %+v", got)
	}
	if len(viewer.List()) != 0 {
		t.Errorf("List = %+v", viewer.List())
	}
}

func TestLive_RefusesAPayloadTooLongBeforeSendingAndCarriesOneAtTheLimit(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	var big *PayloadTooLargeError
	err := p.peer.SendOffer(t.Context(), string(make([]byte, 20000)))
	if !errors.As(err, &big) {
		t.Errorf("offer: %v", err)
	}
	long := IceCandidate{Candidate: sdpLike(12000), SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}
	err = p.view.SendCandidate(t.Context(), long)
	if !errors.As(err, &big) {
		t.Errorf("candidate: %v", err)
	}
	// The longest candidate this package sends: the line is exactly the limit.
	wrap := func(text string) int {
		c := IceCandidate{Candidate: text, SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}

		return len(encoded(signalRequest(p.view.StreamID(), p.peer.ClientID(), candidateJSON(c))))
	}
	text := make([]byte, maxCommandLineBytes-wrap(""))
	for i := range text {
		text[i] = 'a'
	}
	for wrap(string(text)) > maxCommandLineBytes {
		text = text[1:]
	}
	if wrap(string(text)) != maxCommandLineBytes {
		t.Fatalf("could not build a line of exactly the limit: %d", wrap(string(text)))
	}
	arrived := listen(p.peer.OnCandidate, nil)
	longest := IceCandidate{Candidate: string(text), SDPMid: new("0"), SDPMLineIndex: new(uint16(0))}
	err = p.view.SendCandidate(t.Context(), longest)
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, arrived, "long candidate"); got.Candidate != string(text) {
		t.Error("the candidate changed on the way")
	}
}

func TestLive_DeliversABurstOfCandidatesInOrder(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	const n = 40
	got := listen(p.peer.OnCandidate, nil)
	errs := make(chan error, n)
	// Issued together, so they queue in the client's throttle in order of issue.
	for i := range n {
		time.Sleep(time.Millisecond)
		go func() { errs <- p.view.SendCandidate(timeout(t, 40*time.Second), candidate(i)) }()
	}
	received := make([]string, 0, n)
	for len(received) < n {
		select {
		case c := <-got:
			received = append(received, c.Candidate)
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d candidates arrived", len(received), n)
		}
	}
	for range n {
		err := <-errs
		if err != nil {
			t.Fatal(err)
		}
	}
	// Goroutines racing the throttle may interleave neighbours; every candidate must arrive once.
	want := make([]string, n)
	for i := range n {
		want[i] = candidate(i).Candidate
	}
	slices.Sort(want)
	slices.Sort(received)
	if !slices.Equal(want, received) {
		t.Error("the candidates that arrived are not the ones sent")
	}
}

func TestLive_CloseEndsEverythingAndStopsNothingItDidNotPublish(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	closed := listen(p.view.OnClosed, nil)
	err := p.viewer.Close(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, closed, "closed"); got.Cause != PeerCauseShutdown {
		t.Errorf("closed = %+v", got)
	}
	if p.pub.Ended() {
		t.Error("the stream was stopped by its viewer")
	}
	_, err = l.b.WhoAmI(t.Context())
	if err != nil {
		t.Errorf("the connection is none the worse: %v", err)
	}
}

func TestLive_TellsThePublisherAViewerLeftOnCloseAndTheViewerTheStreamStoppedWhenThePublisherCloses(t *testing.T) {
	l := requireTS6(t)
	p := connectedPair(t, l)
	peerClosed := listen(p.peer.OnClosed, nil)
	left := listen(p.publisher.OnViewerLeft, nil)
	err := p.viewer.Close(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, peerClosed, "closed"); got != (PeerClosedEvent{Cause: PeerCauseLeft}) {
		t.Errorf("closed = %+v", got)
	}
	if got := await(t, left, "viewer left"); got.ClientID != l.b.ClientID() {
		t.Errorf("left = %+v", got)
	}
	if len(p.pub.Viewers()) != 0 || p.pub.Ended() {
		t.Error("the stream or its viewer list is wrong")
	}

	// A new viewer, whose publisher then closes: the stop reaches it.
	second := attach(t, l.b, Options{})
	deadline := time.Now().Add(eventTimeout)
	for time.Now().Before(deadline) && len(second.List()) == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	requests := listen(p.pub.OnRequest, nil)
	done := make(chan *View, 1)
	go func() {
		v, _ := second.Watch(timeout(t, 20*time.Second), p.pub.ID(), WatchOptions{})
		done <- v
	}()
	_, err = await(t, requests, "request").Accept(t.Context(), sdpLike(500), "")
	if err != nil {
		t.Fatal(err)
	}
	view := await(t, done, "view")
	viewClosed := listen(view.OnClosed, nil)
	err = p.publisher.Close(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := await(t, viewClosed, "closed"); got.Cause != PeerCauseStopped {
		t.Errorf("closed = %+v", got)
	}
}

func TestLive_RejectsWatchOfAnIdNobodyAnnouncedWithoutAskingTheServer(t *testing.T) {
	l := requireTS6(t)
	viewer := attach(t, l.b, Options{})
	start := time.Now()
	_, err := viewer.Watch(t.Context(), "00000000-0000-4000-8000-000000000000", WatchOptions{})
	var ended *EndedError
	if !errors.As(err, &ended) || time.Since(start) > 500*time.Millisecond {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func TestLive_KnowsWhoAskedFromAChannelItDoesNotFollowAndLeavesTheirRememberedDenialUnanswered(t *testing.T) {
	l := requireTS6(t)
	if l.other == 0 {
		t.Skip("no second channel")
	}
	_, viewer, pub, info := publishAndSee(t, l, "across", Options{RememberDenied: true})
	err := l.a.UnsubscribeChannel(t.Context(), l.other)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.a.SubscribeChannel(context.WithoutCancel(t.Context()), l.other) })
	err = l.b.MoveClient(t.Context(), l.b.ClientID(), l.other, teamspeak.ClientMoveOptions{Password: l.otherPassword})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	if _, ok := l.a.View().Client(l.b.ClientID()); ok {
		t.Fatal("the publisher still sees the viewer")
	}
	requests := listen(pub.OnRequest, nil)
	denied := make(chan error, 1)
	go func() { _, werr := viewer.Watch(timeout(t, 20*time.Second), info.ID, WatchOptions{}); denied <- werr }()
	request := await(t, requests, "request")
	// The server renames a nickname that is taken, so compare with what it gave.
	self := l.b.View().Self
	if v := request.Viewer(); v.ClientID != l.b.ClientID() || v.UID != l.b.UID() || v.Nickname != self.Nickname {
		t.Errorf("viewer = %+v", v)
	}
	err = request.Deny(t.Context(), "no")
	if err != nil {
		t.Fatal(err)
	}
	_ = await(t, denied, "refusal")
	ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
	defer cancel()
	_, err = viewer.Watch(ctx, info.ID, WatchOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	awaitNone(t, requests, "request", 200*time.Millisecond)
}

func TestLive_StopsAStreamWhosePublishWasGivenUpOnAfterItWasSent(t *testing.T) {
	l := requireTS6(t)
	// The caller gives up as the command is about to leave, so the stream is
	// announced to nobody who waits for it.
	ctx, cancel := context.WithCancel(t.Context())
	giveUp := func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(c context.Context, req teamspeak.Request) ([]map[string]string, error) {
			if req.Command() == "setupstream" {
				cancel()
			}

			return next.Send(c, req)
		})
	}
	c := connectLive(t, "go-stream-giveup", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"), client.WithCommandMiddleware(giveUp))
	t.Cleanup(func() { _ = c.Disconnect(context.WithoutCancel(t.Context())) })
	publisher := attach(t, c, Options{})
	viewer := attach(t, l.b, Options{})
	started := listen(viewer.OnStarted, nil)
	stopped := listen(viewer.OnStopped, nil)
	_, err := publisher.Publish(ctx, PublishOptions{Name: "abandoned"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish: %v", err)
	}
	info := await(t, started, "started")
	if got := await(t, stopped, "stopped"); got.Info.ID != info.ID {
		t.Errorf("stopped %s, started %s", got.Info.ID, info.ID)
	}
	if len(viewer.List()) != 0 || len(publisher.List()) != 0 {
		t.Errorf("left over: %+v %+v", viewer.List(), publisher.List())
	}
}

// ---- Attributing an announcement to its command by return_code ---------------

func setup(name string, viewerLimit int) teamspeak.Request {
	return setupRequest(name, SourceScreen, 1_500_000, AccessibilityPublic, viewerLimit, false)
}

func stopQuietly(c *client.Client, id string) {
	_, _ = c.Send(context.Background(), stopRequest(ID(id), 0))
}

func TestLive_AnswersEachOfSeveralSameNameSetupstreamCommandsFromOneClientWithItsOwnStream(t *testing.T) {
	l := requireTS6(t)
	type result struct {
		err  error
		rows []map[string]string
	}
	results := make([]result, 3)
	done := make(chan int, 3)
	for i := range 3 {
		go func() {
			results[i].rows, results[i].err = l.a.Send(timeout(t, 15*time.Second), setup("same", i+1))
			done <- i
		}()
	}
	for range 3 {
		<-done
	}
	ids := map[string]bool{}
	for i, r := range results {
		if r.err != nil || len(r.rows) != 1 {
			t.Fatalf("command %d: %v, %d rows", i, r.err, len(r.rows))
		}
		defer stopQuietly(l.a, r.rows[0]["id"])
		ids[r.rows[0]["id"]] = true
		// Each is the row of the command that asked for that viewer limit.
		if r.rows[0]["viewer_limit"] != strconv.Itoa(i+1) || r.rows[0]["clid"] != strconv.Itoa(int(l.a.ClientID())) {
			t.Errorf("command %d got %v", i, r.rows[0])
		}
	}
	if len(ids) != 3 {
		t.Errorf("ids = %v", ids)
	}
}

func TestLive_AnswersSameNameSetupstreamCommandsFromTwoClientsEachWithItsOwn(t *testing.T) {
	l := requireTS6(t)
	var rowsA, rowsB []map[string]string
	var errA, errB error
	done := make(chan struct{}, 2)
	go func() { rowsA, errA = l.a.Send(timeout(t, 15*time.Second), setup("same", 4)); done <- struct{}{} }()
	go func() { rowsB, errB = l.b.Send(timeout(t, 15*time.Second), setup("same", 5)); done <- struct{}{} }()
	<-done
	<-done
	if errA != nil || errB != nil || len(rowsA) != 1 || len(rowsB) != 1 {
		t.Fatalf("a: %v %v, b: %v %v", rowsA, errA, rowsB, errB)
	}
	defer stopQuietly(l.a, rowsA[0]["id"])
	defer stopQuietly(l.b, rowsB[0]["id"])
	if rowsA[0]["clid"] != strconv.Itoa(int(l.a.ClientID())) || rowsA[0]["viewer_limit"] != "4" ||
		rowsB[0]["clid"] != strconv.Itoa(int(l.b.ClientID())) || rowsB[0]["viewer_limit"] != "5" {
		t.Errorf("a got %v, b got %v", rowsA[0], rowsB[0])
	}
}

// The publisher's own announcement carries the number and other clients' copies
// do not. If the server ever stops echoing it, this says so, rather than every
// publish timing out.
func TestLive_EchoesTheReturnCodeOnThePublishersOwnAnnouncementOnly(t *testing.T) {
	l := requireTS6(t)
	seenByA := listen(l.a.OnNotification, func(n client.NotificationEvent) bool { return n.Name == "notifystreamstarted" })
	seenByB := listen(l.b.OnNotification, func(n client.NotificationEvent) bool { return n.Name == "notifystreamstarted" })
	publisher := attach(t, l.a, Options{})
	attach(t, l.b, Options{})
	pub, err := publisher.Publish(t.Context(), PublishOptions{Name: "canary"})
	if err != nil {
		t.Fatal(err)
	}
	a := await(t, seenByA, "announcement to the publisher")
	b := await(t, seenByB, "announcement to the other client")
	if a.Params["id"] != string(pub.ID()) || b.Params["id"] != string(pub.ID()) {
		t.Fatalf("a %v, b %v", a.Params, b.Params)
	}
	_, err = strconv.Atoi(a.Params["return_code"])
	if err != nil {
		t.Errorf("the publisher's copy has no return_code: %v", a.Params)
	}
	if rc, ok := b.Params["return_code"]; ok {
		t.Errorf("the other client's copy carries return_code %q", rc)
	}
}

// gate holds a setupstream back by its viewer limit, so a test decides which of
// two otherwise identical commands reaches the server first.
type gate struct {
	mu      chan struct{}
	waiting map[int]chan struct{}
	opened  map[int]bool
}

func newGate() *gate {
	g := &gate{mu: make(chan struct{}, 1), waiting: map[int]chan struct{}{}, opened: map[int]bool{}}
	g.mu <- struct{}{}

	return g
}

func (g *gate) middleware() client.CommandMiddleware {
	return func(next teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
			if req.Command() == "setupstream" {
				limit, _ := strconv.Atoi(wire.ParseCommand(encoded(req)).Params["viewer_limit"])
				<-g.mu
				ch := make(chan struct{})
				if g.opened[limit] || limit == 0 {
					close(ch)
				} else {
					g.waiting[limit] = ch
				}
				g.mu <- struct{}{}
				select {
				case <-ch:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}

			return next.Send(ctx, req)
		})
	}
}

func (g *gate) open(limit int) {
	<-g.mu
	defer func() { g.mu <- struct{}{} }()
	g.opened[limit] = true
	if ch := g.waiting[limit]; ch != nil {
		close(ch)
		delete(g.waiting, limit)
	}
}

// The abandoned call's stream and the live call's have one name and differ in
// nothing but the number; matching by name stopped the live one when it was
// announced first.
func testGatedOrder(t *testing.T, firstLimit, secondLimit int) {
	t.Helper()
	l := requireTS6(t)
	g := newGate()
	gated := client.WithCommandMiddleware(g.middleware())
	publishing := connectLive(t, "go-stream-gate", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"), gated)
	t.Cleanup(func() { _ = publishing.Disconnect(context.WithoutCancel(t.Context())) })
	publisher := attach(t, publishing, Options{})
	viewer := attach(t, l.b, Options{})
	heard := listen(viewer.OnStarted, nil)
	stopped := listen(viewer.OnStopped, nil)

	// Held in the middleware, so the caller gives up before the command is sent.
	short, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := publisher.Publish(short, PublishOptions{Name: "same", ViewerLimit: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandoned: %v", err)
	}
	type result struct {
		pub *Published
		err error
	}
	live := make(chan result, 1)
	go func() {
		p, err := publisher.Publish(timeout(t, 20*time.Second), PublishOptions{Name: "same", ViewerLimit: 2})
		live <- result{p, err}
	}()
	time.Sleep(200 * time.Millisecond)
	g.open(firstLimit)
	for {
		info := await(t, heard, "first announcement")
		if info.ViewerLimit != nil && *info.ViewerLimit == firstLimit {
			break
		}
	}
	g.open(secondLimit)
	r := await(t, live, "live publish")
	if r.err != nil {
		t.Fatal(r.err)
	}
	if lim := r.pub.Info().ViewerLimit; lim == nil || *lim != 2 {
		t.Errorf("the live call got viewer limit %v", lim)
	}
	if firstLimit == 1 {
		if got := await(t, stopped, "stop of the abandoned stream"); got.Info.ID == r.pub.ID() {
			t.Error("the live stream was stopped")
		}
	}
	time.Sleep(time.Second)
	if list := viewer.List(); len(list) != 1 || list[0].ID != r.pub.ID() {
		t.Errorf("viewer sees %+v, want only %s", list, r.pub.ID())
	}
	if list := publisher.List(); len(list) != 1 || list[0].ID != r.pub.ID() {
		t.Errorf("publisher knows %+v, want only %s", list, r.pub.ID())
	}
}

func TestLive_KeepsTheLiveStreamAndStopsTheAbandonedOneWhenTheAbandonedCommandIsSentFirst(t *testing.T) {
	testGatedOrder(t, 1, 2)
}

func TestLive_KeepsTheLiveStreamAndStopsTheAbandonedOneWhenTheLiveCommandIsSentFirst(t *testing.T) {
	testGatedOrder(t, 2, 1)
}

// The command is held in the middleware while the connection ends, so the call
// is certainly in flight.
func TestLive_RejectsAPublishInFlightWhenTheConnectionEndsAndPublishesOnTheNextOne(t *testing.T) {
	requireTS6(t)
	g := newGate()
	gated := client.WithCommandMiddleware(g.middleware())
	c := connectLive(t, "go-stream-reconnect", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"), gated)
	t.Cleanup(func() { _ = c.Disconnect(context.WithoutCancel(t.Context())) })
	publisher := attach(t, c, Options{})
	interrupted := make(chan error, 1)
	go func() {
		_, err := publisher.Publish(timeout(t, 20*time.Second), PublishOptions{Name: "interrupted", ViewerLimit: 1})
		interrupted <- err
	}()
	time.Sleep(500 * time.Millisecond)
	err := c.Disconnect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = await(t, interrupted, "rejection")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("err = %v", err)
	}
	g.open(1)
	err = paceConnect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(timeout(t, 15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	err = c.WaitView(timeout(t, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publisher.Publish(timeout(t, 15*time.Second), PublishOptions{Name: "after"})
	if err != nil {
		t.Fatal(err)
	}
	if list := publisher.List(); len(list) != 1 || list[0].ID != pub.ID() {
		t.Errorf("List = %+v", list)
	}
}

// ---- A server without streams --------------------------------------------------

func TestLive_RefusesPublishAndWatchAtOnceWithoutSendingOnAServerWithoutStreams(t *testing.T) {
	l := requireLive(t)
	if l.family != client.ServerFamilyTS3 {
		t.Skip("not a TeamSpeak 3 server")
	}
	s := attach(t, l.a, Options{})
	start := time.Now()
	_, err := s.Publish(t.Context(), PublishOptions{Name: "nope"})
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Family != client.ServerFamilyTS3 || unsupported.Version == "" {
		t.Fatalf("Publish: %v", err)
	}
	_, err = s.Watch(t.Context(), "x", WatchOptions{ClientID: l.b.ClientID()})
	if !errors.As(err, &unsupported) {
		t.Fatalf("Watch: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond || s.Supported() || len(s.List()) != 0 {
		t.Error("slow, supported or non-empty")
	}
	// The connection is none the worse.
	for _, c := range []*client.Client{l.a, l.b} {
		who, err := c.WhoAmI(t.Context())
		if err != nil || who.ClientID != c.ClientID() {
			t.Errorf("WhoAmI: %+v, %v", who, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
