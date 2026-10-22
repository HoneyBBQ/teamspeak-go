//go:build integration

// Package e2e carries a stream between two WebRTC peers over a live TeamSpeak 6
// server, with the stream package doing all the signalling. It is a module of
// its own so that the WebRTC stack stays out of the SDK's dependencies.
//
//	TEAMSPEAK_ADDR=127.0.0.1:9988 go test -race -tags integration ./...
package e2e

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/stream"
)

func connect(t *testing.T, nickname string) *client.Client {
	t.Helper()
	opts := []client.Option{client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD"))}
	if ch := os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"); ch != "" {
		opts = append(opts, client.WithDefaultChannel(ch))
	}
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(id, os.Getenv("TEAMSPEAK_ADDR"), nickname, opts...)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		err = c.Connect(ctx)
		cancel()
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatalf("connecting %s: %v", nickname, err)
		}
		time.Sleep(2 * time.Second)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.WithoutCancel(t.Context())) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err = c.WaitView(ctx)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func toStream(c webrtc.ICECandidateInit) stream.IceCandidate {
	return stream.IceCandidate{Candidate: c.Candidate, SDPMid: c.SDPMid, SDPMLineIndex: c.SDPMLineIndex}
}

func toPion(c stream.IceCandidate) webrtc.ICECandidateInit {
	return webrtc.ICECandidateInit{Candidate: c.Candidate, SDPMid: c.SDPMid, SDPMLineIndex: c.SDPMLineIndex}
}

// sizes keeps the largest of what went over the wire.
type sizes struct {
	mu                    sync.Mutex
	offer, answer, maxCan int
	candidates            int
}

func (s *sizes) setAnswer(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer = n
}

func (s *sizes) log(t *testing.T, packets int64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Logf("offer %d bytes, answer %d bytes, %d candidates seen by the SDK, longest %d bytes, %d RTP packets",
		s.offer, s.answer, s.candidates, s.maxCan, packets)
}

func (s *sizes) candidate(c stream.IceCandidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates++
	s.maxCan = max(s.maxCan, len(c.Candidate))
}

func connected(t *testing.T, pc *webrtc.PeerConnection, who string) <-chan struct{} {
	ch := make(chan struct{})
	var once sync.Once
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		t.Logf("%s ICE: %s", who, s)
		if s == webrtc.ICEConnectionStateConnected || s == webrtc.ICEConnectionStateCompleted {
			once.Do(func() { close(ch) })
		}
	})

	return ch
}

// publisherSide is the publisher's peer connection: a VP8 track, and an audio
// transceiver that sends nothing but is offered anyway, as the TeamSpeak 6
// client requires.
type publisherSide struct {
	pc       *webrtc.PeerConnection
	track    *webrtc.TrackLocalStaticSample
	up       <-chan struct{}
	gathered chan webrtc.ICECandidateInit
}

func newPublisherSide(t *testing.T) *publisherSide {
	t.Helper()
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	audio := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly}
	_, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, audio)
	if err != nil {
		t.Fatal(err)
	}
	vp8 := webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}
	track, err := webrtc.NewTrackLocalStaticSample(vp8, "video", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			_, _, err := sender.Read(buf)
			if err != nil {
				return
			}
		}
	}()
	p := &publisherSide{
		pc: pc, track: track, up: connected(t, pc, "publisher"),
		gathered: make(chan webrtc.ICECandidateInit, 64),
	}
	// Candidates found before the viewer's peer exists wait here.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			p.gathered <- c.ToJSON()
		}
	})

	return p
}

// offer makes the offer and hands it, with the candidates, to the viewer.
func (p *publisherSide) accept(t *testing.T, request *stream.JoinRequest, wire *sizes) {
	t.Helper()
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.pc.SetLocalDescription(offer)
	if err != nil {
		t.Fatal(err)
	}
	wire.offer = len(offer.SDP)
	t.Logf("offer: %d bytes", wire.offer)
	peer, err := request.Accept(t.Context(), offer.SDP, "welcome")
	if err != nil {
		t.Fatalf("Accept (offer of %d bytes): %v", len(offer.SDP), err)
	}
	peer.OnAnswer(func(sdp string) {
		wire.setAnswer(len(sdp))
		answer := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}
		err := p.pc.SetRemoteDescription(answer)
		if err != nil {
			t.Errorf("publisher SetRemoteDescription: %v", err)
		}
	})
	peer.OnCandidate(func(c stream.IceCandidate) {
		wire.candidate(c)
		err := p.pc.AddICECandidate(toPion(c))
		if err != nil {
			t.Errorf("publisher AddICECandidate: %v", err)
		}
	})
	go func() {
		for c := range p.gathered {
			err := peer.SendCandidate(t.Context(), toStream(c))
			if err != nil && t.Context().Err() == nil {
				t.Errorf("publisher SendCandidate: %v", err)
			}
		}
	}()
}

// frames writes video until the context ends.
func (p *publisherSide) frames(ctx context.Context) {
	tick := time.NewTicker(33 * time.Millisecond)
	defer tick.Stop()
	frame := make([]byte, 400)
	frame[0] = 0x10 // a VP8 key frame marker; the payload is opaque to the transport
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = p.track.WriteSample(media.Sample{Data: frame, Duration: 33 * time.Millisecond})
		}
	}
}

// viewerSide is the viewer's receive-only peer connection.
type viewerSide struct {
	pc      *webrtc.PeerConnection
	up      <-chan struct{}
	packets atomic.Int64
}

func newViewerSide(t *testing.T) *viewerSide {
	t.Helper()
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	v := &viewerSide{pc: pc, up: connected(t, pc, "viewer")}
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		t.Logf("viewer track: %s", tr.Codec().MimeType)
		for {
			_, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			v.packets.Add(1)
		}
	})

	return v
}

// answer takes the publisher's offer and sends the answer, and only then the
// candidates: one that outran the answer would reach a publisher that cannot
// use it yet.
func (v *viewerSide) answer(t *testing.T, view *stream.View, wire *sizes) {
	t.Helper()
	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: view.Offer()}
	err := v.pc.SetRemoteDescription(offer)
	if err != nil {
		t.Fatal(err)
	}
	view.OnCandidate(func(c stream.IceCandidate) {
		wire.candidate(c)
		addErr := v.pc.AddICECandidate(toPion(c))
		if addErr != nil {
			t.Errorf("viewer AddICECandidate: %v", addErr)
		}
	})
	found := make(chan webrtc.ICECandidateInit, 64)
	v.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			found <- c.ToJSON()
		}
	})
	answer, err := v.pc.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = v.pc.SetLocalDescription(answer)
	if err != nil {
		t.Fatal(err)
	}
	err = view.Answer(t.Context(), answer.SDP)
	if err != nil {
		t.Fatalf("Answer (%d bytes): %v", len(answer.SDP), err)
	}
	go func() {
		for c := range found {
			err := view.SendCandidate(t.Context(), toStream(c))
			if err != nil && t.Context().Err() == nil {
				t.Errorf("viewer SendCandidate: %v", err)
			}
		}
	}()
}

func TestLive_PublisherToViewerCarriesRTP(t *testing.T) {
	if os.Getenv("TEAMSPEAK_ADDR") == "" {
		t.Skip("TEAMSPEAK_ADDR not set")
	}
	a, b := connect(t, "go-e2e-pub"), connect(t, "go-e2e-view")
	publisher, viewer := stream.New(a, stream.Options{}), stream.New(b, stream.Options{})
	t.Cleanup(func() { _ = viewer.Close(context.WithoutCancel(t.Context())) })
	t.Cleanup(func() { _ = publisher.Close(context.WithoutCancel(t.Context())) })
	if !publisher.Supported() {
		t.Skip("not a TeamSpeak 6 server")
	}
	var wire sizes
	pub, info := publishAndFind(t, publisher, viewer)
	requests := make(chan *stream.JoinRequest, 1)
	pub.OnRequest(func(r *stream.JoinRequest) { requests <- r })
	pubSide, viewSide := newPublisherSide(t), newViewerSide(t)

	watching := make(chan *stream.View, 1)
	go func() {
		v, err := viewer.WatchInfo(t.Context(), info, stream.WatchOptions{Message: "e2e"})
		if err != nil {
			t.Errorf("Watch: %v", err)
		}
		watching <- v
	}()
	pubSide.accept(t, <-requests, &wire)
	view := <-watching
	if view == nil {
		t.FailNow()
	}
	viewSide.answer(t, view, &wire)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	go pubSide.frames(ctx)

	waitUp(t, pubSide.up, viewSide.up)
	viewSide.waitPackets(t, 20)
	wire.log(t, viewSide.packets.Load())
}

// publishAndFind publishes a stream and waits for the viewer to hear of it.
func publishAndFind(t *testing.T, publisher, viewer *stream.Streams) (*stream.Published, stream.Info) {
	t.Helper()
	started := make(chan stream.Info, 4)
	viewer.OnStarted(func(i stream.Info) { started <- i })
	pub, err := publisher.Publish(t.Context(), stream.PublishOptions{Name: "e2e", Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case info := <-started:
		return pub, info
	case <-time.After(8 * time.Second):
		t.Fatal("the viewer never heard of the stream")

		return nil, stream.Info{}
	}
}

// waitUp waits for ICE to connect on both sides.
func waitUp(t *testing.T, up ...<-chan struct{}) {
	t.Helper()
	for i, ch := range up {
		select {
		case <-ch:
		case <-time.After(15 * time.Second):
			t.Fatalf("ICE never connected on side %d", i)
		}
	}
}

// waitPackets waits for the viewer to have received n RTP packets.
func (v *viewerSide) waitPackets(t *testing.T, n int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for v.packets.Load() < n && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := v.packets.Load(); got < n {
		t.Fatalf("only %d RTP packets arrived", got)
	}
}
