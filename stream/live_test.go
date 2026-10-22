//go:build integration

package stream

// Live tests of streams: two or three voice clients on a real server, signalling
// a stream between them. They run when TEAMSPEAK_ADDR is set. On a TeamSpeak 6
// server they exercise the whole flow; on a TeamSpeak 3 server only that streams
// are refused up front, and the rest skips. The server needs a second channel
// (TEAMSPEAK_PASSWORD_CHANNEL) for the tests that move a client.
//
//	TEAMSPEAK_ADDR=127.0.0.1:9988 go test -race -tags integration -run Live ./stream

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

const eventTimeout = 8 * time.Second

// live is the two clients the live tests share, and what they found.
type live struct {
	a, b          *client.Client
	family        teamspeak.ServerFamily
	otherPassword string
	alpha, other  teamspeak.ChannelID
}

var (
	liveMu     sync.Mutex
	liveShared *live
	// Connects are paced: the server's flood protection bans an address that
	// connects too fast.
	paceMu     sync.Mutex
	paceStarts []time.Time
)

func paceConnect(ctx context.Context) error {
	for {
		paceMu.Lock()
		now := time.Now()
		for len(paceStarts) > 0 && now.Sub(paceStarts[0]) >= 10*time.Second {
			paceStarts = paceStarts[1:]
		}
		if len(paceStarts) < 8 {
			paceStarts = append(paceStarts, now)
			paceMu.Unlock()

			return nil
		}
		wait := 10*time.Second - now.Sub(paceStarts[0])
		paceMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// connectLive connects a client, trying again: a datagram can be dropped, and
// the server's flood protection is touchy.
func connectLive(t *testing.T, nickname, channel string, opts ...client.Option) *client.Client {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_ADDR")
	all := append([]client.Option{client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD"))}, opts...)
	if channel != "" {
		all = append(all, client.WithDefaultChannel(channel))
		if channel == os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL") {
			all = append(all, client.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD")))
		}
	}
	id, err := identity.Generate(t.Context(), 8)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(id, addr, nickname, all...)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; ; attempt++ {
		err = paceConnect(t.Context())
		if err == nil {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			err = c.Connect(ctx)
			cancel()
		}
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatalf("connecting %s: %v", nickname, err)
		}
		time.Sleep(2 * time.Second)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err = c.WaitView(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	return c
}

func requireLive(t *testing.T) *live {
	t.Helper()
	if os.Getenv("TEAMSPEAK_ADDR") == "" {
		t.Skip("TEAMSPEAK_ADDR not set")
	}
	liveMu.Lock()
	defer liveMu.Unlock()

	// The shared clients are made by the first test that needs them and left to
	// the process to drop; connecting uses that test's context only for the
	// handshake.
	if liveShared == nil {
		l := &live{
			a:             connectLive(t, "go-stream-a", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL")),
			b:             connectLive(t, "go-stream-b", os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL")),
			otherPassword: os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD"),
		}
		l.family = l.a.ServerCapabilities().Family
		for _, ch := range l.a.View().Channels() {
			switch ch.Name {
			case os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL"):
				l.alpha = ch.ID
			case os.Getenv("TEAMSPEAK_PASSWORD_CHANNEL"):
				l.other = ch.ID
			}
		}
		liveShared = l
	}

	return liveShared
}

func requireTS6(t *testing.T) *live {
	t.Helper()
	l := requireLive(t)
	if l.family != client.ServerFamilyTS6 {
		t.Skip("not a TeamSpeak 6 server")
	}
	t.Cleanup(func() { l.reset(t) })

	return l
}

// reset puts both clients back in the first channel.
func (l *live) reset(t *testing.T) {
	t.Helper()
	for _, c := range []*client.Client{l.a, l.b} {
		if c.Status() == client.StatusConnected && l.alpha != 0 {
			_ = c.MoveClient(context.WithoutCancel(t.Context()), c.ClientID(), l.alpha, teamspeak.ClientMoveOptions{})
		}
	}
	time.Sleep(300 * time.Millisecond)
}

// attach makes a Streams on c, closed after the test.
func attach(t *testing.T, c *client.Client, opts Options) *Streams {
	t.Helper()
	s := New(c, opts)
	t.Cleanup(func() { _ = s.Close(context.WithoutCancel(t.Context())) })

	return s
}

// listen collects what a handler registered by register is given and match accepts.
func listen[E any](register func(func(E)) func(), match func(E) bool) <-chan E {
	ch := make(chan E, 256)
	register(func(e E) {
		if match == nil || match(e) {
			select {
			case ch <- e:
			default:
			}
		}
	})

	return ch
}

func await[E any](t *testing.T, ch <-chan E, what string) E {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(eventTimeout):
		t.Fatalf("no %s arrived", what)

		var zero E

		return zero
	}
}

func awaitNone[E any](t *testing.T, ch <-chan E, what string, wait time.Duration) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected %s: %+v", what, e)
	case <-time.After(wait):
	}
}

func timeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)

	return ctx
}

// sdpLike is an SDP-looking text of about size characters, with the characters
// the wire has to escape.
func sdpLike(size int) string {
	lines := []string{
		"v=0", "o=- 4611731400430051336 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0",
		"m=audio 9 UDP/TLS/RTP/SAVPF 111", "m=video 9 UDP/TLS/RTP/SAVPF 96 97", "c=IN IP4 0.0.0.0", "a=rtcp-mux",
		"a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
		`a=note:quotes " pipes | back\slash ünï 日本 😀`,
	}
	var b strings.Builder
	n := 0
	for i := 0; n < size; i++ {
		line := lines[i%len(lines)] + "\r\n"
		b.WriteString(line)
		n += utf8.RuneCountInString(line)
	}

	return string([]rune(b.String())[:size])
}

func candidate(n int) IceCandidate {
	return IceCandidate{
		Candidate:     fmt.Sprintf("candidate:%d 1 udp 2122260223 192.168.0.%d %d typ host generation 0", n, n%250, 50000+n),
		SDPMid:        new("0"),
		SDPMLineIndex: new(uint16(0)),
	}
}

// eventually polls until condition holds, and fails after eventTimeout.
func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(eventTimeout); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if condition() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
