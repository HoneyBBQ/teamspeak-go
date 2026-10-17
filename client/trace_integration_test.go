//go:build integration

package client_test

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// The trace must report a real connection's milestones in order, with timings
// that grow, on TeamSpeak 3 and 6 alike.
//
//nolint:cyclop,funlen,gocyclo // one scenario, recorded hook by hook
func TestIntegration_Trace(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	var mu sync.Mutex
	var order []string
	var resolveDone client.ResolveDoneInfo
	var handshake client.HandshakeDoneInfo
	var session client.SessionStartInfo
	var welcome client.WelcomeDoneInfo
	var connectDone client.ConnectDoneInfo
	var disconnectDone client.DisconnectDoneInfo
	var sessionEnd client.SessionEndInfo
	ended := make(chan struct{})
	welcomed := make(chan struct{})
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}
	trace := &client.Trace{
		ResolveStart: func(client.ResolveStartInfo) { record("ResolveStart") },
		ResolveDone: func(i client.ResolveDoneInfo) {
			record("ResolveDone")
			resolveDone = i
		},
		ConnectStart: func(client.ConnectStartInfo) { record("ConnectStart") },
		ConnectDone: func(i client.ConnectDoneInfo) {
			record("ConnectDone")
			connectDone = i
		},
		DisconnectStart: func(client.DisconnectStartInfo) { record("DisconnectStart") },
		DisconnectDone: func(i client.DisconnectDoneInfo) {
			record("DisconnectDone")
			disconnectDone = i
		},
		SessionEnd: func(i client.SessionEndInfo) {
			record("SessionEnd")
			sessionEnd = i
			close(ended)
		},
		ReconnectStopped: func(client.ReconnectStoppedInfo) { record("ReconnectStopped") },
		HandshakeDone: func(i client.HandshakeDoneInfo) {
			record("HandshakeDone")
			handshake = i
		},
		SessionStart: func(i client.SessionStartInfo) {
			record("SessionStart")
			session = i
		},
		WelcomeDone: func(i client.WelcomeDoneInfo) {
			record("WelcomeDone")
			welcome = i
			close(welcomed)
		},
		AttemptFailed:      func(client.AttemptFailedInfo) { record("AttemptFailed") },
		ReconnectScheduled: func(client.ReconnectScheduledInfo) { record("ReconnectScheduled") },
	}

	opts := append(integrationClientOptions(nil), client.WithTrace(trace))
	c := newClient(t, id, addr, "connect-trace", opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	requireNoErr(t, paceConnect(ctx))
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	disconnected := false
	t.Cleanup(func() {
		if !disconnected {
			_ = c.Disconnect(context.Background())
		}
	})

	select {
	case <-welcomed:
	case <-time.After(15 * time.Second):
		t.Fatal("WelcomeDone was not reported")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"ResolveStart", "ResolveDone", "ConnectStart", "ConnectDone", "HandshakeDone", "SessionStart", "WelcomeDone",
	}
	if !slices.Equal(order, want) {
		t.Fatalf("hooks = %v, want %v", order, want)
	}
	requireNewTraceFields(t, c, "connect-trace", resolveDone, connectDone, handshake, session, welcome)
	if session.ClientID != c.ClientID() || session.ClientID == 0 {
		t.Errorf("SessionStart.ClientID = %d, ClientID() = %d", session.ClientID, c.ClientID())
	}
	for name, d := range map[string]time.Duration{
		"ResolveDone":   resolveDone.Duration,
		"HandshakeDone": handshake.Duration,
		"SessionStart":  session.Duration,
		"WelcomeDone":   welcome.Duration,
	} {
		if d <= 0 {
			t.Errorf("%s.Duration = %v, want > 0", name, d)
		}
	}
	if handshake.Duration > session.Duration || session.Duration > welcome.Duration {
		t.Errorf("durations out of order: handshake %v, session %v, welcome %v",
			handshake.Duration, session.Duration, welcome.Duration)
	}
	if resolveDone.Target == "" {
		t.Error("ResolveDone.Target is empty")
	}
	t.Logf("resolve %v, handshake %v (puzzle level %d, %d resends), session %v, welcome %v (%s)",
		resolveDone.Duration, handshake.Duration, handshake.PuzzleLevel, handshake.Resends,
		session.Duration, welcome.Duration, session.Capabilities.Version)

	mu.Unlock()
	disconnected = true
	err = c.Disconnect(context.Background())
	mu.Lock()
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("SessionEnd was not reported")
	}
	tail := order[len(order)-3:]
	if !slices.Equal(tail, []string{"DisconnectStart", "DisconnectDone", "SessionEnd"}) {
		t.Errorf("hooks after Disconnect = %v", tail)
	}
	if !disconnectDone.Acknowledged || disconnectDone.Duration <= 0 {
		t.Errorf("DisconnectDone = %+v, want the goodbye acknowledged", disconnectDone)
	}
	if sessionEnd.Cause != nil || sessionEnd.ClientID != session.ClientID || sessionEnd.Duration <= 0 {
		t.Errorf("SessionEnd = %+v", sessionEnd)
	}
}

// requireNewTraceFields checks what the milestones know on a real server, which
// is the same on TeamSpeak 3 and 6.
func requireNewTraceFields(
	t *testing.T, c *client.Client, nickname string, resolveDone client.ResolveDoneInfo,
	connectDone client.ConnectDoneInfo, handshake client.HandshakeDoneInfo, session client.SessionStartInfo,
	welcome client.WelcomeDoneInfo,
) {
	t.Helper()
	if len(resolveDone.Candidates) == 0 && resolveDone.Source != "Fallback" {
		t.Errorf("ResolveDone has no candidates and did not fall back: %+v", resolveDone)
	}
	if connectDone.LocalAddr == "" || connectDone.Duration <= 0 {
		t.Errorf("ConnectDone = %+v", connectDone)
	}
	if handshake.PuzzleLevel <= 0 || handshake.PuzzleDuration <= 0 {
		t.Errorf("HandshakeDone puzzle = level %d in %v, want both positive", handshake.PuzzleLevel, handshake.PuzzleDuration)
	}
	if handshake.ServerPublicKey == "" {
		t.Error("HandshakeDone.ServerPublicKey is empty")
	}
	if session.Nickname != nickname {
		t.Errorf("SessionStart.Nickname = %q, want %q", session.Nickname, nickname)
	}
	if session.Capabilities.ServerID <= 0 {
		t.Errorf("Capabilities.ServerID = %d, want > 0", session.Capabilities.ServerID)
	}
	if _, secret := session.InitServer["client_server_password"]; secret || len(session.InitServer) == 0 {
		t.Errorf("SessionStart.InitServer = %d keys, secret present: %v", len(session.InitServer), secret)
	}
	if welcome.ChannelID == 0 || welcome.ChannelID != c.ChannelID() {
		t.Errorf("WelcomeDone.ChannelID = %d, ChannelID() = %d, want equal and > 0", welcome.ChannelID, c.ChannelID())
	}
	// The fixture has Default Channel, Alpha and Secret.
	if welcome.Channels < 3 || welcome.Clients < 1 {
		t.Errorf("WelcomeDone = %d channels, %d clients, want at least 3 and 1", welcome.Channels, welcome.Clients)
	}
}

// Nothing listens on the port, so the attempt fails before any session: it is
// reported as AttemptFailed, never as SessionStart.
func TestIntegration_TraceAttemptFailed(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	closed := pc.LocalAddr().String()
	_ = pc.Close()

	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	var mu sync.Mutex
	var failures []client.AttemptFailedInfo
	sessions := 0
	trace := &client.Trace{
		SessionStart: func(client.SessionStartInfo) {
			mu.Lock()
			sessions++
			mu.Unlock()
		},
		AttemptFailed: func(i client.AttemptFailedInfo) {
			mu.Lock()
			failures = append(failures, i)
			mu.Unlock()
		},
	}
	c := newClient(t, id, closed, "connect-trace-fail", client.WithTrace(trace))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	err = c.Connect(ctx)

	if err == nil {
		t.Fatal("Connect to a closed port succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(failures) != 1 || sessions != 0 {
		t.Fatalf("AttemptFailed %d times, SessionStart %d times; want 1 and 0", len(failures), sessions)
	}
	got := failures[0]
	if got.Phase != client.ConnectPhaseHandshake && got.Phase != client.ConnectPhaseOpen {
		t.Errorf("Phase = %v, want handshake or open", got.Phase)
	}
	// A refused datagram can end the attempt before the context does, so the
	// cause is Connect's own error, which is the context's when it ran out.
	if got.Err == nil || got.Err.Error() != err.Error() {
		t.Errorf("AttemptFailed.Err = %v, Connect returned %v", got.Err, err)
	}
	if got.Attempt != 1 || got.Reconnect || got.Duration <= 0 {
		t.Errorf("AttemptFailed = %+v", got)
	}
}
