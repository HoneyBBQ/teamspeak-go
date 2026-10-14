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
//nolint:funlen // one scenario, recorded hook by hook
func TestIntegration_ConnectTrace(t *testing.T) {
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
	welcomed := make(chan struct{})
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}
	trace := &client.ConnectTrace{
		ResolveStart: func(client.ResolveStartInfo) { record("ResolveStart") },
		ResolveDone: func(i client.ResolveDoneInfo) {
			record("ResolveDone")
			resolveDone = i
		},
		ConnectStart: func(client.ConnectStartInfo) { record("ConnectStart") },
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

	opts := append(integrationClientOptions(nil), client.WithConnectTrace(trace))
	c := newClient(t, id, addr, "connect-trace", opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	select {
	case <-welcomed:
	case <-time.After(15 * time.Second):
		t.Fatal("WelcomeDone was not reported")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"ResolveStart", "ResolveDone", "ConnectStart", "HandshakeDone", "SessionStart", "WelcomeDone"}
	if !slices.Equal(order, want) {
		t.Fatalf("hooks = %v, want %v", order, want)
	}
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
	t.Logf("resolve %v, handshake %v, session %v, welcome %v (%s)",
		resolveDone.Duration, handshake.Duration, session.Duration, welcome.Duration, session.Capabilities.Version)
}

// Nothing listens on the port, so the attempt fails before any session: it is
// reported as AttemptFailed, never as SessionStart.
func TestIntegration_ConnectTraceAttemptFailed(t *testing.T) {
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
	trace := &client.ConnectTrace{
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
	c := newClient(t, id, closed, "connect-trace-fail", client.WithConnectTrace(trace))
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
