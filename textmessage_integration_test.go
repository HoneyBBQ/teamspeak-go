//go:build integration

package teamspeak_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

func TestIntegration_TextPrivateNotifyFields(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	var logBuf bytes.Buffer
	debugLogger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	receiver := newConnectedIntegrationClient(t, addr, "rx", debugLogger)

	sender := newConnectedIntegrationClient(t, addr, "tx", slog.Default())
	senderInfo, err := sender.GetClientInfo(sender.ClientID())
	if err != nil {
		t.Fatalf("sender GetClientInfo: %v", err)
	}
	senderUID := strings.TrimSpace(senderInfo["client_unique_identifier"])
	t.Logf("sender clientinfo keys: %v", mapKeys(senderInfo))

	received := make(chan teamspeak.TextMessage, 1)
	receiver.OnTextMessage(func(msg teamspeak.TextMessage) {
		select {
		case received <- msg:
		default:
		}
	})

	// Give both clients a brief moment to settle before sending the probe.
	time.Sleep(500 * time.Millisecond)

	probeText := fmt.Sprintf("cursor-probe-%d", time.Now().UTC().UnixNano())
	if err := sender.SendTextMessage(1, uint64(receiver.ClientID()), probeText); err != nil {
		t.Fatalf("sender SendTextMessage private: %v", err)
	}

	var msg teamspeak.TextMessage
	select {
	case msg = <-received:
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for private text notification; logs=%s", logBuf.String())
	}

	if msg.Message != probeText {
		t.Fatalf("unexpected message text: got %q want %q", msg.Message, probeText)
	}

	logs := logBuf.String()
	t.Logf("receiver logs: %s", logs)

	if !strings.Contains(logs, "\"name\":\"notifytextmessage\"") {
		t.Fatalf("expected notifytextmessage in logs, got: %s", logs)
	}

	targetNeedle := fmt.Sprintf("\"target\":\"%d\"", receiver.ClientID())
	if !strings.Contains(logs, targetNeedle) {
		t.Fatalf("expected raw notify target %s in logs, got: %s", targetNeedle, logs)
	}

	rawInvokerUID := extractJSONField(logs, "\"invokeruid\":\"")
	if rawInvokerUID == "" {
		t.Fatalf("expected raw notify invokeruid in logs, got: %s", logs)
	}

	if msg.TargetMode != 1 {
		t.Fatalf("unexpected target mode: got %d want 1", msg.TargetMode)
	}

	if msg.TargetID != uint64(receiver.ClientID()) {
		t.Fatalf("parsed TargetID mismatch: got %d want %d", msg.TargetID, receiver.ClientID())
	}

	expectedInvokerUID := rawInvokerUID
	if senderUID != "" {
		expectedInvokerUID = senderUID
	}
	if strings.TrimSpace(msg.InvokerUID) != expectedInvokerUID {
		t.Fatalf("parsed InvokerUID mismatch: got %q want %q", msg.InvokerUID, expectedInvokerUID)
	}
}

func newConnectedIntegrationClient(t *testing.T, addr string, nicknamePrefix string, logger *slog.Logger) *teamspeak.Client {
	t.Helper()

	id, err := crypto.GenerateIdentity(8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	nickname := nicknamePrefix + strconv.FormatInt(time.Now().UTC().UnixNano()%1_000_000, 10)
	client := teamspeak.NewClient(id, addr, nickname, teamspeak.WithLogger(logger))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect(%s): %v", nickname, err)
	}

	t.Cleanup(func() {
		_ = client.Disconnect()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.WaitConnected(ctx); err != nil {
		t.Fatalf("WaitConnected(%s): %v", nickname, err)
	}
	return client
}

func extractJSONField(s string, needle string) string {
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(s[start:], "\"")
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}
