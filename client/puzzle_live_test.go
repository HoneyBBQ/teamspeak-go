//go:build integration

package client_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/identity"
)

// A live connect while the server asks for a high puzzle level.
//
// Opt-in twice: it runs only with TEAMSPEAK_ADDR and
// TEAMSPEAK_EXPECT_PUZZLE_LEVEL set. A server raises its protection level
// under a burst of connections from several addresses, which this test never
// causes: whoever runs it holds the server at that level, which falls back
// about a minute and a half after the last burst.
//
//	TEAMSPEAK_ADDR=127.0.0.1:9988 TEAMSPEAK_EXPECT_PUZZLE_LEVEL=1000000 \
//	  go test -tags integration -run PuzzleLevel -v ./client
func TestIntegration_ConnectsAtTheExpectedPuzzleLevel(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	raw := os.Getenv("TEAMSPEAK_EXPECT_PUZZLE_LEVEL")
	want, err := strconv.Atoi(raw)
	if err != nil || want <= 0 {
		t.Skip("TEAMSPEAK_EXPECT_PUZZLE_LEVEL not set")
	}
	id, err := identity.Generate(context.Background(), 8)
	requireNoErr(t, err)

	got := make(chan client.HandshakeDoneInfo, 1)
	c := newClient(t, id, addr, "PuzzleBot", client.WithTrace(&client.Trace{
		HandshakeDone: func(i client.HandshakeDoneInfo) { got <- i },
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	requireNoErr(t, c.Connect(ctx))
	defer func() { _ = c.Disconnect(context.Background()) }()

	info := <-got
	if info.PuzzleLevel != want {
		t.Errorf("puzzle level = %d, want %d", info.PuzzleLevel, want)
	}
	t.Logf("solved level %d in %v", info.PuzzleLevel, info.PuzzleDuration)
}
