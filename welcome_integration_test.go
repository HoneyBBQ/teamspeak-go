//go:build integration

package teamspeak_test

import (
	"context"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

// The server pushes its own channellist, channelgrouplist and so on as soon as
// the handshake completes, without being asked. A client that issues a command
// immediately must not have that data land in its response: asking for
// channellist used to return duplicate rows plus a phantom cid=0, while the
// same call made a second later was correct.
func TestIntegration_NoWelcomeContamination(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	id, err := crypto.GenerateIdentity(8)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	c := teamspeak.NewClient(id, addr, "welcome-contamination", integrationClientOptions(nil)...)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.WaitConnected(ctx); err != nil {
		t.Fatalf("WaitConnected: %v", err)
	}

	// No settling delay: the point is to ask while the welcome is still
	// arriving, which is exactly when contamination used to happen.
	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	seen := make(map[uint64]bool)
	for _, ch := range channels {
		if ch.ID == 0 {
			t.Errorf("phantom channel with id 0 in %d rows", len(channels))
		}
		if seen[ch.ID] {
			t.Errorf("duplicate channel id %d in %d rows", ch.ID, len(channels))
		}
		seen[ch.ID] = true
	}

	// A second read must agree with the first; contamination made the early
	// read longer than the settled one.
	again, err := c.ListChannels(t.Context())
	if err != nil {
		t.Fatalf("ListChannels (second): %v", err)
	}
	if len(again) != len(channels) {
		t.Errorf("first read returned %d channels, settled read %d", len(channels), len(again))
	}
}
