//go:build integration

package client_test

import (
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

// The typed channel layer issues real commands rather than building strings
// that happen to compile.
func TestIntegration_ChannelAPI(t *testing.T) {
	c := requireSharedClient(t)

	channels, err := c.ListChannels(t.Context())
	requireNoErr(t, err)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) == 0 {
		t.Fatal("expected at least one channel")
	}

	checkListedChannelFlags(t, c, channels)

	first := channels[0]
	if first.Name == "" {
		t.Error("channel has no name")
	}
	if first.ID == 0 {
		t.Error("channel has id 0")
	}
	t.Logf("channel: id=%d name=%q order=%d permanent=%v", first.ID, first.Name, first.Order, first.IsPermanent)

	// A second read of the same channel must agree, which exercises the
	// channelinfo path (pid, not cpid) against the list path (cpid).
	info, err := c.GetChannelInfo(t.Context(), first.ID)
	if err != nil {
		t.Fatalf("GetChannelInfo: %v", err)
	}
	if info.Name != first.Name {
		t.Errorf("GetChannelInfo name = %q, list said %q", info.Name, first.Name)
	}
	if info.ID != first.ID {
		t.Errorf("GetChannelInfo id = %d, list said %d", info.ID, first.ID)
	}
	// channellist reports cpid, channelinfo reports pid; both must land in
	// ParentID or one of the two silently reads 0.
	if info.ParentID != first.ParentID {
		t.Errorf("GetChannelInfo parentID = %d, list said %d", info.ParentID, first.ParentID)
	}

	_, descErr := c.GetChannelDescription(t.Context(), first.ID)
	if descErr != nil {
		t.Errorf("GetChannelDescription: %v", descErr)
	}
}

func checkListedChannelFlags(t *testing.T, c *client.Client, channels []teamspeak.Channel) {
	t.Helper()
	// channellist is asked for its flags, so they are filled in: the shared
	// client's own channel holds at least the client itself.
	permanent := false
	for _, ch := range channels {
		permanent = permanent || ch.IsPermanent
		if ch.ID == c.ChannelID() && ch.TotalClients < 1 {
			t.Errorf("channel %d holds this client but TotalClients = %d", ch.ID, ch.TotalClients)
		}
		if ch.IsDefault && !ch.IsPermanent {
			t.Errorf("default channel %d is not permanent", ch.ID)
		}
	}
	if !permanent {
		t.Error("no channel is permanent: the flags were not requested")
	}
}
