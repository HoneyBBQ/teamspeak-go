//go:build integration

package teamspeak_test

import "testing"

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

	if _, descErr := c.GetChannelDescription(t.Context(), first.ID); descErr != nil {
		t.Errorf("GetChannelDescription: %v", descErr)
	}
}
