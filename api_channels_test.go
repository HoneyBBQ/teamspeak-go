package teamspeak

import "testing"

func TestListChannels_AsksForEveryFlag(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.ListChannels(t.Context())

		return err
	})
	if line != "channellist -topic -flags -voice -limits -icon" {
		t.Errorf("line = %q", line)
	}
}

func TestListChannels_ParsesEveryField(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"cid": "5", "pid": "2", "channel_order": "4", "channel_name": "Lobby",
		"channel_topic": "hello", "channel_flag_default": "1", "channel_flag_password": "1",
		"channel_flag_permanent": "1", "channel_flag_semi_permanent": "1",
		"channel_codec": "4", "channel_codec_quality": "6", "channel_needed_talk_power": "10",
		"channel_icon_id": "77", "channel_maxclients": "-1", "channel_maxfamilyclients": "-1",
		"total_clients": "3", "total_clients_family": "7", "channel_needed_subscribe_power": "9",
	}}}}}
	got, err := NewCommands(s).ListChannels(t.Context())
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	want := Channel{
		ID: 5, ParentID: 2, Order: 4, Name: "Lobby", Topic: "hello",
		IsDefault: true, HasPassword: true, IsPermanent: true, IsSemiPermanent: true,
		Codec: Codec(4), CodecQuality: 6, NeededTalkPower: 10, IconID: 77,
		MaxClients: -1, MaxFamilyClients: -1, TotalClients: 3, TotalFamilyClients: 7,
		NeededSubscribePower: 9,
	}
	if got[0] != want {
		t.Errorf("channel = %+v, want %+v", got[0], want)
	}
}
