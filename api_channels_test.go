package teamspeak

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestListChannels_AsksForEveryFlag(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.ListChannels(t.Context(), ChannelListOptions{})

		return err
	})
	if line != "channellist -topic -flags -voice -limits -icon -secondsempty -banners" {
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
	got, err := NewCommands(s).ListChannels(t.Context(), ChannelListOptions{})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	want := Channel{
		ID: 5, ParentID: 2, Order: 4, Name: "Lobby", Topic: "hello",
		IsDefault: true, HasPassword: true, IsPermanent: true, IsSemiPermanent: true,
		Codec: Codec(4), CodecQuality: 6, NeededTalkPower: 10, IconID: 77,
		MaxClients: -1, MaxFamilyClients: -1, TotalClients: new(int32(3)), TotalFamilyClients: new(int32(7)),
		NeededSubscribePower: new(int32(9)),
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("channel = %+v, want %+v", got[0], want)
	}
}

func TestParseChannel_AbsentCountsAreNilAndPresentZerosAreNot(t *testing.T) {
	absent := parseChannel(map[string]string{"cid": "5", "channel_name": "Lobby"})
	if absent.TotalClients != nil || absent.TotalFamilyClients != nil || absent.NeededSubscribePower != nil {
		t.Errorf("absent counts = %v %v %v, want nil",
			absent.TotalClients, absent.TotalFamilyClients, absent.NeededSubscribePower)
	}

	zero := parseChannel(map[string]string{
		"total_clients": "0", "total_clients_family": "0", "channel_needed_subscribe_power": "0",
	})
	if zero.TotalClients == nil || *zero.TotalClients != 0 ||
		zero.TotalFamilyClients == nil || *zero.TotalFamilyClients != 0 ||
		zero.NeededSubscribePower == nil || *zero.NeededSubscribePower != 0 {
		t.Errorf("zero counts = %v %v %v, want pointers to 0",
			zero.TotalClients, zero.TotalFamilyClients, zero.NeededSubscribePower)
	}
}

func TestListBindings_FillsTheSubsystem(t *testing.T) {
	for _, tc := range []struct{ asked, want string }{{"", "voice"}, {"query", "query"}} {
		s := &script{replies: []reply{{rows: []map[string]string{{"ip": "0.0.0.0"}}}}}
		got, err := NewCommands(s).ListBindings(t.Context(), BindingListOptions{Subsystem: tc.asked})
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v", got, err)
		}
		if want := (Binding{Subsystem: tc.want, IP: "0.0.0.0"}); !reflect.DeepEqual(got[0], want) {
			t.Errorf("asked %q: binding = %+v, want %+v", tc.asked, got[0], want)
		}
	}
}

func TestListBindings_PortIsNilWhenNotReported(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"ip": "::", "port": "9987"}, {"ip": "::"}}}}}
	got, err := NewCommands(s).ListBindings(t.Context(), BindingListOptions{})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
	if got[0].Port == nil || *got[0].Port != 9987 || got[1].Port != nil {
		t.Errorf("ports = %v, %v, want 9987 and nil", got[0].Port, got[1].Port)
	}
}

// channelcreate answered with status ok and no row: the channel exists, so it
// is found by its exact name under the same parent.
func TestCreateChannel_WithoutACidFindsTheChannelByNameAndParent(t *testing.T) {
	list := []map[string]string{
		{"cid": "1", "cpid": "0", "channel_name": "Room"},
		{"cid": "2", "cpid": "1", "channel_name": "Room"},
		{"cid": "3", "cpid": "1", "channel_name": "Room 2"},
	}
	s := &script{replies: []reply{{}, {rows: list}, {}, {rows: list}}}
	c := NewCommands(s)

	id, err := c.CreateChannel(t.Context(), ChannelCreateOptions{Name: "Room", ParentID: 1})
	if err != nil || id != 2 {
		t.Errorf("under 1: id = %d, err = %v, want 2", id, err)
	}
	id, err = c.CreateChannel(t.Context(), ChannelCreateOptions{Name: "Room"})
	if err != nil || id != 1 {
		t.Errorf("top level: id = %d, err = %v, want 1", id, err)
	}
	if len(s.sent) != 4 || !strings.HasPrefix(s.sent[1], "channellist") {
		t.Errorf("sent %q", s.sent)
	}
}

func TestCreateChannel_WithoutACidAndNoMatchIsNoData(t *testing.T) {
	list := []map[string]string{{"cid": "1", "cpid": "0", "channel_name": "Other"}}
	for _, opts := range []ChannelCreateOptions{{Name: "Room"}, {Name: "Other", ParentID: 5}} {
		s := &script{replies: []reply{{}, {rows: list}}}
		_, err := NewCommands(s).CreateChannel(t.Context(), opts)
		if !errors.Is(err, ErrNoData) {
			t.Errorf("%+v: err = %v, want ErrNoData", opts, err)
		}
	}
}

func TestCreateChannel_WithACidLooksNothingUp(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{"cid": "9"}}}}}
	id, err := NewCommands(s).CreateChannel(t.Context(), ChannelCreateOptions{Name: "Room"})
	if err != nil || id != 9 || len(s.sent) != 1 {
		t.Errorf("id = %d, err = %v, sent %q", id, err, s.sent)
	}
}
