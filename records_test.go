package teamspeak

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A clientlist row carrying every key a client record reads.
func fullClientRow() map[string]string {
	return map[string]string{
		"clid": "7", "cid": "3", "client_database_id": "42", "client_nickname": "Ann",
		"client_type": "0", "client_unique_identifier": "uidAnn=", "client_away": "1",
		"client_away_message": "lunch", "client_is_recording": "0", "client_is_talker": "1",
		"client_servergroups": "6,9", "client_channel_group_id": "8",
		"client_channel_group_inherited_channel_id": "3",
		"client_input_muted":                        "1", "client_output_muted": "0", "client_outputonly_muted": "0",
		"client_input_hardware": "1", "client_output_hardware": "1",
		"client_is_channel_commander": "0", "client_is_priority_speaker": "1", "client_talk_power": "75",
		"client_talk_request": "1700000000", "client_talk_request_msg": "please",
		"client_description": "desc", "client_meta_data": "meta", "client_flag_avatar": "abc123",
		"client_icon_id": "99", "client_nickname_phonetic": "an", "client_unread_messages": "0",
		"client_needed_serverquery_view_power": "75", "client_country": "SE",
		"client_version": "3.6.2", "client_platform": "Windows", "connection_client_ip": "10.0.0.2",
		"client_badges": "overwolf=0", "client_signed_badges": "sb", "client_myteamspeak_id": "mt",
		"client_myteamspeak_avatar": "mta", "client_integrations": "int", "client_user_tag": "tag",
		"client_is_streaming": "1", "client_created": "1600000000", "client_lastconnected": "1700000001",
		"client_idle_time": "1500",
	}
}

func TestParseClient_ReadsEveryField(t *testing.T) {
	got := parseClient(fullClientRow())
	want := ClientEntry{
		ID: 7, ChannelID: 3, DatabaseID: 42, Nickname: "Ann", UID: "uidAnn=", IsAway: true,
		AwayMessage: "lunch", IsTalker: true, ServerGroups: []ServerGroupID{6, 9}, ChannelGroupID: 8,
		ChannelGroupInheritedChannelID: 3, IsInputMuted: new(true), IsOutputMuted: new(false),
		IsOutputOnlyMuted: new(false), HasInputHardware: new(true), HasOutputHardware: new(true),
		IsChannelCommander: new(false), IsPrioritySpeaker: new(true), TalkPower: new(int32(75)),
		IsRequestingTalk: new(true), TalkRequestMessage: "please", Description: "desc", MetaData: "meta",
		Avatar: "abc123", IconID: 99, NicknamePhonetic: "an", UnreadMessages: new(int32(0)),
		NeededServerQueryViewPower: new(int32(75)), Country: "SE", Version: "3.6.2", Platform: "Windows",
		IP: "10.0.0.2", Badges: "overwolf=0", SignedBadges: "sb", MyTeamSpeakID: "mt",
		MyTeamSpeakAvatar: "mta", Integrations: "int", UserTag: "tag", IsStreaming: new(true),
		Created: time.Unix(1600000000, 0), LastConnected: time.Unix(1700000001, 0),
		IdleTime: 1500 * time.Millisecond, TalkRequestedAt: time.Unix(1700000000, 0),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseClient = %+v\nwant %+v", got, want)
	}
}

// A bare clientlist row brings no flag: what a flag would bring is unknown,
// not false or 0.
func TestParseClient_AbsentFlagFieldsAreUnknown(t *testing.T) {
	got := parseClient(map[string]string{"clid": "7", "cid": "3", "client_nickname": "Ann"})
	want := ClientEntry{ID: 7, ChannelID: 3, Nickname: "Ann"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseClient = %+v, want %+v", got, want)
	}
}

// A present zero is a value, unlike an absent key.
func TestParseClient_PresentZerosAreKept(t *testing.T) {
	got := parseClient(map[string]string{
		"clid": "7", "client_input_muted": "0", "client_talk_power": "0", "client_talk_request": "0",
	})
	if got.IsInputMuted == nil || *got.IsInputMuted || got.TalkPower == nil || *got.TalkPower != 0 ||
		got.IsRequestingTalk == nil || *got.IsRequestingTalk {
		t.Errorf("zeros = %v %v %v, want pointers to false, 0, false", got.IsInputMuted, got.TalkPower, got.IsRequestingTalk)
	}
}

func TestParseChannel_ReadsTheChannelInfoFields(t *testing.T) {
	got := parseChannel(map[string]string{
		"cid": "5", "channel_name": "Lobby", "channel_codec_latency_factor": "2",
		"channel_codec_is_unencrypted": "1", "channel_flag_maxclients_unlimited": "1",
		"channel_flag_maxfamilyclients_unlimited": "0", "channel_flag_maxfamilyclients_inherited": "1",
		"channel_delete_delay": "90", "channel_name_phonetic": "lob", "channel_forced_silence": "0",
		"channel_banner_gfx_url": "https://example.test/b.png", "channel_banner_mode": "1",
	})
	want := Channel{
		ID: 5, Name: "Lobby", CodecLatencyFactor: new(int32(2)), IsUnencrypted: new(true),
		IsMaxClientsUnlimited: new(true), IsMaxFamilyClientsUnlimited: new(false),
		IsMaxFamilyClientsInherited: new(true), DeleteDelay: new(90 * time.Second), NamePhonetic: "lob",
		IsForcedSilence: new(false), BannerURL: "https://example.test/b.png", BannerMode: new(int32(1)),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseChannel = %+v\nwant %+v", got, want)
	}
}

// A channellist row has none of them.
func TestParseChannel_ListRowLeavesThemUnknown(t *testing.T) {
	got := parseChannel(map[string]string{"cid": "5", "channel_name": "Lobby", "channel_flag_default": "1"})
	want := Channel{ID: 5, Name: "Lobby", IsDefault: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseChannel = %+v, want %+v", got, want)
	}
}

// derefType is the type of a field with one level of pointer removed: an option
// is a pointer where the record holds the value, and a record's own optional
// field is a pointer too.
func derefType(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Pointer {
		return t.Elem()
	}

	return t
}

// A property has one name wherever the SDK writes it and reads it back: every
// field of an options struct is a field of the record, of the same type.
func TestRecordFieldsShareTheNamesOfTheOptions(t *testing.T) {
	cases := []struct {
		record  reflect.Type
		options reflect.Type
		skip    map[string]bool
	}{
		{reflect.TypeFor[ClientEntry](), reflect.TypeFor[ClientUpdateOptions](), nil},
		{reflect.TypeFor[ClientEntry](), reflect.TypeFor[ClientEditOptions](), nil},
		{reflect.TypeFor[Channel](), reflect.TypeFor[ChannelCreateOptions](), map[string]bool{"Password": true}},
		{reflect.TypeFor[Channel](), reflect.TypeFor[ChannelEditOptions](), map[string]bool{"Password": true}},
	}
	for _, c := range cases {
		for field := range c.options.Fields() {
			if c.skip[field.Name] {
				continue
			}
			got, ok := c.record.FieldByName(field.Name)
			if !ok {
				t.Errorf("%s has %s, which %s lacks", c.options, field.Name, c.record)

				continue
			}
			if derefType(got.Type) != derefType(field.Type) {
				t.Errorf("%s.%s is %s, %s.%s is %s", c.record, field.Name, got.Type, c.options, field.Name, field.Type)
			}
		}
	}
}

// Measured on TeamSpeak 3.13.8 and 6.0.0-beta13.1, channellist -secondsempty and
// channelinfo. An occupied channel, and the default channel, report -1.
func TestParseChannel_SecondsEmptyIsADurationOnlyForAnEmptyChannel(t *testing.T) {
	for _, tc := range []struct {
		want *time.Duration
		raw  string
	}{
		{new(3 * time.Second), "3"}, {new(time.Duration(0)), "0"}, {nil, "-1"}, {nil, ""},
	} {
		got := parseChannel(map[string]string{"cid": "5", "seconds_empty": tc.raw})
		if !reflect.DeepEqual(got.EmptyFor, tc.want) {
			t.Errorf("seconds_empty=%q: EmptyFor = %v, want %v", tc.raw, got.EmptyFor, tc.want)
		}
	}
}

// Measured on TeamSpeak 6.0.0-beta13.1 channelinfo; TeamSpeak 3 sends the path
// and no quota.
func TestParseChannel_ReadsTheStorageQuotaAndFilePath(t *testing.T) {
	got := parseChannel(map[string]string{
		"cid": "6", "channel_filepath": "files/virtualserver_1/channel_6", "channel_storage_quota": "4294967295",
	})
	if got.FilePath != "files/virtualserver_1/channel_6" || got.StorageQuota == nil || *got.StorageQuota != 4294967295 {
		t.Errorf("FilePath = %q, StorageQuota = %v", got.FilePath, got.StorageQuota)
	}
	bare := parseChannel(map[string]string{"cid": "6", "channel_filepath": "files/virtualserver_1/channel_6"})
	if bare.StorageQuota != nil {
		t.Errorf("StorageQuota = %v with no quota sent, want nil", bare.StorageQuota)
	}
}

// Measured on TeamSpeak 3.13.8 and 6.0.0-beta13.1, clientdbinfo and clientdblist.
func TestParseDatabaseEntry_ReadsTheInfoAndListFields(t *testing.T) {
	info := parseDatabaseEntry(map[string]string{
		"client_database_id": "12", "client_nickname": "ProbeA", "client_flag_avatar": "5f4dcc3b",
		"client_total_bytes_uploaded": "10", "client_total_bytes_downloaded": "20",
		"client_month_bytes_uploaded": "3", "client_month_bytes_downloaded": "0",
	})
	if info.AvatarHash != "5f4dcc3b" || *info.TotalBytesUploaded != 10 || *info.TotalBytesDownloaded != 20 ||
		*info.MonthBytesUploaded != 3 || *info.MonthBytesDownloaded != 0 {
		t.Errorf("clientdbinfo row = %+v", info)
	}
	listed := parseDatabaseEntry(map[string]string{"cldbid": "2", "client_login_name": "bot", "client_nickname": "Q"})
	if listed.LoginName != "bot" || listed.AvatarHash != "" || listed.TotalBytesUploaded != nil ||
		listed.MonthBytesDownloaded != nil {
		t.Errorf("clientdblist row = %+v, want a login name and no byte counts", listed)
	}
}

// Measured on TeamSpeak 3.13.8 and 6.0.0-beta13.1.
func TestClientLookups_ReadTheUIDNicknameAndMyTSID(t *testing.T) {
	s := &script{replies: []reply{
		{rows: []map[string]string{{"cldbid": "12", "cluid": "Xuf5umNYOFZET4cIpdhfqE1qbpA=", "name": "ProbeA"}}},
		{rows: []map[string]string{{
			"clid": "34", "cluid": "Xuf5umNYOFZET4cIpdhfqE1qbpA=", "mytsid": "", "nickname": "ProbeA",
		}}},
		{rows: []map[string]string{{"clid": "34", "cluid": "u=", "mytsid": "AAAA", "nickname": "N"}}},
	}}
	c := NewCommands(s)
	name, err := c.GetClientNameByDBID(t.Context(), 12)
	if err != nil || name.UID != "Xuf5umNYOFZET4cIpdhfqE1qbpA=" || name.Name != "ProbeA" || name.DatabaseID != 12 {
		t.Errorf("GetClientNameByDBID = %+v, %v", name, err)
	}
	info, err := c.GetClientUIDInfoByID(t.Context(), 34)
	want := ClientUIDInfo{ClientID: 34, UID: "Xuf5umNYOFZET4cIpdhfqE1qbpA=", Nickname: "ProbeA"}
	if err != nil || info != want {
		t.Errorf("GetClientUIDInfoByID = %+v, %v, want %+v", info, err, want)
	}
	uid, err := c.GetClientUIDByID(t.Context(), 34)
	if err != nil || uid != "u=" {
		t.Errorf("GetClientUIDByID = %q, %v", uid, err)
	}
}

// Measured: TeamSpeak 6.0.0-beta13.1 sends the uuid and the guest flags,
// TeamSpeak 3.13.8 none of them.
func TestWhoAmIAndServerList_ReadTheTS6Fields(t *testing.T) {
	s := &script{replies: []reply{
		{rows: []map[string]string{{
			"client_id": "11", "client_origin_server_id": "3", "virtualserver_id": "1",
			"virtualserver_uuid": "070df962-20f1-5989-8102-a463e0a55a33",
		}}},
		{rows: []map[string]string{{
			"virtualserver_id": "1", "virtualserver_uuid": "070df962-20f1-5989-8102-a463e0a55a33",
			"guest_can_create_channels": "1", "guest_can_create_homebase": "0", "virtualserver_weblist_enabled": "0",
		}, {"virtualserver_id": "2"}}},
	}}
	c := NewCommands(s)
	who, err := c.WhoAmI(t.Context())
	if err != nil || who.ServerUUID != "070df962-20f1-5989-8102-a463e0a55a33" || who.OriginServerID != 3 {
		t.Errorf("WhoAmI = %+v, %v", who, err)
	}
	servers, err := c.ListServers(t.Context(), ServerListOptions{})
	if err != nil || len(servers) != 2 {
		t.Fatalf("ListServers = %v, %v", servers, err)
	}
	ts6, ts3 := servers[0], servers[1]
	if ts6.UUID == "" || ts6.GuestCanCreateChannels == nil || !*ts6.GuestCanCreateChannels ||
		ts6.GuestCanCreateHomebase == nil || *ts6.GuestCanCreateHomebase ||
		ts6.WeblistEnabled == nil || *ts6.WeblistEnabled {
		t.Errorf("TS6 row = %+v", ts6)
	}
	if ts3.UUID != "" || ts3.GuestCanCreateChannels != nil || ts3.GuestCanCreateHomebase != nil ||
		ts3.WeblistEnabled != nil {
		t.Errorf("a row with none of them = %+v, want them unset", ts3)
	}
}

// The target channel's password is a secret, as the password is.
func TestTempPassword_TargetChannelPasswordIsReadAndRedacted(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"desc": "d", "end": "1792338931", "nickname": "serveradmin1", "pw_clear": "probepw", "start": "1792335331",
		"tcid": "6", "tcpw": "chanpw", "uid": "serveradmin",
	}}}}}
	got, err := NewCommands(s).ListTempPasswords(t.Context())
	if err != nil || len(got) != 1 || got[0].TargetChannelPassword != "chanpw" {
		t.Fatalf("ListTempPasswords = %+v, %v", got, err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, got[0]); strings.Contains(out, "chanpw") || strings.Contains(out, "probepw") {
			t.Errorf("%s leaks: %s", verb, out)
		}
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("value", "v", got[0])
	if strings.Contains(logged.String(), "chanpw") {
		t.Errorf("slog leaks: %s", logged.String())
	}
}
