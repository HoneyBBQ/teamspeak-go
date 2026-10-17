// Package servernotify reads the notifications a server sends into the event
// types the root package defines.
//
// Both clients receive the same notifications — the voice protocol and
// ServerQuery carry the same names and fields — so the reading is here, once,
// rather than in each of them. What is left to a client is the state a
// notification changes: which clients it knows, which one it is itself, and
// whether a leave is its own goodbye. That state is what differs between the
// two, so it stays with them.
//
// The package imports the root package, which is why it is not part of wire:
// wire builds no teamspeak types, and cannot import them.
package servernotify

import (
	"math"
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// ClientEnter reads notifycliententerview into the client it describes.
//
// The server leaves out of a row whatever the row before it had, so the row
// must already be resolved (wire.SplitRows does that); every field here is one
// a cliententerview row can carry.
func ClientEnter(params map[string]string) teamspeak.ClientEntry {
	clientType, _ := ParseInt(params["client_type"])
	channelGroup, _ := ParseUint64(params["client_channel_group_id"])

	return teamspeak.ClientEntry{
		ID:             ParseClientID(params["clid"]),
		Nickname:       params["client_nickname"],
		UID:            teamspeak.UID(params["client_unique_identifier"]),
		ChannelID:      ParseChannelID(params["ctid"]),
		ChannelGroupID: teamspeak.ChannelGroupID(channelGroup),
		Type:           teamspeak.ClientType(clientType),
		ServerGroups:   ParseIDList[teamspeak.ServerGroupID](params["client_servergroups"]),
		IsAway:         params["client_away"] == "1",
		IsRecording:    params["client_is_recording"] == "1",
		IsTalker:       params["client_is_talker"] == "1",

		DatabaseID:                     teamspeak.ClientDBID(uintOrZero(params["client_database_id"])),
		AwayMessage:                    params["client_away_message"],
		IsInputMuted:                   optBool(params, "client_input_muted"),
		IsOutputMuted:                  optBool(params, "client_output_muted"),
		IsOutputOnlyMuted:              optBool(params, "client_outputonly_muted"),
		HasInputHardware:               optBool(params, "client_input_hardware"),
		HasOutputHardware:              optBool(params, "client_output_hardware"),
		IsChannelCommander:             optBool(params, "client_is_channel_commander"),
		IsPrioritySpeaker:              optBool(params, "client_is_priority_speaker"),
		TalkPower:                      optInt32(params, "client_talk_power"),
		IsRequestingTalk:               optBool(params, "client_talk_request"),
		TalkRequestMessage:             params["client_talk_request_msg"],
		Description:                    params["client_description"],
		MetaData:                       params["client_meta_data"],
		Avatar:                         params["client_flag_avatar"],
		IconID:                         wire.ParseIconID[teamspeak.IconID](params["client_icon_id"]),
		NicknamePhonetic:               params["client_nickname_phonetic"],
		UnreadMessages:                 optInt32(params, "client_unread_messages"),
		NeededServerQueryViewPower:     optInt32(params, "client_needed_serverquery_view_power"),
		ChannelGroupInheritedChannelID: teamspeak.ChannelID(uintOrZero(params["client_channel_group_inherited_channel_id"])),
		Country:                        params["client_country"],
		Version:                        params["client_version"],
		Platform:                       params["client_platform"],
		IP:                             params["connection_client_ip"],
		Badges:                         params["client_badges"],
		SignedBadges:                   params["client_signed_badges"],
		MyTeamSpeakID:                  params["client_myteamspeak_id"],
		MyTeamSpeakAvatar:              params["client_myteamspeak_avatar"],
		Integrations:                   params["client_integrations"],
		UserTag:                        params["client_user_tag"],
		IsStreaming:                    optBool(params, "client_is_streaming"),
	}
}

// uintOrZero reads a decimal uint64, 0 for anything unreadable.
func uintOrZero(s string) uint64 {
	v, _ := ParseUint64(s)

	return v
}

// optBool reads a flag a notification may leave out: nil when the key is
// absent or empty, otherwise a pointer to its value, false included.
func optBool(params map[string]string, key string) *bool {
	raw := params[key]
	if raw == "" {
		return nil
	}
	v := uintOrZero(raw) != 0

	return &v
}

// optInt32 reads a signed 32-bit number a notification may leave out: nil when
// the key is absent or empty, clamped rather than wrapped when too large.
func optInt32(params map[string]string, key string) *int32 {
	raw := params[key]
	if raw == "" {
		return nil
	}
	n := asInt32(raw)

	return &n
}

// ClientLeave reads notifyclientleftview.
func ClientLeave(params map[string]string) teamspeak.ClientLeaveEvent {
	reasonID, _ := ParseInt(params["reasonid"])

	return teamspeak.ClientLeaveEvent{
		ClientID:      ParseClientID(params["clid"]),
		Reason:        teamspeak.Reason(reasonID),
		ReasonMessage: params["reasonmsg"],
		InvokerID:     ParseClientID(params["invokerid"]),
		InvokerName:   params["invokername"],
		InvokerUID:    teamspeak.UID(params["invokeruid"]),
	}
}

// ClientMoved reads notifyclientmoved.
func ClientMoved(params map[string]string) teamspeak.ClientMovedEvent {
	reasonID, _ := ParseInt(params["reasonid"])

	return teamspeak.ClientMovedEvent{
		ClientID:        ParseClientID(params["clid"]),
		TargetChannelID: ParseChannelID(params["ctid"]),
		Reason:          teamspeak.Reason(reasonID),
		InvokerID:       ParseClientID(params["invokerid"]),
		InvokerName:     params["invokername"],
		InvokerUID:      teamspeak.UID(params["invokeruid"]),
		ReasonMessage:   params["reasonmsg"],
	}
}

// Kicked reads the kick a notification carries, given the reason it reports: a
// channel kick arrives as a move (notifyclientmoved with reasonid=4) and a
// server kick as a leave (notifyclientleftview).
func Kicked(reason teamspeak.Reason, params map[string]string) teamspeak.KickedEvent {
	return teamspeak.KickedEvent{
		ReasonMessage: params["reasonmsg"],
		InvokerName:   params["invokername"],
		InvokerUID:    teamspeak.UID(params["invokeruid"]),
		Reason:        reason,
		InvokerID:     ParseClientID(params["invokerid"]),
	}
}

// TextMessage reads notifytextmessage.
//
// InvokerGroups is left nil: a notification does not carry the sender's
// groups, so a client fills them from the client it knows.
func TextMessage(params map[string]string) teamspeak.TextMessageEvent {
	targetMode, _ := ParseInt(params["targetmode"])

	return teamspeak.TextMessageEvent{
		TargetMode:  teamspeak.TextMessageTarget(targetMode),
		TargetID:    ParseClientID(params["target"]),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
		Message:     params["msg"],
	}
}

// ParseClientID reads a clid, invokerid or the like; 0, which names no client,
// for anything unreadable.
func ParseClientID(s string) teamspeak.ClientID {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}

	return teamspeak.ClientID(v)
}

// ParseChannelID reads a cid or ctid; 0, which names no channel, for anything
// unreadable.
func ParseChannelID(s string) teamspeak.ChannelID {
	v, err := ParseUint64(s)
	if err != nil {
		return 0
	}

	return teamspeak.ChannelID(v)
}

// ParseInt reads a plain decimal integer; 0 and the error for anything else.
// An int too large for the platform reads as its maximum rather than wrapping.
func ParseInt(s string) (int, error) {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}

	return int(v), nil
}

// ParseUint64 reads a plain decimal uint64.
func ParseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// ParseIDList reads a comma-separated list of ids, as client_servergroups
// arrives. An id that does not parse is left out rather than ending the list.
func ParseIDList[T ~uint64](raw string) []T {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]T, 0, len(parts))
	for _, part := range parts {
		value, err := ParseUint64(strings.TrimSpace(part))
		if err == nil {
			out = append(out, T(value))
		}
	}

	return out
}

// ClientUpdated reads notifyclientupdated.
func ClientUpdated(params map[string]string) teamspeak.ClientUpdatedEvent {
	return teamspeak.ClientUpdatedEvent{
		ClientID:    ParseClientID(params["clid"]),
		Changes:     ClientChanges(params),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}
}

// ClientChanges reads the client properties a notification names. A property
// is set exactly when its key is in params, an empty value included, so a
// cleared away message reads as a pointer to "" and not as no change. The keys
// are those ClientEnter reads; ChannelID, Created, LastConnected and IdleTime
// are not read, because no notification of an update carries them.
func ClientChanges(params map[string]string) teamspeak.ClientChanges {
	var groups *[]teamspeak.ServerGroupID
	if raw, ok := params["client_servergroups"]; ok {
		list := ParseIDList[teamspeak.ServerGroupID](raw)
		if list == nil {
			list = []teamspeak.ServerGroupID{}
		}
		groups = &list
	}

	return teamspeak.ClientChanges{
		Nickname:       key(params, "client_nickname", identity[string]),
		UID:            key(params, "client_unique_identifier", identity[teamspeak.UID]),
		ServerGroups:   groups,
		ChannelGroupID: key(params, "client_channel_group_id", asID[teamspeak.ChannelGroupID]),
		Type:           key(params, "client_type", asType),
		IsAway:         key(params, "client_away", asBool),
		IsRecording:    key(params, "client_is_recording", asBool),
		IsTalker:       key(params, "client_is_talker", asBool),

		DatabaseID:                     key(params, "client_database_id", asID[teamspeak.ClientDBID]),
		AwayMessage:                    key(params, "client_away_message", identity[string]),
		IsInputMuted:                   key(params, "client_input_muted", asBool),
		IsOutputMuted:                  key(params, "client_output_muted", asBool),
		IsOutputOnlyMuted:              key(params, "client_outputonly_muted", asBool),
		HasInputHardware:               key(params, "client_input_hardware", asBool),
		HasOutputHardware:              key(params, "client_output_hardware", asBool),
		IsChannelCommander:             key(params, "client_is_channel_commander", asBool),
		IsPrioritySpeaker:              key(params, "client_is_priority_speaker", asBool),
		TalkPower:                      key(params, "client_talk_power", asInt32),
		IsRequestingTalk:               key(params, "client_talk_request", asBool),
		TalkRequestMessage:             key(params, "client_talk_request_msg", identity[string]),
		Description:                    key(params, "client_description", identity[string]),
		MetaData:                       key(params, "client_meta_data", identity[string]),
		Avatar:                         key(params, "client_flag_avatar", identity[string]),
		IconID:                         key(params, "client_icon_id", wire.ParseIconID[teamspeak.IconID]),
		NicknamePhonetic:               key(params, "client_nickname_phonetic", identity[string]),
		UnreadMessages:                 key(params, "client_unread_messages", asInt32),
		NeededServerQueryViewPower:     key(params, "client_needed_serverquery_view_power", asInt32),
		ChannelGroupInheritedChannelID: key(params, "client_channel_group_inherited_channel_id", asID[teamspeak.ChannelID]),
		Country:                        key(params, "client_country", identity[string]),
		Version:                        key(params, "client_version", identity[string]),
		Platform:                       key(params, "client_platform", identity[string]),
		IP:                             key(params, "connection_client_ip", identity[string]),
		Badges:                         key(params, "client_badges", identity[string]),
		SignedBadges:                   key(params, "client_signed_badges", identity[string]),
		MyTeamSpeakID:                  key(params, "client_myteamspeak_id", identity[string]),
		MyTeamSpeakAvatar:              key(params, "client_myteamspeak_avatar", identity[string]),
		Integrations:                   key(params, "client_integrations", identity[string]),
		UserTag:                        key(params, "client_user_tag", identity[string]),
		IsStreaming:                    key(params, "client_is_streaming", asBool),
	}
}

// key reads the value of name with read, or returns nil when params does not
// have the key at all.
func key[T any](params map[string]string, name string, read func(string) T) *T {
	raw, ok := params[name]
	if !ok {
		return nil
	}
	v := read(raw)

	return &v
}

func identity[T ~string](s string) T { return T(s) }

func asID[T ~uint64](s string) T { return T(uintOrZero(s)) }

func asBool(s string) bool { return uintOrZero(s) != 0 }

func asType(s string) teamspeak.ClientType {
	v, _ := ParseInt(s)

	return teamspeak.ClientType(v)
}

// asInt32 reads a signed 32-bit number: clamped rather than wrapped when out of
// range, and 0 for anything that is not a number.
func asInt32(s string) int32 {
	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	if value < math.MinInt32 {
		return math.MinInt32
	}

	return int32(value)
}

// ClientServerGroup reads notifyservergroupclientadded and
// notifyservergroupclientdeleted, which carry the same fields.
func ClientServerGroup(params map[string]string) teamspeak.ClientServerGroupChange {
	return teamspeak.ClientServerGroupChange{
		GroupID:     teamspeak.ServerGroupID(uintOrZero(params["sgid"])),
		ClientID:    ParseClientID(params["clid"]),
		Nickname:    params["name"],
		UID:         teamspeak.UID(params["cluid"]),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}
}

// ClientChannelGroupChanged reads notifyclientchannelgroupchanged.
func ClientChannelGroupChanged(params map[string]string) teamspeak.ClientChannelGroupChangedEvent {
	return teamspeak.ClientChannelGroupChangedEvent{
		ClientID:                       ParseClientID(params["clid"]),
		ChannelID:                      ParseChannelID(params["cid"]),
		ChannelGroupID:                 teamspeak.ChannelGroupID(uintOrZero(params["cgid"])),
		ChannelGroupInheritedChannelID: ParseChannelID(params["cgi"]),
		InvokerID:                      ParseClientID(params["invokerid"]),
		InvokerName:                    params["invokername"],
		InvokerUID:                     teamspeak.UID(params["invokeruid"]),
	}
}
