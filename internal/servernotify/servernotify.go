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
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		v = 0
	}
	n := int32(max(math.MinInt32, min(math.MaxInt32, v)))

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
