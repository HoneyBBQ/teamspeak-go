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
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// ClientEnter reads notifycliententerview into the client it describes. A
// clientlist row names the same fields, so it reads here too.
//
// The server leaves out of a row whatever the row before it had, so the row
// must already be resolved (wire.SplitRows does that); every field here is one
// a cliententerview row can carry.
func ClientEnter(params map[string]string) teamspeak.ClientEntry {
	clientType, _ := ParseInt(params["client_type"])

	return teamspeak.ClientEntry{
		ID:           ParseClientID(params["clid"]),
		Nickname:     params["client_nickname"],
		ChannelID:    enterChannel(params),
		Type:         teamspeak.ClientType(clientType),
		DatabaseID:   teamspeak.ClientDBID(uintOrZero(params["client_database_id"])),
		ServerGroups: optIDList[teamspeak.ServerGroupID](params, "client_servergroups"),

		UID:                            optStr[teamspeak.UID](params, "client_unique_identifier"),
		ChannelGroupID:                 optID[teamspeak.ChannelGroupID](params, "client_channel_group_id"),
		IsAway:                         optBool(params, "client_away"),
		IsRecording:                    optBool(params, "client_is_recording"),
		IsTalker:                       optBool(params, "client_is_talker"),
		AwayMessage:                    optStr[string](params, "client_away_message"),
		IsInputMuted:                   optBool(params, "client_input_muted"),
		IsOutputMuted:                  optBool(params, "client_output_muted"),
		IsOutputOnlyMuted:              optBool(params, "client_outputonly_muted"),
		HasInputHardware:               optBool(params, "client_input_hardware"),
		HasOutputHardware:              optBool(params, "client_output_hardware"),
		IsChannelCommander:             optBool(params, "client_is_channel_commander"),
		IsPrioritySpeaker:              optBool(params, "client_is_priority_speaker"),
		TalkPower:                      optInt32(params, "client_talk_power"),
		IsRequestingTalk:               optBool(params, "client_talk_request"),
		TalkRequestedAt:                asTime(params["client_talk_request"]),
		TalkRequestMessage:             optStr[string](params, "client_talk_request_msg"),
		Description:                    optStr[string](params, "client_description"),
		MetaData:                       optStr[string](params, "client_meta_data"),
		Avatar:                         optStr[string](params, "client_flag_avatar"),
		IconID:                         optIconID(params, "client_icon_id"),
		NicknamePhonetic:               optStr[string](params, "client_nickname_phonetic"),
		UnreadMessages:                 optInt32(params, "client_unread_messages"),
		NeededServerQueryViewPower:     optInt32(params, "client_needed_serverquery_view_power"),
		ChannelGroupInheritedChannelID: optID[teamspeak.ChannelID](params, "client_channel_group_inherited_channel_id"),
		Country:                        optStr[string](params, "client_country"),
		Version:                        optStr[string](params, "client_version"),
		Platform:                       optStr[string](params, "client_platform"),
		IP:                             optStr[string](params, "connection_client_ip"),
		Badges:                         optStr[string](params, "client_badges"),
		SignedBadges:                   optStr[string](params, "client_signed_badges"),
		MyTeamSpeakID:                  optStr[string](params, "client_myteamspeak_id"),
		MyTeamSpeakAvatar:              optStr[string](params, "client_myteamspeak_avatar"),
		Integrations:                   optStr[string](params, "client_integrations"),
		UserTag:                        optStr[string](params, "client_user_tag"),
		IsStreaming:                    optBool(params, "client_is_streaming"),
	}
}

// enterChannel reads the channel a client is in. An enter notification names it
// ctid, next to cfid for the channel it came from; a clientlist row names it
// cid. ctid wins when both are there, so an enter is never read by a key that
// is not its own.
func enterChannel(params map[string]string) teamspeak.ChannelID {
	if ctid, ok := params["ctid"]; ok {
		return ParseChannelID(ctid)
	}

	return ParseChannelID(params["cid"])
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

// optStr reads a string a notification may leave out: nil when the key is
// absent, otherwise a pointer to its value, "" included.
func optStr[T ~string](params map[string]string, key string) *T {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	v := T(raw)

	return &v
}

// optID reads an id a notification may leave out: nil when the key is absent
// or empty, otherwise a pointer to it, 0 included.
func optID[T ~uint64](params map[string]string, key string) *T {
	if params[key] == "" {
		return nil
	}
	v := T(uintOrZero(params[key]))

	return &v
}

// optIconID reads an icon id a notification may leave out: nil when the key is
// absent, and nil for icon 0, which is none.
func optIconID(params map[string]string, key string) *teamspeak.IconID {
	if icon := wire.ParseIconID[teamspeak.IconID](params[key]); icon != 0 {
		return &icon
	}

	return nil
}

// optIDList reads a list of ids a notification may leave out: nil when the key
// is absent, and an empty list, not nil, when it is empty.
func optIDList[T ~uint64](params map[string]string, key string) []T {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	list := ParseIDList[T](raw)
	if list == nil {
		list = []T{}
	}

	return list
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

		FromChannelID:   optChannelID(params, "cfid"),
		TargetChannelID: optChannelID(params, "ctid"),
	}
}

// optChannelID reads a channel id a notification may leave out: nil when the
// key is absent, otherwise a pointer to it, 0 included.
func optChannelID(params map[string]string, key string) *teamspeak.ChannelID {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	id := ParseChannelID(raw)

	return &id
}

// ClientMoved reads notifyclientmoved. FromChannelID is nil when the row has no
// cfid, as a TeamSpeak 3 move has none; the client, which knows where the
// client was, fills it in.
//
// A move of the client's own (reason 0) names no invoker on either server, and
// the invoker fields are empty then, whatever the caller knows.
func ClientMoved(params map[string]string) teamspeak.ClientMovedEvent {
	reasonID, _ := ParseInt(params["reasonid"])

	return teamspeak.ClientMovedEvent{
		ClientID:        ParseClientID(params["clid"]),
		TargetChannelID: ParseChannelID(params["ctid"]),
		FromChannelID:   optChannelID(params, "cfid"),
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
		TalkRequestedAt:                key(params, "client_talk_request", asTime),
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

// asTime reads a unix timestamp in whole seconds; 0, an empty value and
// anything that is not a positive number are the zero time, as the server sends
// 0 for "never".
func asTime(s string) time.Time {
	seconds, err := strconv.ParseInt(s, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}

	return time.Unix(seconds, 0)
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

// ChannelCreated reads notifychannelcreated. ok is false for a row that names no
// channel.
func ChannelCreated(params map[string]string) (teamspeak.ChannelCreatedEvent, bool) {
	evt := teamspeak.ChannelCreatedEvent{
		ChannelID:   ParseChannelID(params["cid"]),
		ParentID:    ParseChannelID(params["cpid"]),
		Changes:     ChannelChanges(params),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}

	return evt, evt.ChannelID != 0
}

// ChannelEdited reads notifychanneledited. ok is false for a row that names no
// channel, and for the answer to channelgetdescription: an edit with
// reasonid=9 (teamspeak.ReasonChannelUpdate) that names no invoker, which holds
// the description that was asked for and is no change. A real edit is told
// apart by having an invoker, not by whether a command is waiting, so one that
// arrives meanwhile is not swallowed.
func ChannelEdited(params map[string]string) (teamspeak.ChannelEditedEvent, bool) {
	reasonID, _ := ParseInt(params["reasonid"])
	reason := teamspeak.Reason(reasonID)
	_, hasInvoker := params["invokerid"]
	evt := teamspeak.ChannelEditedEvent{
		ChannelID:   ParseChannelID(params["cid"]),
		Reason:      reason,
		Changes:     ChannelChanges(params),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}
	if reason == teamspeak.ReasonChannelUpdate && !hasInvoker {
		return evt, false
	}

	return evt, evt.ChannelID != 0
}

// ChannelMoved reads notifychannelmoved.
func ChannelMoved(params map[string]string) (teamspeak.ChannelMovedEvent, bool) {
	reasonID, _ := ParseInt(params["reasonid"])
	evt := teamspeak.ChannelMovedEvent{
		ChannelID:   ParseChannelID(params["cid"]),
		ParentID:    ParseChannelID(params["cpid"]),
		Order:       ParseChannelID(params["order"]),
		Reason:      teamspeak.Reason(reasonID),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}

	return evt, evt.ChannelID != 0
}

// ChannelDeleted reads notifychanneldeleted.
func ChannelDeleted(params map[string]string) (teamspeak.ChannelDeletedEvent, bool) {
	evt := teamspeak.ChannelDeletedEvent{
		ChannelID:   ParseChannelID(params["cid"]),
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}

	return evt, evt.ChannelID != 0
}

// ServerEdited reads notifyserveredited: the virtualserver_ properties it
// names, raw. Changes is never nil.
func ServerEdited(params map[string]string) teamspeak.ServerEditedEvent {
	changes := teamspeak.Properties{}
	for name, value := range params {
		if strings.HasPrefix(name, "virtualserver_") {
			changes[name] = value
		}
	}

	return teamspeak.ServerEditedEvent{
		Changes:     changes,
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}
}

// PluginCommand reads notifyplugincmd.
func PluginCommand(params map[string]string) teamspeak.PluginCommandEvent {
	return teamspeak.PluginCommandEvent{
		Name:        params["name"],
		Data:        params["data"],
		InvokerID:   ParseClientID(params["invokerid"]),
		InvokerName: params["invokername"],
		InvokerUID:  teamspeak.UID(params["invokeruid"]),
	}
}

// ClientEnterOrigin reads the parts of notifycliententerview that describe the
// entry and not the client: the channel the client came from and why it came
// into view. Each is nil when the row has none.
func ClientEnterOrigin(params map[string]string) (*teamspeak.ChannelID, *teamspeak.Reason) {
	var reason *teamspeak.Reason
	if raw, ok := params["reasonid"]; ok {
		reasonID, _ := ParseInt(raw)
		r := teamspeak.Reason(reasonID)
		reason = &r
	}

	return optChannelID(params, "cfid"), reason
}

// ClientChatClosed reads notifyclientchatclosed. ok is false for a row that
// names no client.
func ClientChatClosed(params map[string]string) (teamspeak.ClientChatClosedEvent, bool) {
	evt := teamspeak.ClientChatClosedEvent{
		ClientID: ParseClientID(params["clid"]),
		UID:      teamspeak.UID(params["cluid"]),
	}

	return evt, evt.ClientID != 0
}

// ClientChatComposing reads notifyclientchatcomposing. ok is false for a row
// that names no client.
func ClientChatComposing(params map[string]string) (teamspeak.ClientChatComposingEvent, bool) {
	evt := teamspeak.ClientChatComposingEvent{
		ClientID: ParseClientID(params["clid"]),
		UID:      teamspeak.UID(params["cluid"]),
	}

	return evt, evt.ClientID != 0
}

// ChannelChanges reads the channel properties a notification names. A property
// is set exactly when its key is in params, as ClientChanges does. The parent
// is read from pid or cpid, whichever the row has. The channel's own id (cid)
// is not a property.
func ChannelChanges(params map[string]string) teamspeak.ChannelChanges {
	parent := key(params, "pid", asID[teamspeak.ChannelID])
	if parent == nil {
		parent = key(params, "cpid", asID[teamspeak.ChannelID])
	}

	return teamspeak.ChannelChanges{
		UID:                  key(params, "channel_unique_identifier", identity[teamspeak.ChannelUID]),
		Name:                 key(params, "channel_name", identity[string]),
		Topic:                key(params, "channel_topic", identity[string]),
		Description:          key(params, "channel_description", identity[string]),
		ParentID:             parent,
		Order:                key(params, "channel_order", asID[teamspeak.ChannelID]),
		IconID:               key(params, "channel_icon_id", wire.ParseIconID[teamspeak.IconID]),
		Codec:                key(params, "channel_codec", asCodec),
		CodecQuality:         key(params, "channel_codec_quality", asInt32),
		MaxClients:           key(params, "channel_maxclients", asInt32),
		MaxFamilyClients:     key(params, "channel_maxfamilyclients", asInt32),
		TotalClients:         key(params, "total_clients", asInt32),
		TotalFamilyClients:   key(params, "total_clients_family", asInt32),
		NeededSubscribePower: key(params, "channel_needed_subscribe_power", asInt32),
		NeededTalkPower:      key(params, "channel_needed_talk_power", asInt32),
		IsDefault:            key(params, "channel_flag_default", asBool),
		IsPermanent:          key(params, "channel_flag_permanent", asBool),
		IsSemiPermanent:      key(params, "channel_flag_semi_permanent", asBool),
		HasPassword:          key(params, "channel_flag_password", asBool),

		CodecLatencyFactor:          key(params, "channel_codec_latency_factor", asInt32),
		IsUnencrypted:               key(params, "channel_codec_is_unencrypted", asBool),
		IsMaxClientsUnlimited:       key(params, "channel_flag_maxclients_unlimited", asBool),
		IsMaxFamilyClientsUnlimited: key(params, "channel_flag_maxfamilyclients_unlimited", asBool),
		IsMaxFamilyClientsInherited: key(params, "channel_flag_maxfamilyclients_inherited", asBool),
		DeleteDelay:                 key(params, "channel_delete_delay", asSeconds),
		NamePhonetic:                key(params, "channel_name_phonetic", identity[string]),
		IsForcedSilence:             key(params, "channel_forced_silence", asBool),
		BannerURL:                   key(params, "channel_banner_gfx_url", identity[string]),
		BannerMode:                  key(params, "channel_banner_mode", asInt32),
		StorageQuota:                key(params, "channel_storage_quota", uintOrZero),
		FilePath:                    key(params, "channel_filepath", identity[string]),
	}
}

// asCodec reads a codec, clamped to one byte rather than wrapped.
func asCodec(s string) teamspeak.Codec {
	v := uintOrZero(s)
	if v > math.MaxUint8 {
		return teamspeak.Codec(math.MaxUint8)
	}

	return teamspeak.Codec(v)
}

// asSeconds reads a count of seconds as a duration, clamped rather than
// overflowing.
func asSeconds(s string) time.Duration {
	count := uintOrZero(s)
	if count > math.MaxInt64/uint64(time.Second) {
		return time.Duration(math.MaxInt64)
	}

	return time.Duration(count) * time.Second
}

// CloneChannelChanges returns a copy of c that shares no memory with it, so a
// handler editing what it was given cannot change what the next one sees. A
// field added to ChannelChanges must be added here, and the tests fail until it
// is.
//
//nolint:funlen // one line per field
func CloneChannelChanges(c teamspeak.ChannelChanges) teamspeak.ChannelChanges {
	c.UID = clonePtr(c.UID)
	c.Name = clonePtr(c.Name)
	c.Topic = clonePtr(c.Topic)
	c.Description = clonePtr(c.Description)
	c.ParentID = clonePtr(c.ParentID)
	c.Order = clonePtr(c.Order)
	c.IconID = clonePtr(c.IconID)
	c.Codec = clonePtr(c.Codec)
	c.CodecQuality = clonePtr(c.CodecQuality)
	c.MaxClients = clonePtr(c.MaxClients)
	c.MaxFamilyClients = clonePtr(c.MaxFamilyClients)
	c.TotalClients = clonePtr(c.TotalClients)
	c.TotalFamilyClients = clonePtr(c.TotalFamilyClients)
	c.NeededSubscribePower = clonePtr(c.NeededSubscribePower)
	c.NeededTalkPower = clonePtr(c.NeededTalkPower)
	c.IsDefault = clonePtr(c.IsDefault)
	c.IsPermanent = clonePtr(c.IsPermanent)
	c.IsSemiPermanent = clonePtr(c.IsSemiPermanent)
	c.HasPassword = clonePtr(c.HasPassword)
	c.CodecLatencyFactor = clonePtr(c.CodecLatencyFactor)
	c.IsUnencrypted = clonePtr(c.IsUnencrypted)
	c.IsMaxClientsUnlimited = clonePtr(c.IsMaxClientsUnlimited)
	c.IsMaxFamilyClientsUnlimited = clonePtr(c.IsMaxFamilyClientsUnlimited)
	c.IsMaxFamilyClientsInherited = clonePtr(c.IsMaxFamilyClientsInherited)
	c.DeleteDelay = clonePtr(c.DeleteDelay)
	c.NamePhonetic = clonePtr(c.NamePhonetic)
	c.IsForcedSilence = clonePtr(c.IsForcedSilence)
	c.BannerURL = clonePtr(c.BannerURL)
	c.BannerMode = clonePtr(c.BannerMode)
	c.EmptyFor = clonePtr(c.EmptyFor)
	c.StorageQuota = clonePtr(c.StorageQuota)
	c.FilePath = clonePtr(c.FilePath)

	return c
}

// CloneClientMoved returns a copy of e that shares no memory with it, so a
// handler editing what it was given cannot change what the next one sees.
func CloneClientMoved(e teamspeak.ClientMovedEvent) teamspeak.ClientMovedEvent {
	e.FromChannelID = clonePtr(e.FromChannelID)

	return e
}

// CloneClientLeave returns a copy of e as CloneClientMoved does. The record a
// voice client holds in Previous is its own to copy.
func CloneClientLeave(e teamspeak.ClientLeaveEvent) teamspeak.ClientLeaveEvent {
	e.FromChannelID = clonePtr(e.FromChannelID)
	e.TargetChannelID = clonePtr(e.TargetChannelID)

	return e
}

// clonePtr returns a pointer to a copy of what p points at, or nil.
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p

	return &v
}
