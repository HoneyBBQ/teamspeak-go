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
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
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
	}
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
