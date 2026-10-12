package client

import (
	"math"
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

func parseUint64Value(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// parseClientID reads a clid, invokerid or the like; 0, which names no client,
// for anything unreadable.
func parseClientID(s string) teamspeak.ClientID {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}

	return teamspeak.ClientID(v)
}

// parseChannelID reads a cid or ctid; 0, which names no channel, for anything
// unreadable.
func parseChannelID(s string) teamspeak.ChannelID {
	v, err := parseUint64Value(s)
	if err != nil {
		return 0
	}

	return teamspeak.ChannelID(v)
}

func parseIntValue(s string) (int, error) {
	v, err := strconv.ParseInt(s, 10, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	if strconv.IntSize == 32 && v > math.MaxInt32 {
		return math.MaxInt32, nil
	}

	return int(v), nil
}

// isAutoNicknameMatch reports whether actual equals expected or expected followed by only
// digits — the pattern TeamSpeak uses when a requested nickname is already taken.
func isAutoNicknameMatch(expected, actual string) bool {
	if actual == expected {
		return true
	}
	if !strings.HasPrefix(actual, expected) {
		return false
	}
	suffix := strings.TrimPrefix(actual, expected)
	for i := range len(suffix) {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}

	return true
}

// parseIDList reads a comma-separated list of ids, as client_servergroups
// arrives.
func parseIDList[T ~uint64](raw string) []T {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]T, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err == nil {
			out = append(out, T(value))
		}
	}

	return out
}
