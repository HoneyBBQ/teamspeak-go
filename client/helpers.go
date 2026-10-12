package client

import (
	"math"
	"strconv"
	"strings"

	"github.com/honeybbq/teamspeak-go/commands"
)

func parseUint64Value(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

func parseUint16Value(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(v), nil
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

// splitCommandRows expands a pipe-separated multi-row TS3 command line into
// individual rows.
//
// A named line (notifyclientleftview a=1|a=2) keeps its name on every row; a
// nameless response (cldbid=1|cldbid=2) stays nameless. Whether the first token
// is a name is the parser's own rule — deciding it here by position is how a
// nameless batch with no space in it went through unsplit, and a one-field
// response came back as a single row.
func splitCommandRows(line string) []string {
	name, rest := splitName(line)
	if !strings.Contains(rest, "|") {
		return []string{line}
	}
	parts := strings.Split(rest, "|")
	rows := make([]string, 0, len(parts))
	// TeamSpeak compresses pipe-separated rows by omitting fields whose value is
	// unchanged from the previous row: in a notifycliententerview batch, ctid is
	// often present only on the first row. Carry those fields forward. Tokens stay
	// escaped so the command parser still performs its single unescape pass.
	var previous []string
	for _, part := range parts {
		if part == "" {
			continue
		}
		tokens := strings.Fields(part)
		present := make(map[string]struct{}, len(tokens))
		for _, token := range tokens {
			present[fieldName(token)] = struct{}{}
		}
		resolved := make([]string, 0, len(previous)+len(tokens))
		for _, token := range previous {
			if _, ok := present[fieldName(token)]; !ok {
				resolved = append(resolved, token)
			}
		}
		resolved = append(resolved, tokens...)
		row := strings.Join(resolved, " ")
		if name != "" {
			row = name + " " + row
		}
		rows = append(rows, row)
		previous = resolved
	}
	if len(rows) == 0 {
		return []string{line}
	}

	return rows
}

// splitName separates a line's command name, if it has one, from its rows,
// returning the name ("" for a nameless response) and the rest.
func splitName(line string) (string, string) {
	head, tail, hasSpace := strings.Cut(line, " ")
	if !commands.IsCommandName(head) {
		return "", line
	}
	if !hasSpace {
		return head, ""
	}

	return head, tail
}

// fieldName returns the key of a "key=value" token, or the whole token for a
// bare flag such as "-away".
func fieldName(token string) string {
	if key, _, ok := strings.Cut(token, "="); ok && key != "" {
		return key
	}

	return token
}

// parseUint64List reads a comma-separated list of ids, as client_servergroups
// arrives.
func parseUint64List(raw string) []uint64 {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]uint64, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err == nil {
			out = append(out, value)
		}
	}

	return out
}
