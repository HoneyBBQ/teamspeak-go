// Package wire reads the parts of the command line format that every
// TeamSpeak connection shares: the voice protocol and ServerQuery send the
// same rows, error ids and icon ids, so they are read in one place.
//
// It parses and builds command lines too. It depends on nothing but the
// errcode package, so the root package can use it as well as the transports.
package wire

import (
	"strconv"
	"strings"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// SplitRows expands a pipe-separated multi-row command line into individual
// rows.
//
// A named line (notifyclientleftview a=1|a=2) keeps its name on every row; a
// nameless response (cldbid=1|cldbid=2) stays nameless. Whether the first token
// is a name is the parser's own rule — deciding it here by position is how a
// nameless batch with no space in it went through unsplit, and a one-field
// response came back as a single row.
func SplitRows(line string) []string {
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
	if !IsCommandName(head) {
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

// ParseCode reads an error id. One that is missing or unreadable is reported
// as errcode.Undefined: an error line that does not say what went wrong has
// still not said that nothing did.
func ParseCode(raw string) errcode.Code {
	code, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return errcode.Undefined
	}

	return errcode.Code(code)
}

// ParseIconID reads an icon id, returning 0, which names no icon, for anything
// unreadable.
//
// An icon id is the CRC32 of the icon file, and the server sends it either as
// that unsigned number or reinterpreted as a signed 32-bit one — -2004712318
// for 2290254978. Reading only the unsigned form turned every icon whose CRC
// has the top bit set into "no icon".
//
// Generic so that this package needs no IconID type of its own, and the root
// package, which defines that type, can use it.
func ParseIconID[T ~uint32](raw string) T {
	unsignedID, err := strconv.ParseUint(raw, 10, 32)
	if err == nil {
		return T(unsignedID)
	}
	signedID, err := strconv.ParseInt(raw, 10, 32)
	if err == nil {
		return T(uint32(int32(signedID))) //nolint:gosec // the reinterpretation is the point
	}

	return 0
}
