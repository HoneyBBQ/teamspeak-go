package teamspeak

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/honeybbq/teamspeak-go/commands"
)

// defaultCommandTimeout is how long a command waits for its return_code before
// giving up. Commands that can legitimately take longer pass their own.
const defaultCommandTimeout = 10 * time.Second

// param is one wire parameter. A nil Value means "do not send this parameter
// at all", which is not the same as sending an empty string: clearing a
// channel password takes `channel_password=`, while leaving it alone takes no
// parameter. Callers express the difference with a pointer.
type param struct {
	Value *string
	Key   string
}

// Str encodes a string parameter.
func Str(key, value string) param {
	return param{Key: key, Value: &value}
}

// Uint encodes an unsigned integer parameter.
func Uint(key string, value uint64) param {
	encoded := strconv.FormatUint(value, 10)

	return param{Key: key, Value: &encoded}
}

// Int encodes a signed integer parameter, which the protocol needs because
// several fields legitimately carry -1 (channel_maxclients, for one).
func Int(key string, value int64) param {
	encoded := strconv.FormatInt(value, 10)

	return param{Key: key, Value: &encoded}
}

// Bool encodes a boolean as the protocol's 0/1.
func Bool(key string, value bool) param {
	encoded := "0"
	if value {
		encoded = "1"
	}

	return param{Key: key, Value: &encoded}
}

// StrPtr encodes an optional string: nil omits the parameter entirely.
func StrPtr(key string, value *string) param {
	return param{Key: key, Value: value}
}

// Int32Ptr encodes an optional 32-bit integer.
//
// Most options carry *int32 rather than *int64 because that is the width the
// protocol uses for fields like channel_maxclients, and widening them at every
// call site would be noise.
func Int32Ptr(key string, value *int32) param {
	if value == nil {
		return param{Key: key}
	}

	return Int(key, int64(*value))
}

// UintPtr encodes an optional unsigned integer.
func UintPtr(key string, value *uint64) param {
	if value == nil {
		return param{Key: key}
	}

	return Uint(key, *value)
}

// IntPtr encodes an optional signed integer.
func IntPtr(key string, value *int64) param {
	if value == nil {
		return param{Key: key}
	}

	return Int(key, *value)
}

// BoolPtr encodes an optional boolean.
func BoolPtr(key string, value *bool) param {
	if value == nil {
		return param{Key: key}
	}

	return Bool(key, *value)
}

// StrSlice encodes a comma-separated list.
func StrSlice(key string, values []string) param {
	return Str(key, strings.Join(values, ","))
}

// passwordParam names the parameter values that must be hashed rather than sent
// as given.
//
// The client protocol expects base64(sha1(password)) for channel passwords, the
// same encoding clientinit uses — unlike raw ServerQuery, which takes the
// cleartext. Naming them per call keeps every call site from having to remember,
// which is how a plain password used to reach the server and fail with 781.
type passwordParam string

// PlainPassword marks a parameter whose value is hashed before it is sent.
func PlainPassword(key string) passwordParam {
	return passwordParam(key)
}

// buildParams renders params in order, hashing the values named by passwords
// and dropping the ones that are unset.
func buildParams(params []param, passwords ...passwordParam) [][2]string {
	hashed := make(map[string]bool, len(passwords))
	for _, p := range passwords {
		hashed[string(p)] = true
	}

	out := make([][2]string, 0, len(params))
	for _, p := range params {
		if p.Value == nil {
			continue
		}

		value := *p.Value
		// Flags (-uid) are switches: present when true, absent otherwise.
		if strings.HasPrefix(p.Key, "-") {
			if value == "1" {
				out = append(out, [2]string{p.Key, ""})
			}

			continue
		}
		if hashed[p.Key] && value != "" {
			value = prepareClientPassword(value)
		}

		out = append(out, [2]string{p.Key, value})
	}

	return out
}

// exec sends a command and waits for the server's answer.
//
// Both arguments are explicit — an empty params slice for a command that takes
// none — so the password list cannot be mistaken for a parameter. This mirrors
// the JS layer's (params, passwordFields) pair.
func (c *Client) exec(command string, params []param, passwords ...passwordParam) error {
	cmd := commands.BuildCommandOrdered(command, buildParams(params, passwords...))

	return c.ExecCommand(cmd, defaultCommandTimeout)
}

// query sends a command and returns its response rows.
func (c *Client) query(command string, params []param, passwords ...passwordParam) ([]map[string]string, error) {
	cmd := commands.BuildCommandOrdered(command, buildParams(params, passwords...))

	return c.ExecCommandWithResponse(cmd, defaultCommandTimeout)
}

// field readers. The server omits a field rather than sending an empty value in
// several cases, so each tolerates absence instead of assuming presence.

// fieldStr reads a string field. The parser has already unescaped it;
// unescaping again is how a nickname that really contains \s used to come back
// with a space in it.
func fieldStr(row map[string]string, key string) string {
	return row[key]
}

func fieldUint(row map[string]string, key string) uint64 {
	raw := row[key]
	if raw == "" {
		return 0
	}

	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0
	}

	return value
}

func fieldInt(row map[string]string, key string) int64 {
	raw := row[key]
	if raw == "" {
		return 0
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}

	return value
}

func fieldBool(row map[string]string, key string) bool {
	return fieldUint(row, key) != 0
}

// fieldInt32 reads a signed field the protocol defines as 32-bit.
//
// Several of these legitimately carry -1 (channel_maxclients, for one), so the
// value is read as int64 and clamped rather than assumed to fit.
func fieldInt32(row map[string]string, key string) int32 {
	value := fieldInt(row, key)
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	if value < math.MinInt32 {
		return math.MinInt32
	}

	return int32(value)
}

// firstOrEmpty reads a field from the first row, or returns 0 for no rows.
// createdGroupID returns the id of the group a create or copy just made.
//
// ServerQuery answers servergroupadd with the new id alone. The voice protocol
// answers with the whole group list instead (notifyservergrouplist), so taking
// the first row returned the first group on the server rather than the new
// one. The new group is the one with the requested name — the newest, should
// the name repeat across group types.
func createdGroupID(rows []map[string]string, idKey, name string) (uint64, error) {
	var listed bool
	var id uint64
	for _, row := range rows {
		rowName, ok := row["name"]
		if !ok {
			continue
		}
		listed = true
		if rowName == name {
			id = max(id, fieldUint(row, idKey))
		}
	}

	if !listed {
		return firstOrEmpty(rows, idKey), nil
	}
	if id == 0 {
		return 0, fmt.Errorf("%w: the server did not report the new group %q", errNoDataReturned, name)
	}

	return id, nil
}

func firstOrEmpty(rows []map[string]string, key string) uint64 {
	if len(rows) == 0 {
		return 0
	}

	return fieldUint(rows[0], key)
}

// fieldUintList reads a comma-separated list of ids, as client_servergroups
// arrives.
func fieldUintList(row map[string]string, key string) []uint64 {
	return parseUint64List(row[key])
}

// fieldUint16 reads a field the protocol defines as a 16-bit id, clamping rather
// than wrapping if the server ever sends something wider.
func fieldUint16(row map[string]string, key string) uint16 {
	value := fieldUint(row, key)
	if value > math.MaxUint16 {
		return math.MaxUint16
	}

	return uint16(value)
}

// splitLines splits a multi-line field, tolerating both separators the server
// uses.
func splitLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")

	return strings.Split(normalized, "\n")
}

// parseUint64List reads a comma-separated list of ids. An unparseable entry is
// skipped rather than failing the whole list.
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

// joinPipe joins values into the pipe-separated parameter the server expects for
// multi-file operations.
//
// The separator is deliberately left unescaped here: buildParams escapes the
// value as a whole, turning each pipe into \p so it cannot be read as a second
// parameter.
func joinPipe(values []string) string {
	return strings.Join(values, "|")
}
