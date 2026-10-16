package teamspeak

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// param is one wire parameter. A nil Value means "do not send this parameter
// at all", which is not the same as sending an empty string: clearing a
// channel password takes `channel_password=`, while leaving it alone takes no
// parameter. Callers express the difference with a pointer.
type param struct {
	Value *string
	// rows, when set, makes the parameter a row group: one key=value per
	// value, separated by pipes, as the server takes a list (name=/a|name=/b).
	rows []string
	// err is why the parameter cannot be encoded. The command carrying it is
	// refused before anything is sent: sending it without the parameter would
	// mean something else — a ban without its duration is permanent.
	err error
	Key string
}

// invalidArg is a parameter that cannot be sent, for the reason given. Its
// error wraps ErrInvalidCommand.
func invalidArg(reason string) param {
	return param{err: fmt.Errorf("%w: %s", ErrInvalidCommand, reason)}
}

// firstInvalid returns the error of the first parameter that cannot be sent.
func firstInvalid(params []param) error {
	for _, p := range params {
		if p.err != nil {
			return p.err
		}
	}

	return nil
}

// strArg encodes a string parameter.
func strArg(key, value string) param {
	return param{Key: key, Value: &value}
}

// uintArg encodes an unsigned integer parameter.
func uintArg(key string, value uint64) param {
	encoded := strconv.FormatUint(value, 10)

	return param{Key: key, Value: &encoded}
}

// intArg encodes a signed integer parameter, which the protocol needs because
// several fields legitimately carry -1 (channel_maxclients, for one).
func intArg(key string, value int64) param {
	encoded := strconv.FormatInt(value, 10)

	return param{Key: key, Value: &encoded}
}

// boolArg encodes a boolean as the protocol's 0/1.
func boolArg(key string, value bool) param {
	encoded := "0"
	if value {
		encoded = "1"
	}

	return param{Key: key, Value: &encoded}
}

// strPtrArg encodes an optional string: nil omits the parameter entirely.
func strPtrArg(key string, value *string) param {
	return param{Key: key, Value: value}
}

// optStrArg encodes a string that is omitted when empty, for the parameters
// where an empty value would mean nothing to the server: a ban reason, a
// subsystem filter.
func optStrArg(key, value string) param {
	if value == "" {
		return param{Key: key}
	}

	return strArg(key, value)
}

// unsigned is every unsigned type a parameter or field carries, ids included.
type unsigned interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64
}

// idArg encodes an id.
func idArg[T unsigned](key string, id T) param {
	return uintArg(key, uint64(id))
}

// optIDArg encodes an id that is omitted when 0. Where a command takes an id
// as a filter, 0 is no channel, client or group, so it can only mean "any".
func optIDArg[T unsigned](key string, id T) param {
	if id == 0 {
		return param{Key: key}
	}

	return idArg(key, id)
}

// durationArg encodes a duration in the field's unit, rounded to the nearest
// one.
//
// A positive duration shorter than half a unit is sent as one unit rather than
// rounded down to 0, because to some fields 0 means "no limit": a ban of 0
// seconds is permanent, so rounding a 400ms ban down would make it last
// forever. A negative duration is refused.
func durationArg(key string, d, unit time.Duration) param {
	if d < 0 {
		return invalidArg(fmt.Sprintf("%s: negative duration %v", key, d))
	}

	units := d.Round(unit) / unit
	if units == 0 && d > 0 {
		units = 1
	}

	return uintArg(key, uint64(units))
}

// durationPtrArg encodes an optional duration in the field's unit.
func durationPtrArg(key string, d *time.Duration, unit time.Duration) param {
	if d == nil {
		return param{Key: key}
	}

	return durationArg(key, *d, unit)
}

// permArg encodes a permission as permid or permsid, whichever names it. A
// zero Permission names nothing, and sending a command with neither parameter
// fails on the server with a less helpful error, if it fails at all.
func permArg(perm Permission) param {
	switch {
	case perm.name != "":
		return strArg("permsid", perm.name)
	case perm.id != 0:
		return idArg("permid", perm.id)
	default:
		return invalidArg("no permission given")
	}
}

// int32PtrArg encodes an optional 32-bit integer.
//
// Most options carry *int32 rather than *int64 because that is the width the
// protocol uses for fields like channel_maxclients, and widening them at every
// call site would be noise.
func int32PtrArg(key string, value *int32) param {
	if value == nil {
		return param{Key: key}
	}

	return intArg(key, int64(*value))
}

// uintPtrArg encodes an optional unsigned integer or id.
func uintPtrArg[T unsigned](key string, value *T) param {
	if value == nil {
		return param{Key: key}
	}

	return uintArg(key, uint64(*value))
}

// boolPtrArg encodes an optional boolean.
func boolPtrArg(key string, value *bool) param {
	if value == nil {
		return param{Key: key}
	}

	return boolArg(key, *value)
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

// fieldUint32 reads a field the protocol defines as 32-bit unsigned, clamping
// rather than wrapping.
func fieldUint32(row map[string]string, key string) uint32 {
	value := fieldUint(row, key)
	if value > math.MaxUint32 {
		return math.MaxUint32
	}

	return uint32(value)
}

// fieldUint8 reads a field the protocol defines as one byte, clamping rather
// than wrapping.
func fieldUint8(row map[string]string, key string) uint8 {
	value := fieldUint(row, key)
	if value > math.MaxUint8 {
		return math.MaxUint8
	}

	return uint8(value)
}

// fieldEnum reads an enumeration value. The protocol's enumerations are
// 32-bit, and an int is only that wide on some platforms, so the value is
// bounded to 32 bits rather than truncated by a conversion.
func fieldEnum(row map[string]string, key string) int {
	return int(fieldInt32(row, key))
}

// fieldFloat32 reads a decimal field, such as a transfer speed. Reading one as
// an integer failed on the decimal point and reported 0.
func fieldFloat32(row map[string]string, key string) float32 {
	value, err := strconv.ParseFloat(row[key], 32)
	if err != nil {
		return 0
	}

	return float32(value)
}

// fieldIconID reads an icon id, signed or not; see wire.ParseIconID.
func fieldIconID(row map[string]string, key string) IconID {
	return wire.ParseIconID[IconID](row[key])
}

// Timestamps above these are not seconds. TS6 sends some in finer units —
// ftgetfilelist's datetime in milliseconds, ftgetfileinfo's in nanoseconds,
// for the same file — while TS3 sends seconds throughout. 1e11 seconds is the
// year 5138, and 1e11 milliseconds early 1973, so the magnitude settles the
// unit for any date this protocol will carry.
const (
	maxUnixSeconds = 1e11
	maxUnixMillis  = 1e14
	maxUnixMicros  = 1e17
)

// fieldTime reads a unix timestamp. 0 and an absent field are the zero
// time.Time, not 1970: the server sends 0 for "never".
func fieldTime(row map[string]string, key string) time.Time {
	value := fieldInt(row, key)
	switch {
	case value <= 0:
		return time.Time{}
	case value < maxUnixSeconds:
		return time.Unix(value, 0)
	case value < maxUnixMillis:
		return time.UnixMilli(value)
	case value < maxUnixMicros:
		return time.UnixMicro(value)
	default:
		return time.Unix(0, value)
	}
}

// fieldDuration reads a duration sent as a count of unit, clamping rather than
// overflowing.
func fieldDuration(row map[string]string, key string, unit time.Duration) time.Duration {
	value := fieldUint(row, key)
	if value > math.MaxInt64 {
		return time.Duration(math.MaxInt64)
	}
	count := int64(value)
	if count > math.MaxInt64/int64(unit) {
		return time.Duration(math.MaxInt64)
	}

	return time.Duration(count) * unit
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

// fieldOptInt32 reads a signed 32-bit field that an answer may leave out. It
// is nil when the key is absent or empty, and a pointer to the value, zero
// included, when the server sent it: 0 and "not reported" mean different things.
func fieldOptInt32(row map[string]string, key string) *int32 {
	if row[key] == "" {
		return nil
	}
	value := fieldInt32(row, key)

	return &value
}

// fieldOptUint16 is fieldOptInt32 for a 16-bit unsigned field.
func fieldOptUint16(row map[string]string, key string) *uint16 {
	if row[key] == "" {
		return nil
	}
	value := fieldUint16(row, key)

	return &value
}

// createdGroupID returns the id of the group a create or copy just made.
//
// ServerQuery answers servergroupadd with the new id alone. The voice protocol
// answers with the whole group list instead (notifyservergrouplist), so taking
// the first row returned the first group on the server rather than the new
// one. The new group is the one with the requested name — the newest, should
// the name repeat across group types.
//
// The difference is a property of the answers, not a choice:
// notifychannelcreated names the client that invoked it, so channelcreate
// keeps only its own row, while the group commands answer with the whole list
// and name no invoker — notifyservergrouplist for servergroupadd and
// servergroupcopy, notifychannelgrouplist for channelgroupadd and
// channelgroupcopy — leaving nothing but the name to match on. A group of the
// same name created concurrently by another party is therefore
// indistinguishable from ours, channel groups as much as server groups, and
// the id returned may be theirs rather than the one just made. That is a limit
// of what the notification reports, not of this function.
func createdGroupID[T ~uint64](rows []map[string]string, idKey, name string) (T, error) {
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
		row, err := requireRow(rows, "group creation", idKey)
		if err != nil {
			return 0, err
		}

		return T(fieldUint(row, idKey)), nil
	}
	if id == 0 {
		return 0, fmt.Errorf("%w: the server did not report the new group %q", ErrNoData, name)
	}

	return T(id), nil
}

// requireRow returns the row command is defined to answer with, which must
// hold key when one is named. A server that acknowledged the command without
// it has not answered: that is an error wrapping ErrNoData, not a row of empty
// fields.
func requireRow(rows []map[string]string, command, key string) (map[string]string, error) {
	if len(rows) == 0 || (key != "" && rows[0][key] == "") {
		return nil, fmt.Errorf("%w: %s", ErrNoData, command)
	}

	return rows[0], nil
}

// fieldIDList reads a comma-separated list of ids, as client_servergroups
// arrives.
func fieldIDList[T ~uint64](row map[string]string, key string) []T {
	return parseIDList[T](row[key])
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

// parseIDList reads a comma-separated list of ids. An unparseable entry is
// skipped rather than failing the whole list.
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

// rowsArg encodes a list the way the server takes one: key=value once per
// value, the occurrences separated by pipes. Joining the values into one
// parameter escaped each pipe to \p, which the server read as one name.
func rowsArg(key string, values []string) param {
	if len(values) == 0 {
		return invalidArg(key + ": an empty list")
	}

	return param{Key: key, rows: values}
}
