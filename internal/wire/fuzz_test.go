package wire_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// FuzzEscapeRoundTrip checks that Unescape reverses Escape for any bytes, and
// that an escaped value holds none of the bytes the format reserves, so it can
// never end its parameter, its row or its line early.
func FuzzEscapeRoundTrip(f *testing.F) {
	f.Add("")
	f.Add("hello world|a/b\\c")
	f.Add("\\s\\p\\/\\\\")
	f.Add("\a\b\f\n\r\t\v\x00\xff")

	f.Fuzz(func(t *testing.T, value string) {
		escaped := wire.Escape(value)
		if strings.ContainsAny(escaped, " |\a\b\f\n\r\t\v") {
			t.Fatalf("Escape(%q) = %q still holds a reserved byte", value, escaped)
		}
		if got := wire.Unescape(escaped); got != value {
			t.Fatalf("Unescape(Escape(%q)) = %q", value, got)
		}
	})
}

// FuzzParseCommand checks that no line panics the parser, and that a command
// built from a name, a key and its values reads back as built.
func FuzzParseCommand(f *testing.F) {
	f.Add("", "", "", "")
	f.Add("clientlist", "client_nickname", "a b|c", "-away")
	f.Add("notifytextmessage", "msg", "\\s\\p\\\\", "invokerid")
	f.Add("\x01\x02error id=2 msg=a\\sb", "id", "2", "")
	f.Add("-1 id=2|=|\x00", "=", "", "")

	f.Fuzz(func(t *testing.T, line, key, value, flag string) {
		parsed := wire.ParseCommand(line)
		if parsed != nil && parsed.Params == nil {
			t.Fatalf("ParseCommand(%q) has nil Params", line)
		}

		// A round trip needs a name and keys the format can carry; the rest
		// of the input was the panic check.
		name, _, _ := strings.Cut(line, " ")
		if !wire.IsCommandName(name) || !isKey(key) || !isKey(flag) || key == flag {
			return
		}
		built := wire.BuildCommandOrdered(name, [][2]string{{key, value}, {"-" + flag, ""}})
		got := wire.ParseCommand(built)
		if got == nil || got.Name != name {
			t.Fatalf("ParseCommand(%q) = %+v, want name %q", built, got, name)
		}
		if v, ok := got.Params[key]; !ok || v != value {
			t.Fatalf("ParseCommand(%q): %q = %q (present %v), want %q", built, key, v, ok, value)
		}
		if v, ok := got.Params["-"+flag]; !ok || v != "" {
			t.Fatalf("ParseCommand(%q): flag -%s = %q (present %v)", built, flag, v, ok)
		}
	})
}

// isKey reports whether s is a parameter name the format carries unescaped.
func isKey(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}

	return true
}

// maxRowAmplification is how many times larger than the line it came from the
// rows of a split line may be together. Rows inherit the fields a batch
// leaves out, so they are larger than the line; a hostile line must not make
// them without bound.
const maxRowAmplification = 64

// FuzzSplitRows checks that no line panics the row splitter, that it makes at
// most one row per pipe-separated part, that a named line keeps its name on
// every row, and that the rows together stay within a fixed multiple of the
// line, which can be 1 MiB of what a server sent.
func FuzzSplitRows(f *testing.F) {
	f.Add("")
	f.Add("clientlist")
	f.Add("notifycliententerview clid=1 ctid=5|clid=2|clid=3 ctid=7")
	f.Add("clid=1|clid=2|=|\\p|")
	f.Add("-1 id=2|a=1")
	f.Add("a|b|c|d")
	f.Add("notifyclientleftview |||")

	f.Fuzz(func(t *testing.T, line string) {
		rows := wire.SplitRows(line)
		if len(rows) == 0 {
			t.Fatalf("SplitRows(%q) returned no rows", line)
		}
		if len(rows) > strings.Count(line, "|")+1 {
			t.Fatalf("SplitRows(%q) made %d rows from %d parts", line, len(rows), strings.Count(line, "|")+1)
		}

		head, rest, _ := strings.Cut(line, " ")
		total := 0
		for _, row := range rows {
			total += len(row)
			if wire.IsCommandName(head) && strings.Contains(rest, "|") && !strings.HasPrefix(row, head) {
				t.Fatalf("SplitRows(%q): row %q lost the name %q", line, row, head)
			}
			_ = wire.ParseCommand(row)
		}
		if total > maxRowAmplification*len(line)+4096 {
			t.Fatalf("SplitRows of a %d-byte line returned %d rows holding %d bytes", len(line), len(rows), total)
		}
		if wire.IsCommandName(head) && strings.Contains(rest, "|") {
			checkRowsKeepTheirParts(t, line, head, rest, rows)
		}
	})
}

// checkRowsKeepTheirParts checks that each row of a named, batched line holds
// every parameter its own part of the line carries, with the value that part
// gave it: a row may gain the fields the batch left out, but never lose or
// change what it was sent.
func checkRowsKeepTheirParts(t *testing.T, line, name, rest string, rows []string) {
	t.Helper()
	next := 0
	for part := range strings.SplitSeq(rest, "|") {
		if part == "" {
			continue
		}
		if next >= len(rows) {
			return // the line made no rows of its own and came back whole
		}
		want := wire.ParseCommand(name + " " + part)
		got := wire.ParseCommand(rows[next])
		next++
		if want == nil || got == nil {
			continue
		}
		for key, value := range want.Params {
			if gotValue, ok := got.Params[key]; !ok || gotValue != value {
				t.Fatalf("SplitRows(%q): row %d has %q = %q (present %v), its part says %q",
					line, next-1, key, gotValue, ok, value)
			}
		}
	}
}

// FuzzParseIconID checks that an icon id reads the same whether the server
// sends it as an unsigned number, as the signed one it is reinterpreted as, or
// as that signed one sign-extended to 64 bits,
// and that no other text panics it or an error id's reader.
func FuzzParseIconID(f *testing.F) {
	f.Add("", uint32(0))
	f.Add("-2004712318", uint32(2290254978))
	f.Add("99999999999999999999", uint32(1))
	f.Add("+5", uint32(5))

	f.Fuzz(func(t *testing.T, raw string, id uint32) {
		_ = wire.ParseIconID[uint32](raw)
		want := errcode.Undefined
		value, err := strconv.ParseUint(raw, 10, 32)
		if err == nil {
			want = errcode.Code(value)
		}
		got := wire.ParseCode(raw)
		if got != want {
			t.Fatalf("ParseCode(%q) = %d, want %d", raw, got, want)
		}
		got = wire.ParseCode(strconv.FormatUint(uint64(id), 10))
		if got != errcode.Code(id) {
			t.Fatalf("ParseCode(%d) = %d", id, got)
		}

		unsigned := strconv.FormatUint(uint64(id), 10)
		signed := strconv.FormatInt(int64(int32(id)), 10)
		if got := wire.ParseIconID[uint32](unsigned); got != id {
			t.Fatalf("ParseIconID(%q) = %d, want %d", unsigned, got, id)
		}
		if got := wire.ParseIconID[uint32](signed); got != id {
			t.Fatalf("ParseIconID(%q) = %d, want %d", signed, got, id)
		}
		wide := strconv.FormatUint(uint64(int64(int32(id))), 10)
		if got := wire.ParseIconID[uint32](wide); got != id {
			t.Fatalf("ParseIconID(%q) = %d, want %d", wide, got, id)
		}
	})
}
