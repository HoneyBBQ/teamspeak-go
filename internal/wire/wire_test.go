package wire_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

func TestSplitRows_SingleLine(t *testing.T) {
	rows := wire.SplitRows("clientlist")
	if len(rows) != 1 || rows[0] != "clientlist" {
		t.Errorf("unexpected rows: %v", rows)
	}
}

func TestSplitRows_NoArgsNoPipe(t *testing.T) {
	rows := wire.SplitRows("hello key=val")
	if len(rows) != 1 || rows[0] != "hello key=val" {
		t.Errorf("unexpected rows: %v", rows)
	}
}

func TestSplitRows_PipeSplitsToPrefixedRows(t *testing.T) {
	rows := wire.SplitRows("notifycliententerview clid=1|clid=2|clid=3")
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d: %v", len(rows), rows)
	}
	if rows[0] != "notifycliententerview clid=1" {
		t.Errorf("row[0] = %q", rows[0])
	}
	if rows[1] != "notifycliententerview clid=2" {
		t.Errorf("row[1] = %q", rows[1])
	}
	if rows[2] != "notifycliententerview clid=3" {
		t.Errorf("row[2] = %q", rows[2])
	}
}

func TestSplitRows_InheritsFieldsOmittedFromLaterRows(t *testing.T) {
	// Shape captured from a live TS3 server: the second row of a batched
	// notifycliententerview carries no cfid/ctid/reasonid at all.
	rows := wire.SplitRows(
		"notifycliententerview cfid=0 ctid=2 reasonid=2 clid=10 client_nickname=a|clid=13 client_nickname=b",
	)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %v", len(rows), rows)
	}
	want := "notifycliententerview cfid=0 ctid=2 reasonid=2 clid=13 client_nickname=b"
	if rows[1] != want {
		t.Errorf("row[1] = %q, want %q", rows[1], want)
	}
}

func TestSplitRows_LaterRowOverridesInheritedField(t *testing.T) {
	rows := wire.SplitRows("notifychannelsubscribed cid=5 es=177|cid=4|cid=1 es=0")
	want := []string{
		"notifychannelsubscribed cid=5 es=177",
		"notifychannelsubscribed es=177 cid=4",
		"notifychannelsubscribed cid=1 es=0",
	}
	if len(rows) != len(want) {
		t.Fatalf("expected %d rows, got %d: %v", len(want), len(rows), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row[%d] = %q, want %q", i, rows[i], want[i])
		}
	}
}

// ctid is sent once, on the first row of a notifycliententerview batch, and
// holds for the rows after it.
func TestSplitRows_EnterBatchInheritsTheChannelFromItsFirstRow(t *testing.T) {
	rows := wire.SplitRows("notifycliententerview cfid=0 ctid=2 clid=10|clid=11|clid=12")
	want := []string{
		"notifycliententerview cfid=0 ctid=2 clid=10",
		"notifycliententerview cfid=0 ctid=2 clid=11",
		"notifycliententerview cfid=0 ctid=2 clid=12",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %q, want %q", rows, want)
	}
}

// A value a row changes holds for the rows after it, until another changes it.
func TestSplitRows_CarriesAChangedValueToTheNextRow(t *testing.T) {
	rows := wire.SplitRows("notifycliententerview ctid=2 clid=10|ctid=5 clid=11|clid=12|clid=13 ctid=2")
	want := []string{
		"notifycliententerview ctid=2 clid=10",
		"notifycliententerview ctid=5 clid=11",
		"notifycliententerview ctid=5 clid=12",
		"notifycliententerview clid=13 ctid=2",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %q, want %q", rows, want)
	}
}

// A field that first appears on a later row holds for the rows after it, as any
// field the row before had does.
func TestSplitRows_CarriesAFieldFirstSeenOnALaterRow(t *testing.T) {
	rows := wire.SplitRows("notifycliententerview ctid=2 clid=10|clid=11 away=1|clid=12")
	want := []string{
		"notifycliententerview ctid=2 clid=10",
		"notifycliententerview ctid=2 clid=11 away=1",
		"notifycliententerview ctid=2 away=1 clid=12",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %q, want %q", rows, want)
	}
}

// The first row of a permission list is a marker with a field of its own, and
// the rows after it carry the fields that follow.
func TestSplitRows_CarriesFieldsAcrossAMarkerRow(t *testing.T) {
	rows := wire.SplitRows("notifypermissionlist group_id_end=0|permname=a permdesc=x|permname=b|permdesc=y")
	want := []string{
		"notifypermissionlist group_id_end=0",
		"notifypermissionlist group_id_end=0 permname=a permdesc=x",
		"notifypermissionlist group_id_end=0 permdesc=x permname=b",
		"notifypermissionlist group_id_end=0 permname=b permdesc=y",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %q, want %q", rows, want)
	}
}

// dropLimit is the most the rows of a line of n bytes may hold together: twice
// the larger of four times the line and 64 KiB, and never 64 times the line.
func dropLimit(n int) int {
	return min(2*max(4*n, 64<<10), 64*n)
}

// rowsSize returns the bytes the rows hold together.
func rowsSize(rows []string) int {
	total := 0
	for _, row := range rows {
		total += len(row)
	}

	return total
}

// Rows with a key of their own each would inherit every key before them, and
// the rows together would grow with the square of the line. They are held to
// the budget, and the rows after it carry their own tokens only.
func TestSplitRows_RowsOfDistinctKeysStayWithinTheBudget(t *testing.T) {
	const count = 2000
	var line strings.Builder
	line.WriteString("notifyfoo ")
	for i := range count {
		if i > 0 {
			line.WriteByte('|')
		}
		fmt.Fprintf(&line, "k%d=1", i)
	}

	rows := wire.SplitRows(line.String())
	if len(rows) != count {
		t.Fatalf("got %d rows, want %d", len(rows), count)
	}
	if limit := dropLimit(line.Len()); rowsSize(rows) > limit {
		t.Errorf("%d rows hold %d bytes, more than %d for a %d-byte line", len(rows), rowsSize(rows), limit, line.Len())
	}
	if want := "notifyfoo k0=1 k1=1 k2=1"; rows[2] != want {
		t.Errorf("row 2 = %q, want %q", rows[2], want)
	}
	if want := "notifyfoo k1999=1"; rows[count-1] != want {
		t.Errorf("last row = %q, want it as sent once the budget was passed", rows[count-1])
	}
}

// A first row of many fields followed by many short rows would give rows of the
// first row's size each; once the budget is passed they carry their own tokens.
func TestSplitRows_StopsInheritingPastTheBudget(t *testing.T) {
	var line strings.Builder
	line.WriteString("notifyfoo")
	for i := range 3000 {
		fmt.Fprintf(&line, " f%d=1", i)
	}
	for range 3000 {
		line.WriteString("|g=2")
	}

	rows := wire.SplitRows(line.String())
	if len(rows) != 3001 {
		t.Fatalf("got %d rows, want 3001", len(rows))
	}
	if limit := dropLimit(line.Len()); rowsSize(rows) > limit {
		t.Errorf("rows hold %d bytes, more than %d for a %d-byte line", rowsSize(rows), limit, line.Len())
	}
	if !strings.Contains(rows[1], " f2999=1") {
		t.Errorf("second row lost the fields the first row had: %.60q", rows[1])
	}
	if last := rows[len(rows)-1]; last != "notifyfoo g=2" {
		t.Errorf("last row = %q, want it as sent", last)
	}
}

// The name is on every row, so a long name over many short rows grows the same
// way, with nothing to stop inheriting; what does not fit is dropped.
func TestSplitRows_DropsTheRowsPastTheBudget(t *testing.T) {
	line := "n" + strings.Repeat("a", 4000) + " " + strings.Repeat("a=1|", 4000)

	rows := wire.SplitRows(line)
	if limit := dropLimit(len(line)); rowsSize(rows) > limit {
		t.Errorf("rows hold %d bytes, more than %d for a %d-byte line", rowsSize(rows), limit, len(line))
	}
	if len(rows) == 0 || len(rows) >= 4000 {
		t.Errorf("got %d rows, want some but not all 4000", len(rows))
	}
}

// The parser splits a row on the space alone, so every other kind of space is
// part of a value. Splitting on it too let a nickname such as "a\u00a0clid=1"
// put a clid of its own on its row.
func TestSplitRows_SplitsOnTheSpaceAlone(t *testing.T) {
	for _, space := range []string{"\t", "\u00a0", "\u0085", "\u3000", "\v"} {
		rows := wire.SplitRows("notifycliententerview clid=2 client_nickname=a" + space + "clid=1|clid=3")
		if len(rows) != 2 {
			t.Fatalf("%q: got %d rows: %q", space, len(rows), rows)
		}
		got := wire.ParseCommand(rows[0])
		if got.Params["clid"] != "2" || got.Params["client_nickname"] != "a"+space+"clid=1" {
			t.Errorf("%q: first row reads %v", space, got.Params)
		}
	}
	if rows := wire.SplitRows("0 |\t"); len(rows) != 1 || rows[0] != "0 \t" {
		t.Errorf("a row of one tab = %q, want it kept", rows)
	}
}

func TestSplitRows_KeepsValuesEscaped(t *testing.T) {
	rows := wire.SplitRows(`x a=hello\sworld|b=1`)
	if rows[1] != `x a=hello\sworld b=1` {
		t.Errorf("row[1] = %q", rows[1])
	}
}

func TestSplitRows_EmptyPartSkipped(t *testing.T) {
	// Leading/trailing | in "rest" produces empty parts, which are skipped.
	rows := wire.SplitRows("cmd a=1||b=2")
	// empty part skipped → 2 rows
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %v", len(rows), rows)
	}
}

func TestSplitRows_NoNameNoSpace(t *testing.T) {
	// A string without a space → treated as a single command with no args.
	rows := wire.SplitRows("justcommand")
	if len(rows) != 1 || rows[0] != "justcommand" {
		t.Errorf("unexpected: %v", rows)
	}
}

// Response rows carry no name. Treating the first field as one copied it onto
// every row, and a batch with no space in it was never split at all.
func TestSplitRows_NamelessBatches(t *testing.T) {
	cases := map[string][]string{
		"clid=1 cid=5|clid=2 cid=6":  {"clid=1 cid=5", "clid=2 cid=6"},
		"cldbid=1|cldbid=2|cldbid=3": {"cldbid=1", "cldbid=2", "cldbid=3"},
		"cid=1 name=a|name=b":        {"cid=1 name=a", "cid=1 name=b"},
	}
	for line, want := range cases {
		if got := wire.SplitRows(line); !reflect.DeepEqual(got, want) {
			t.Errorf("wire.SplitRows(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseCode(t *testing.T) {
	got := wire.ParseCode("2568")
	if got != errcode.PermissionsClientInsufficient {
		t.Errorf("ParseCode(2568) = %v", got)
	}
	got = wire.ParseCode("")
	if got != errcode.Undefined {
		t.Errorf("ParseCode(\"\") = %v, want errcode.Undefined", got)
	}
	// Not read as a prefix, a sign or a wrapped value.
	for _, raw := range []string{"12abc", " 7", "-1", "+5", "1.5", "0x10", "4294967296", "99999999999999999999"} {
		got = wire.ParseCode(raw)
		if got != errcode.Undefined {
			t.Errorf("ParseCode(%q) = %v, want errcode.Undefined", raw, got)
		}
	}
	got = wire.ParseCode("4294967295")
	if got != errcode.Code(4294967295) {
		t.Errorf("ParseCode(4294967295) = %v", got)
	}
	got = wire.ParseCode("0000000000000000000012")
	if got != errcode.Code(12) {
		t.Errorf("ParseCode with leading zeros = %v, want 12", got)
	}
}

type iconID uint32

// The server sends an icon's CRC32 unsigned, signed, or signed and
// sign-extended to 64 bits; every form names the same file.
func TestParseIconID(t *testing.T) {
	cases := map[string]iconID{
		"2766950830":  2766950830,
		"-1528016466": 2766950830,
		"100":         100,
		"0":           0,
		"":            0,
		"icon":        0,
		"4294967296":  0,
		"-2147483649": 0,
		// Sign-extended to 64 bits, as notifychanneledited sends them.
		"18446744072424443899": 3009859579,
		"18446744073709551615": 4294967295,
		"18446744071562067968": 2147483648,
		// Above 32 bits but not a sign-extended 32-bit number.
		"18446744071562067967": 0,
		"9223372036854775808":  0,
		"18446744073709551616": 0,
	}
	for raw, want := range cases {
		if got := wire.ParseIconID[iconID](raw); got != want {
			t.Errorf("ParseIconID(%q) = %d, want %d", raw, got, want)
		}
	}
}
