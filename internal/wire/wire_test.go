package wire_test

import (
	"reflect"
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
}

type iconID uint32

// The server sends an icon's CRC32 signed as often as not; both forms name
// the same file.
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
	}
	for raw, want := range cases {
		if got := wire.ParseIconID[iconID](raw); got != want {
			t.Errorf("ParseIconID(%q) = %d, want %d", raw, got, want)
		}
	}
}
