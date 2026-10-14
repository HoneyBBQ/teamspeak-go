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

// The bytes the rows of a line may hold together, see rowLimits.
const (
	minRowBudget        = 64 << 10
	rowGrowth           = 4
	maxRowAmplification = 64
)

// SplitRows expands a pipe-separated multi-row command line into individual
// rows.
//
// A named line (notifyclientleftview a=1|a=2) keeps its name on every row; a
// nameless response (cldbid=1|cldbid=2) stays nameless. Whether the first token
// is a name is the parser's own rule — deciding it here by position is how a
// nameless batch with no space in it went through unsplit, and a one-field
// response came back as a single row. Tokens are split on the space and on
// nothing else, as the parser splits them: a tab or a no-break space inside a
// value stays inside it, since an escaped value never holds a raw space.
//
// TeamSpeak compresses a batch by leaving out of a row the fields whose value
// is unchanged from the previous row: in a notifycliententerview batch, ctid is
// often present only on the first row. A row is therefore the fields of the
// previous row, as that row came out, that it does not name itself, followed by
// its own. Tokens stay escaped so the command parser still performs its single
// unescape pass.
//
// A row that names a field of its own each time makes every row carry all the
// fields before it, so the rows would grow with the square of the line. The
// rows of a real server's line are a little larger than their own parts and
// never come near the limits that stop this: once the rows together would hold
// more than the larger of four times the line and 64 KiB, the rows after that
// carry only their own tokens. A name repeated on every row can grow them on its
// own, so at twice that the rows stop, and the rest of the line is dropped.
// Neither limit passes 64 times the line.
func SplitRows(line string) []string {
	name, rest := splitName(line)
	if !strings.Contains(rest, "|") {
		return []string{line}
	}
	batch := newRowBatch(name, len(line))

	var rows []string
	for part := range strings.SplitSeq(rest, "|") {
		if part == "" {
			continue
		}
		row, ok := batch.next(splitTokens(part))
		if !ok {
			break
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return []string{line}
	}

	return rows
}

// rowBatch resolves the rows of one line, one after another.
type rowBatch struct {
	prefix string
	// previous holds the fields of the row before, each once, with the token
	// that row gave it, in the order the row had them. It is nil once rows stop
	// inheriting.
	previous []string
	// used counts the bytes of the rows so far.
	used         int
	inheritLimit int
	dropLimit    int
	inherit      bool
}

func newRowBatch(name string, lineLen int) *rowBatch {
	b := &rowBatch{inherit: true}
	b.inheritLimit, b.dropLimit = rowLimits(lineLen)
	if name != "" {
		b.prefix = name + " "
	}

	return b
}

// next returns the next row of the line, given its own tokens, or false once
// the rows have reached their limit.
func (b *rowBatch) next(tokens []string) (string, bool) {
	row := b.prefix + strings.Join(tokens, " ")
	if b.inherit {
		resolved := b.resolve(tokens)
		if inherited := b.prefix + strings.Join(resolved, " "); b.used+len(inherited) <= b.inheritLimit {
			row = inherited
			b.previous = lastPerField(resolved)
		} else {
			b.inherit, b.previous = false, nil
		}
	}
	if b.used+len(row) > b.dropLimit {
		return "", false
	}
	b.used += len(row)

	return row, true
}

// resolve returns the tokens of a row: the fields of the previous row that the
// row does not name, then the row's own tokens.
func (b *rowBatch) resolve(tokens []string) []string {
	named := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		named[fieldName(token)] = struct{}{}
	}
	resolved := make([]string, 0, len(b.previous)+len(tokens))
	for _, token := range b.previous {
		if _, ok := named[fieldName(token)]; !ok {
			resolved = append(resolved, token)
		}
	}

	return append(resolved, tokens...)
}

// lastPerField keeps the last token of each field, in the order the fields
// first appear.
func lastPerField(tokens []string) []string {
	at := make(map[string]int, len(tokens))
	kept := make([]string, 0, len(tokens))
	for _, token := range tokens {
		key := fieldName(token)
		if i, ok := at[key]; ok {
			kept[i] = token

			continue
		}
		at[key] = len(kept)
		kept = append(kept, token)
	}

	return kept
}

// rowLimits returns how many bytes the rows of a line of n bytes may hold
// together before they stop inheriting fields, and before they stop.
func rowLimits(n int) (int, int) {
	inherit := max(rowGrowth*n, minRowBudget)
	drop := min(2*inherit, maxRowAmplification*n)

	return min(inherit, drop), drop
}

// splitTokens splits a row on the space, dropping the empty tokens that
// repeated spaces leave, as the parser does.
func splitTokens(part string) []string {
	tokens := strings.Split(part, " ")
	kept := tokens[:0]
	for _, token := range tokens {
		if token != "" {
			kept = append(kept, token)
		}
	}

	return kept
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
