package serverquery

import (
	"regexp"
	"time"
)

// lateRows are the commands whose answer carries the row that names what they
// made, and what that row is known by.
//
// TeamSpeak 6 over SSH has been measured (6.0.0-beta13.1) to write that row
// after the command's error line, a fraction of a millisecond later, in a share
// of the answers. A client that takes the error line for the end of the answer
// loses the row and, worse, hands it to whichever command is sent next. Holding
// the answer briefly is harmless on a server that writes the row first. See
// the "Server behaviour the SDK works around" section of the serverquery package documentation.
var lateRows = map[string]lateRow{
	"channelcreate":    {keys: []string{"cid"}},
	"servergroupadd":   {keys: []string{"sgid"}},
	"servergroupcopy":  {keys: []string{"sgid"}},
	"channelgroupadd":  {keys: []string{"cgid"}},
	"channelgroupcopy": {keys: []string{"cgid"}},
	"banadd":           {keys: []string{"banid"}},
	"banclient":        {keys: []string{"banid"}, several: true},
	"privilegekeyadd":  {keys: []string{"token"}},
	"tokenadd":         {keys: []string{"token"}},
	"apikeyadd":        {keys: []string{"apikey"}},
	"servercreate":     {keys: []string{"sid"}},
}

// lateRow is the row a command's answer carries.
type lateRow struct {
	// keys are the keys the row is known by.
	keys []string
	// several marks an answer with one row for each of several things it made,
	// of which all, some or none may follow the error line, so it is held until
	// the rows stop.
	several bool
	// any marks a read: any row is the answer, and it is held only when empty.
	any bool
}

// lateRowGrace is how long a successful answer without its row is held open for
// the row to arrive.
const lateRowGrace = 250 * time.Millisecond

// WholeAnswers is implemented by a transport that delivers each answer as one
// piece, rows and error line together, so no row can follow the error line.
type WholeAnswers interface {
	WholeAnswers()
}

// lateRowQuiet is how long without a new row ends an answer with several.
const lateRowQuiet = 25 * time.Millisecond

// reads matches the commands that read something, by name: a list, info or
// find, a get..., whoami, version. A plain read has been measured to have its
// whole answer after the error line too, much less often than a create (2 in
// 3000 clientlist calls, while clients were connecting), so one that is
// answered with no row is held briefly as well. An empty success is rare for
// these: the servers answer an empty list with error 1281.
var reads = regexp.MustCompile(`(list|info|find|search)$|^(get\w+|whoami|version|permfind|permoverview|permget)$`)

// lateRowOf is what is known of where a command's answer rows may fall.
func lateRowOf(command string) (lateRow, bool) {
	if late, ok := lateRows[command]; ok {
		return late, true
	}
	if reads.MatchString(command) {
		return lateRow{any: true}, true
	}

	return lateRow{}, false
}

// answered reports whether rows already hold what the command waits for.
func (l lateRow) answered(rows []map[string]string) bool {
	if l.any {
		return len(rows) > 0
	}

	return hasKey(rows, l.keys)
}
