package wire

import "strings"

// Command is a parsed or built command line: its name and parameters.
type Command struct {
	Params map[string]string
	Name   string
}

// Build returns the string representation of the command.
func (c *Command) Build() string {
	return BuildCommand(c.Name, c.Params)
}

var escaper = strings.NewReplacer(
	"\\", "\\\\",
	"/", "\\/",
	" ", "\\s",
	"|", "\\p",
	"\a", "\\a",
	"\b", "\\b",
	"\f", "\\f",
	"\n", "\\n",
	"\r", "\\r",
	"\t", "\\t",
	"\v", "\\v",
)

// Escape escapes a parameter value for a command line: a space becomes \s, a
// pipe \p, a slash \/, and so on, the escapes Unescape reverses.
func Escape(s string) string {
	return escaper.Replace(s)
}

// BuildCommand renders a command line from a name and its parameters, escaping
// the values. Map order is random, so the parameters' order is too; use
// BuildCommandOrdered where order matters.
func BuildCommand(cmd string, params map[string]string) string {
	var res strings.Builder
	res.WriteString(Escape(cmd))
	for k, v := range params {
		res.WriteByte(' ')
		res.WriteString(k)
		res.WriteByte('=')
		res.WriteString(Escape(v))
	}

	return res.String()
}

// BuildCommandOrdered renders a command line with its parameters in the order
// given, escaping the values. A key starting with "-" and an empty value is
// written as a bare flag.
func BuildCommandOrdered(cmd string, params [][2]string) string {
	var res strings.Builder
	res.WriteString(Escape(cmd))
	for _, kv := range params {
		res.WriteByte(' ')
		res.WriteString(kv[0])
		// A flag such as -uid is a bare switch. -uid=1 happens to be accepted
		// over the voice protocol, but it is not the documented form and
		// nothing promises another transport tolerates it.
		if strings.HasPrefix(kv[0], "-") && kv[1] == "" {
			continue
		}
		res.WriteByte('=')
		res.WriteString(Escape(kv[1]))
	}

	return res.String()
}

// ParseCommand reads one command line into its name and unescaped parameters,
// or returns nil for an empty line. A line that starts with a parameter rather
// than a name — a response row — has the name "". A line carrying several rows
// separated by pipes must be split first; this reads it as one.
func ParseCommand(s string) *Command {
	if s == "" {
		return nil
	}

	parts := strings.Split(stripLeadingNonPrintable(s), " ")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}

	// A command name is a run of alphanumerics followed by a space — the rule
	// tsproto-packets uses (CommandParser::new). Anything else means the line is
	// not a command at all: response rows carry no name ("clid=6 cid=2 ..."),
	// and negative feedback is "-1 id=2 ...", naming the *rejected* command id
	// rather than a command of its own. Returning those as a nameless row keeps
	// the data intact instead of folding the first field into a name, which is
	// how every clientlist row used to lose its clid.
	first := parts[0]

	cmd := &Command{
		Name:   "",
		Params: make(map[string]string),
	}

	var rest []string

	if IsCommandName(first) {
		cmd.Name = first
		rest = parts[1:]
	} else {
		rest = parts
	}

	for _, p := range rest {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			cmd.Params[Unescape(kv[0])] = Unescape(kv[1])
		} else {
			cmd.Params[Unescape(p)] = ""
		}
	}

	return cmd
}

// IsCommandName reports whether a line's first token is a command name rather
// than one of a response row's key=value pairs.
//
// Everything that splits or parses a line asks this one function, so the
// parser and the row splitter cannot disagree about where a command's data
// begins.
func IsCommandName(token string) bool {
	if token == "" {
		return false
	}
	for i := range len(token) {
		c := token[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}

// stripLeadingNonPrintable drops control bytes some servers prefix a command
// with, so the line starts at its first printable character.
func stripLeadingNonPrintable(s string) string {
	for i := range len(s) {
		if s[i] >= 32 && s[i] <= 126 {
			return s[i:]
		}
	}

	return s
}

var unescaper = strings.NewReplacer(
	"\\\\", "\\",
	"\\/", "/",
	"\\s", " ",
	"\\p", "|",
	"\\a", "\a",
	"\\b", "\b",
	"\\f", "\f",
	"\\n", "\n",
	"\\r", "\r",
	"\\t", "\t",
	"\\v", "\v",
)

// Unescape reverses Escape.
func Unescape(s string) string {
	return unescaper.Replace(s)
}
