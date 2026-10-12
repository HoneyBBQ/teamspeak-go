// Package commands reads and writes TeamSpeak command lines: a name followed
// by key=value parameters, with values escaped so a space or a pipe cannot end
// them early. The voice protocol and ServerQuery share the format.
package commands

import (
	"strings"
)

// Command represents a parsed or built TS3 command line.
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
