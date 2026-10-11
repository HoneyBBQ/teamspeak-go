package commands

import (
	"strings"
)

func ParseCommand(s string) *Command {
	if s == "" {
		return nil
	}

	parts := strings.Split(stripLeadingNonPrintable(s), " ")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}

	// TeamSpeak leaves the command name off response rows. A clientlist reply is
	// "clid=6 cid=2 ..." and a rejection is "-1 id=2 ...", so the first token is
	// a name only when it is neither a key=value pair nor a leading-'-' flag.
	// Deciding that here keeps every consumer from having to re-inspect Name for
	// an '=' it was never told about.
	first := parts[0]

	cmd := &Command{
		Name:   "",
		Params: make(map[string]string),
	}

	var rest []string

	switch {
	case strings.HasPrefix(first, "-"):
		// Negative feedback: "-<cmdId> <error>". The id is the command being
		// rejected, so the rest of the line carries the error, not this one.
		cmd.Params["flag"] = first[1:]
		rest = parts[1:]
	case strings.Contains(first, "="):
		// A response row — the whole line is data, so take it from the first token.
		rest = parts
	default:
		cmd.Name = first
		rest = parts[1:]
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

func Unescape(s string) string {
	return unescaper.Replace(s)
}
