// Package commands is the TeamSpeak command language: the names of the
// commands, and the escaping of their values. A command line is a name
// followed by key=value parameters, with values escaped so a space or a pipe
// cannot end them early. The voice protocol and ServerQuery share the format.
//
// It is what a caller of Exec needs to build a raw line by hand. Reading and
// building whole lines is the clients' own business.
package commands

import "github.com/honeybbq/teamspeak-go/internal/wire"

// Escape escapes a parameter value for a command line: a space becomes \s, a
// pipe \p, a slash \/, and so on, the escapes Unescape reverses.
func Escape(s string) string {
	return wire.Escape(s)
}

// Unescape reverses Escape.
func Unescape(s string) string {
	return wire.Unescape(s)
}
