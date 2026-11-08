// Package request lets the SDK's own transports build and encode a
// teamspeak.Request, which keeps both out of the public API: a caller builds
// requests only through the typed commands, and the encoding is the
// transport's business.
//
// Package teamspeak installs the functions as it is initialised, so they are
// set before any importer of it runs. They traffic in any because this package
// cannot import teamspeak, which imports it.
package request

var (
	// New returns a teamspeak.Request for command, with params sent in order.
	New func(command string, params [][2]string) any
	// NewList returns a teamspeak.Request for command whose one parameter is a
	// list: key=value once per value, separated by pipes. An empty list is
	// refused when the request is sent.
	NewList func(command, key string, values []string) any
	// NewRowed returns a teamspeak.Request for command that takes several rows:
	// params are the first row, each of rest a row after it, and passwords names
	// the parameters of the first row that carry a channel password; with no rest
	// it is one row. A command such as s3ft_getpresignedurl reads its channel
	// from the first row and each file from a row of its own.
	NewRowed func(command string, params [][2]string, passwords []string, rest [][][2]string) any
	// Encode renders a teamspeak.Request as a command line, with
	// encodePassword as the transport's rule for password parameters.
	Encode func(req any, encodePassword func(password string) string) string
)
