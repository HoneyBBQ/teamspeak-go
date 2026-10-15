package serverquery

import (
	"errors"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// The errors this package reports beyond the ones every client shares. A
// refusal from the server is a *teamspeak.ServerError, as it is for the voice
// client; these are the ones a connection can fail with before any command is
// answered.

// ErrInvalidConfig reports a client [New] cannot build as configured, such as
// no dialer, a login over a transport that has none, or events asked for over
// a transport that cannot deliver them.
var ErrInvalidConfig = errors.New("invalid query client configuration")

// ErrDial reports a connection that could not be opened: a refused TCP
// connection, an SSH failure that is not authentication, or a WebQuery the
// request could not reach. The cause is wrapped, so errors.Is still matches
// what the transport reported.
var ErrDial = errors.New("could not open the query connection")

// ErrAuth reports an SSH login the server refused.
//
// x/crypto/ssh reports a refused login as an untyped error whose text says
// "unable to authenticate", so that text is the only thing there is to match
// on; the package has no exported error for it. The wrapped cause is the
// library's own error.
var ErrAuth = errors.New("the query login was refused")

// ErrHostKey reports an SSH server whose host key was not accepted: the check
// failed, the key could not be read, or no check was given at all.
//
// A host that is not in the known_hosts file and a host whose key has changed
// both wrap it; the wrapped error says which, so an unknown host is not
// mistaken for an attack, nor the other way round.
var ErrHostKey = errors.New("the ssh host key was not accepted")

// ErrMissingDependency reports a transport whose dependency was left out of
// the build. It is teamspeak.ErrMissingDependency, so a caller matching either
// name matches both.
var ErrMissingDependency = teamspeak.ErrMissingDependency

// Why a connect or a command failed, when it is not the server's own answer.
var (
	// errEmptyCommand is a command line with no command in it.
	errEmptyCommand = errors.New("empty command line")
	// errInvalidUse is a `use` naming neither a server nor a port.
	errInvalidUse = errors.New("use takes a sid or a port")
	// errStopped ends a reconnect attempt that finds Disconnect already called.
	errStopped = errors.New("the client was disconnected")
)
