package serverquery

import (
	"context"

	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// Dialer opens the connection a query client talks over. Build one with [TCP],
// [SSH] or [Web]; the interface is sealed, so a transport cannot be supplied
// from outside this package.
//
// A Dialer is a description rather than a connection: it holds where to
// connect and who to log in as, and opens a fresh connection every time, which
// is what reconnection needs. A client reuses one for the life of the client.
type Dialer interface {
	// SupportsNotifications reports whether the server can push notifications
	// over this connection. Raw TCP and SSH can; WebQuery has no session for
	// the server to push to, so it cannot.
	SupportsNotifications() bool
	// String names the transport and where it points, for a log line. It
	// never includes a password.
	String() string
	// credentials returns the query login to send as a command once the
	// connection is open, or nil for none. Only the raw protocol has one: SSH
	// logs in as the query account and WebQuery's api key is the login.
	credentials() *login
	// needsQuit reports whether the session ends with a `quit` command. The
	// transports that hold a session have one; WebQuery, which has none, is
	// refused it.
	needsQuit() bool
	// validate reports a dialer that cannot be used as configured, before
	// anything is dialled. The SSH dialer refuses to connect with no host key
	// policy; the others have nothing to refuse.
	validate() error
	// open connects and starts the session, returning the transport the
	// engine runs commands over.
	open(ctx context.Context) (engine.Transport, error)
}
