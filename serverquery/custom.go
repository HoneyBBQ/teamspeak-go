package serverquery

import (
	"context"
	"fmt"

	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// Transport is a ServerQuery connection a caller supplies through [Custom]: a
// tunnel, a proxy, an in-memory pipe, or another carrier of the line protocol.
// It moves lines and knows nothing of the protocol above them.
//
// The client sends one command at a time and reads each answer to its end, so
// a Transport needs no locking of its own beyond what the three methods are
// called from: WriteLine from one goroutine at a time, ReadLine from one
// goroutine that runs until the connection ends, and Close from any.
//
// Experimental: this package may change in a minor release.
type Transport interface {
	// WriteLine sends one command line; the transport adds the terminator. The
	// line is already escaped, as the protocol writes it. ctx ends the wait for
	// the write.
	WriteLine(ctx context.Context, line string) error
	// ReadLine returns the next line the server sent, without its
	// terminator, in the order received, notifications included, each answer
	// ending with its `error id=… msg=…` line. A greeting the server opens a
	// connection with is the transport's to consume. Any error ends the
	// connection, and after Close it must return one.
	ReadLine() (string, error)
	// Close ends the connection. It may be called more than once.
	Close() error
}

// Custom returns a Dialer that connects through a [Transport] of the caller's
// own. open is called for every connection, the first and each reconnect, and
// must return a transport that is ready for commands.
//
// The client adds nothing beneath the line protocol. It sends no login: a
// transport that needs one has done it, or the caller runs [Client.Login] after
// Connect. It registers for notifications like the raw and SSH transports, so
// pass [WithoutEvents] for a carrier that cannot deliver them. Disconnect sends
// `quit`, best effort, before it closes the transport. A transport that is
// not a raw or SSH session, and answers each command on its own, can ignore
// `quit`.
//
// The keep-alive of [WithKeepAlive], and the byte counts of [Client.Stats], are
// not part of a [Transport]: a custom transport is never sent the keep-alive,
// and Stats reports the zero value for it.
//
// An open that returns an error ends the attempt with an error wrapping both
// [ErrDial] and its own. [New] refuses a nil open with [ErrInvalidConfig].
//
// Experimental: this package may change in a minor release.
func Custom(open func(ctx context.Context) (Transport, error)) Dialer {
	return customDialer{connect: open}
}

// customDialer is the dialer [Custom] returns.
type customDialer struct {
	connect func(ctx context.Context) (Transport, error)
}

// SupportsNotifications reports true: a line transport carries what the server
// sends, notifications among it. WithoutEvents opts out of registering.
func (d customDialer) SupportsNotifications() bool { return true }

func (d customDialer) String() string { return "custom transport" }

func (d customDialer) credentials() *login { return nil }

func (d customDialer) needsQuit() bool { return true }

func (d customDialer) validate() error {
	if d.connect == nil {
		return fmt.Errorf("%w: Custom needs an open function", ErrInvalidConfig)
	}

	return nil
}

func (d customDialer) open(ctx context.Context) (engine.Transport, error) {
	transport, err := d.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: custom transport: %w", ErrDial, err)
	}
	if transport == nil {
		return nil, fmt.Errorf("%w: custom transport: the open function returned no transport", ErrDial)
	}

	return transport, nil
}
