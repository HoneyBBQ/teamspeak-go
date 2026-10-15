package serverquery

import (
	"context"
	"fmt"
	"net"
	"time"

	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// TCPOptions are the seam [TCPWith] leaves open. The zero value is what [TCP]
// does, so a caller sets only what it needs.
//
// Experimental: this package may change in a minor release.
type TCPOptions struct {
	// Dial opens the byte stream in place of the direct dial. It is where a
	// proxy or a tunnel goes: the transport needs only a net.Conn, so anything
	// that answers one fits, and the socket is put in no-delay mode only when
	// it offers that.
	//
	// ctx bounds the dial; an implementation that ignores it leaves the
	// attempt running after a cancelled Connect.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
}

// tcpDialer is the raw ServerQuery protocol: a TCP connection that greets with
// two banner lines and then speaks the line protocol directly. Only TeamSpeak
// 3 serves it.
type tcpDialer struct {
	dial func(ctx context.Context, addr string) (net.Conn, error)
	addr string
}

// TCP returns a Dialer for the raw ServerQuery protocol at addr, a host:port
// such as "127.0.0.1:10011".
//
// It is TeamSpeak 3's transport: TeamSpeak 6 dropped raw ServerQuery for
// WebQuery and SSH. Unless the address is in the server's query allowlist, the
// session starts unauthenticated, so [WithLogin] is needed before any command
// that requires a query account.
//
// Experimental: this package may change in a minor release.
func TCP(addr string) Dialer {
	return TCPWith(addr, TCPOptions{})
}

// TCPWith returns a raw-protocol dialer with options applied; it is [TCP] when
// options is the zero value. Use it to reach the server through a proxy or a
// tunnel, or to drive the client from something that is not a socket.
//
// Experimental: this package may change in a minor release.
func TCPWith(addr string, options TCPOptions) Dialer {
	dial := options.Dial
	if dial == nil {
		dial = defaultTCPDial
	}

	return tcpDialer{addr: addr, dial: dial}
}

// defaultTCPDial dials addr directly, which is what TCP does without a Dial.
func defaultTCPDial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "tcp", addr)
}

// SupportsNotifications reports that the server can push notifications over
// this connection.
func (d tcpDialer) SupportsNotifications() bool { return true }

func (d tcpDialer) String() string { return "tcp " + d.addr }

// needsLogin reports that the query login is a command here.
func (d tcpDialer) needsLogin() bool { return true }

// needsQuit reports that the session ends with a `quit` command.
func (d tcpDialer) needsQuit() bool { return true }

// validate accepts the dialer: there is no host key to check over raw TCP, and
// no configuration it could be missing.
func (d tcpDialer) validate() error { return nil }

func (d tcpDialer) open(ctx context.Context) (engine.Transport, error) {
	conn, err := d.dial(ctx, d.addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDial, d.addr, err)
	}
	// Whole lines are sent and a query's answers are small, so there is
	// nothing to be gained by waiting to coalesce them. A connection from a
	// caller's own dialer need not be a TCP one, so this is offered rather
	// than assumed.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	return newStream(conn, streamOptions{
		banner: 2,
		identity: streamIdentity{
			transport: "tcp",
			address:   d.addr,
			opened:    time.Now(),
		},
		write: func(line string) error {
			_, err := conn.Write([]byte(line + "\n"))

			return err
		},
		closeConn: conn.Close,
	}), nil
}
