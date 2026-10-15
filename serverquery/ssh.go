package serverquery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	engine "github.com/honeybbq/teamspeak-go/internal/serverquery"
)

// SSHShell is the shell a ServerQuery session runs on, narrowed to what the
// transport needs. A caller supplying its own connection implements it over
// whatever it has: *ssh.Session satisfies it through the adapter below, and so
// does a test double.
//
// Experimental: this package may change in a minor release.
type SSHShell interface {
	// Stdin carries command lines to the server.
	Stdin() io.Writer
	// Stdout carries the server's lines back.
	Stdout() io.Reader
	// Close ends the shell.
	Close() error
}

// SSHConn is an open SSH connection, narrowed to what the transport needs.
// *ssh.Client satisfies it through the adapter below.
//
// Experimental: this package may change in a minor release.
type SSHConn interface {
	// Shell starts a shell session on the connection.
	Shell() (SSHShell, error)
	// Close ends the connection.
	Close() error
}

// SSHOptions are the seam [SSHWith] leaves open. The zero value is what [SSH]
// does.
//
// Experimental: this package may change in a minor release.
type SSHOptions struct {
	// Open connects to addr in place of the built-in dial. It is where an
	// already-connected client, a jump host, or a test double goes; the
	// transport asks the connection only for a shell.
	//
	// A connection opened here is closed by the transport. A refused login
	// should be reported wrapping ErrAuth, which is what the built-in dial
	// does.
	Open func(ctx context.Context, addr string) (SSHConn, error)
}

// sshDialer is ServerQuery inside an SSH shell. The SSH login is the query
// login, so the session is already the query account when it opens, and only
// `use` is left. Only TeamSpeak 6 serves it, and off by default.
type sshDialer struct {
	conn     func(ctx context.Context, addr string) (SSHConn, error)
	addr     string
	user     string
	password string
}

// SSH returns a Dialer for ServerQuery over SSH at addr, a host:port such as
// "127.0.0.1:10022", logging in as user with password.
//
// The password is the SSH login's, not a query login sent as a command: over
// this transport no query password goes over the wire at all. [WithLogin] is
// refused here.
//
// The server's host key is not verified, so this authenticates the client to
// the server and not the server to the client. Check the host key by other
// means, or tunnel the connection, if that matters for where this runs.
//
// Experimental: this package may change in a minor release.
func SSH(addr, user, password string) Dialer {
	return SSHWith(addr, user, password, SSHOptions{})
}

// SSHWith returns an SSH dialer with options applied; it is [SSH] when options
// is the zero value. Use it to supply a connection the transport does not dial
// itself, such as one through a jump host or a tunnel.
//
// Experimental: this package may change in a minor release.
func SSHWith(addr, user, password string, options SSHOptions) Dialer {
	d := sshDialer{addr: addr, user: user, password: password, conn: options.Open}
	if d.conn == nil {
		d.conn = d.dial
	}

	return d
}

// SupportsNotifications reports that the server can push notifications over
// this connection.
func (d sshDialer) SupportsNotifications() bool { return true }

func (d sshDialer) String() string { return "ssh " + d.user + "@" + d.addr }

// needsLogin reports that the query login is not a command here: SSH logged in
// already.
func (d sshDialer) needsLogin() bool { return false }

// needsQuit reports that the session ends with a `quit` command. The session
// is a shell, so quitting closes it as ending the connection would.
func (d sshDialer) needsQuit() bool { return true }

func (d sshDialer) open(ctx context.Context) (engine.Transport, error) {
	conn, err := d.conn(ctx, d.addr)
	if err != nil {
		return nil, err
	}
	shell, err := conn.Shell()
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("%w: ssh %s: %w", ErrDial, d.addr, err)
	}

	closeAll := func() error {
		_ = shell.Close()
		err := conn.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}

		return err
	}

	return newStream(shell.Stdout(), streamOptions{
		banner: 2,
		identity: streamIdentity{
			transport: "ssh",
			address:   d.user + "@" + d.addr,
			opened:    time.Now(),
		},
		write: func(line string) error {
			_, err := io.WriteString(shell.Stdin(), line+"\n")

			return err
		},
		closeConn: closeAll,
	}), nil
}

// dial is the built-in opener: one SSH connection to addr, logging in as the
// configured user.
func (d sshDialer) dial(ctx context.Context, addr string) (SSHConn, error) {
	config := &ssh.ClientConfig{
		User:            d.user,
		Auth:            []ssh.AuthMethod{ssh.Password(d.password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // documented on SSH
	}
	client, err := dialSSH(ctx, addr, config)
	if err != nil {
		return nil, err
	}

	return sshConn{client: client}, nil
}

// sshConn adapts *ssh.Client to SSHConn, so no caller of this package has to
// name the library's own type.
type sshConn struct {
	client *ssh.Client
}

// Shell starts a shell session and resolves its two pipes, so the SSHShell it
// returns cannot fail part-way through being used.
func (c sshConn) Shell() (SSHShell, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()

		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()

		return nil, err
	}
	// A shell rather than a command: ServerQuery is a line protocol, and the
	// server answers each line as it arrives.
	err = session.Shell()
	if err != nil {
		_ = session.Close()

		return nil, err
	}

	return sshShell{session: session, stdin: stdin, stdout: stdout}, nil
}

func (c sshConn) Close() error { return c.client.Close() }

// sshShell adapts an *ssh.Session that has already been started.
type sshShell struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

func (s sshShell) Stdin() io.Writer  { return s.stdin }
func (s sshShell) Stdout() io.Reader { return s.stdout }
func (s sshShell) Close() error      { return s.session.Close() }

// dialSSH connects, closing the connection if ctx ends first. ssh.Dial has no
// context, so an attempt that outlives the caller's deadline is abandoned
// rather than waited out.
func dialSSH(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	type answer struct {
		client *ssh.Client
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		client, err := ssh.Dial("tcp", addr, config)
		answered <- answer{client: client, err: err}
	}()

	select {
	case a := <-answered:
		if a.err != nil {
			return nil, classifySSHError(addr, a.err)
		}

		return a.client, nil
	case <-ctx.Done():
		// The dial's own goroutine closes what it opens once it returns.
		go func() {
			if a := <-answered; a.client != nil {
				_ = a.client.Close()
			}
		}()

		return nil, fmt.Errorf("%w: ssh %s: %w", ErrDial, addr, ctx.Err())
	}
}

// classifySSHError turns what the library reported into this package's errors.
// A refused login arrives as a plain error whose text says so — the package
// exports no type for it — so the text is what there is to read.
func classifySSHError(addr string, err error) error {
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("%w: ssh %s: %w", ErrAuth, addr, err)
	}

	return fmt.Errorf("%w: ssh %s: %w", ErrDial, addr, err)
}
