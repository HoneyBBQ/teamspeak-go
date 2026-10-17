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

// SSHOptions are the seam [SSHWith] leaves open, and the host key policy it
// requires.
//
// Experimental: this package may change in a minor release.
type SSHOptions struct {
	// Open connects to addr in place of the built-in dial. It is where an
	// already-connected client, a jump host, or a test double goes; the
	// transport asks the connection only for a shell.
	//
	// The handshake happened inside the connection Open returned, so the
	// transport never sees the host key, and whoever made the connection is the
	// one who can check it. Setting HostKeyCheck as well would be a check that
	// never runs, which reads as a verified server and is not one, so New
	// refuses the combination with ErrInvalidConfig.
	//
	// A connection opened here is closed by the transport. A refused login
	// should be reported wrapping ErrAuth, which is what the built-in dial
	// does.
	Open func(ctx context.Context, addr string) (SSHConn, error)
	// HostKeyCheck decides whether the server is the one expected, before the
	// login is sent. See [HostKey] for what it is given.
	//
	// It has to be set when the transport dials, and must not be set when Open
	// supplies the connection: in the first case the dial would otherwise
	// trust whatever answers the port, and in the second the check could never
	// run. New refuses either with ErrInvalidConfig. [KnownHosts] checks
	// against a known_hosts file and [InsecureIgnoreHostKey] accepts anything,
	// which the name says out loud.
	HostKeyCheck func(HostKey) error
}

// sshDialer is ServerQuery inside an SSH shell. The SSH login is the query
// login, so the session is already the query account when it opens, and only
// `use` is left. Only TeamSpeak 6 serves it, and off by default.
type sshDialer struct {
	conn         func(ctx context.Context, addr string) (SSHConn, error)
	hostKeyCheck func(HostKey) error
	addr         string
	user         string
	password     string
	// guest reports a login as the server's guest user, with no password.
	guest bool
	// ownDial reports whether conn is the built-in dial, which is what has to
	// check a host key. A connection the caller opened is the caller's to
	// check, and the transport never sees its key.
	ownDial bool
}

// SSH returns a Dialer for ServerQuery over SSH at addr, a host:port such as
// "127.0.0.1:10022", logging in as user with password.
//
// The password is the SSH login's, not a query login sent as a command: over
// this transport no query password goes over the wire at all. [WithLogin] is
// refused here.
//
// A TeamSpeak 6 server may hold back the end of a reply until the client writes
// again; this transport handles that itself, by writing an empty line while a
// command waits.
//
// The host key has to be checked, and this constructor takes no policy for it,
// so it always produces a dialer that [New] refuses. Use [SSHWith] with
// [KnownHosts], [InsecureIgnoreHostKey], or [SSHOptions.HostKeyCheck]:
//
//	check, err := serverquery.KnownHosts(filepath.Join(home, ".ssh", "known_hosts"))
//	if err != nil { ... }
//	d := serverquery.SSHWith("127.0.0.1:10022", "serveradmin", password,
//		serverquery.SSHOptions{HostKeyCheck: check})
//
// The check runs before the login, so a server that is not the one expected
// never sees the password. Accepting any key instead — InsecureIgnoreHostKey —
// hands the query account, normally serveradmin, to whoever answers the port.
//
// Experimental: this package may change in a minor release.
func SSH(addr, user, password string) Dialer {
	return SSHWith(addr, user, password, SSHOptions{})
}

// guestUser is the SSH user name TeamSpeak 6 serves its guest ServerQuery
// access under, and the one name [SSH] refuses, so that a guest connection is
// only ever the one [SSHGuest] asks for.
const guestUser = "guest"

// SSHGuest returns a Dialer for ServerQuery over SSH at addr that connects as
// the server's guest user, which takes no password: the access is that of the
// Guest ServerQuery group, whose permissions the server's administrator
// controls, and a session can still raise it by sending `login`.
//
// TeamSpeak 6 beta13 and later serve it, and it is on unless the server was
// started with --query-ssh-allow-guest=0 (or TSSERVER_QUERY_SSH_ALLOW_GUEST=0),
// so a refused login is reported wrapping [ErrAuth]. Guest access is an
// explicit choice made by calling this: [SSH] and [SSHWith] refuse an empty
// user, an empty password and the user name "guest" with [ErrInvalidConfig],
// so a missing credential never turns into a guest connection unnoticed.
//
// The host key policy applies exactly as it does to [SSH]: this constructor
// takes none, so it always produces a dialer that [New] refuses. Use
// [SSHGuestWith].
//
// Experimental: this package may change in a minor release.
func SSHGuest(addr string) Dialer {
	return SSHGuestWith(addr, SSHOptions{})
}

// SSHGuestWith returns a guest SSH dialer with options applied; see [SSHGuest]
// and [SSHWith]. The host key policy is required in the same way.
//
// Experimental: this package may change in a minor release.
func SSHGuestWith(addr string, options SSHOptions) Dialer {
	d := newSSHDialer(addr, guestUser, "", options)
	d.guest = true

	return d
}

// SSHWith returns an SSH dialer with options applied. It needs exactly one way
// to know the server: HostKeyCheck, for a connection this package dials, or
// Open, for one made elsewhere, whose caller checks the key. New returns
// ErrInvalidConfig for neither and for both.
//
// Experimental: this package may change in a minor release.
func SSHWith(addr, user, password string, options SSHOptions) Dialer {
	return newSSHDialer(addr, user, password, options)
}

func newSSHDialer(addr, user, password string, options SSHOptions) sshDialer {
	d := sshDialer{
		addr:         addr,
		user:         user,
		password:     password,
		conn:         options.Open,
		hostKeyCheck: options.HostKeyCheck,
		ownDial:      options.Open == nil,
	}
	if d.conn == nil {
		d.conn = d.dial
	}

	return d
}

// SupportsNotifications reports that the server can push notifications over
// this connection.
func (d sshDialer) SupportsNotifications() bool { return true }

func (d sshDialer) String() string { return "ssh " + d.user + "@" + d.addr }

// credentialError refuses a login that is not a complete account login, naming
// SSHGuest for the case where a guest is what was meant.
func (d sshDialer) credentialError() error {
	switch {
	case d.guest:
		return nil
	case d.user == "":
		return fmt.Errorf("%w: the ssh dialer has no user; use SSHGuest to connect as the guest user",
			ErrInvalidConfig)
	case strings.EqualFold(d.user, guestUser):
		return fmt.Errorf("%w: %q is the server's guest user, which takes no password; "+
			"use SSHGuest to connect as a guest", ErrInvalidConfig, d.user)
	case d.password == "":
		return fmt.Errorf("%w: the ssh dialer has no password for %q; "+
			"use SSHGuest to connect as the guest user", ErrInvalidConfig, d.user)
	}

	return nil
}

// needsLogin reports that the query login is not a command here: SSH logged in
// already.
func (d sshDialer) needsLogin() bool { return false }

// needsQuit reports that the session ends with a `quit` command. The session
// is a shell, so quitting closes it as ending the connection would.
func (d sshDialer) needsQuit() bool { return true }

// validate refuses a host key policy that is missing or that could not run,
// naming what to do about it.
//
// A transport that dials for the caller must not accept whatever answers the
// port, and must not go looking for a policy of its own: a library does not
// read ~/.ssh/known_hosts unasked any more than it accepts anything. And a
// policy given alongside Open is a security option that is silently ignored,
// since the connection Open returns has already done its handshake: whoever
// set both believes the key is being checked when it is not.
func (d sshDialer) validate() error {
	err := d.credentialError()
	if err != nil {
		return err
	}
	switch {
	case d.ownDial && d.hostKeyCheck == nil:
		return fmt.Errorf("%w: the ssh dialer checks the host key before it logs in, and "+
			"none of SSHOptions.HostKeyCheck, KnownHosts(...) or InsecureIgnoreHostKey() was given",
			ErrInvalidConfig)
	case !d.ownDial && d.hostKeyCheck != nil:
		return fmt.Errorf("%w: SSHOptions.HostKeyCheck and SSHOptions.Open are both set, but the "+
			"connection Open returns has already made its handshake, so the transport never sees the "+
			"host key and the check would never run; check the key where the connection is made",
			ErrInvalidConfig)
	}

	return nil
}

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

	return &nudgingStream{newStream(shell.Stdout(), streamOptions{
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
	})}, nil
}

// nudgingStream is an SSH stream that can release a held reply. See
// [engine.Nudger] for what the server does and why only SSH.
type nudgingStream struct {
	*stream
}

// Nudge writes a bare line terminator. The server answers an empty line with
// nothing, so it adds no reply line.
func (s *nudgingStream) Nudge() error {
	return s.WriteLine(context.Background(), "")
}

// dial is the built-in opener: one SSH connection to addr, logging in as the
// configured user.
func (d sshDialer) dial(ctx context.Context, addr string) (SSHConn, error) {
	config := &ssh.ClientConfig{
		User: d.user,
		// The library tries the "none" method before the password, which is
		// what the server takes a guest with; the empty password that follows
		// is for a server that asks for one first.
		Auth: []ssh.AuthMethod{ssh.Password(d.password)},
		// The caller's policy, converted: this is the only place the library's
		// callback type is named, and validate has already refused a dialer
		// without one.
		HostKeyCallback: hostKeyCallback(addr, d.hostKeyCheck),
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
