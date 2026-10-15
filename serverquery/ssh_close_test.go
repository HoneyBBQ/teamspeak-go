package serverquery

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

const testSSHPassword = "pw"

var (
	errBadPassword      = errors.New("wrong password")
	errUnexpectedKey    = errors.New("not the test server's host key")
	errConnectionLeaked = errors.New("the connection is still open")
)

// sshTestServer is an SSH server that speaks just enough ServerQuery to
// connect, answer a few commands and quit. It ends a session the way a server
// that keeps its connection open does: on quit it closes the shell's channel
// and leaves the TCP connection to the client, which is the case a live
// TeamSpeak does not exercise, since it hangs up the whole connection.
type sshTestServer struct {
	listener net.Listener
	hostKey  ssh.PublicKey
	// connGone is closed when the client's connection has ended, however it
	// ended: the client closing it, or the server dropping it.
	connGone chan struct{}
	conns    []*ssh.ServerConn
	wg       sync.WaitGroup
	mu       sync.Mutex
	goneOnce sync.Once
	stopOnce sync.Once
}

func startSSHServer(t *testing.T) *sshTestServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != testSSHPassword {
				return nil, errBadPassword
			}

			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &sshTestServer{listener: listener, hostKey: signer.PublicKey(), connGone: make(chan struct{})}
	s.wg.Add(1)
	go s.accept(config)
	t.Cleanup(s.stop)

	return s
}

func (s *sshTestServer) addr() string { return s.listener.Addr().String() }

// stop closes the listener and every connection, and waits for the server's
// goroutines, so that what is left running afterwards is the client's.
func (s *sshTestServer) stop() {
	s.stopOnce.Do(func() {
		_ = s.listener.Close()
		s.mu.Lock()
		for _, conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func (s *sshTestServer) accept(config *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.serve(conn, config)
	}
}

func (s *sshTestServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer s.wg.Done()
	sconn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()

		return
	}
	s.mu.Lock()
	s.conns = append(s.conns, sconn)
	s.mu.Unlock()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "sessions only")

			continue
		}
		channel, sessionRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go s.session(channel, sessionRequests)
	}
	// The channel list ends with the connection.
	s.goneOnce.Do(func() { close(s.connGone) })
}

func (s *sshTestServer) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer s.wg.Done()
	for request := range requests {
		isShell := request.Type == "shell"
		_ = request.Reply(isShell, nil)
		if isShell {
			s.wg.Add(1)
			go s.shell(channel)
		}
	}
}

func (s *sshTestServer) shell(channel ssh.Channel) {
	defer s.wg.Done()
	_, _ = channel.Write([]byte("TS3\n\rWelcome to the TeamSpeak 3 ServerQuery interface.\n\r"))
	reader := bufio.NewReader(channel)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if !answer(channel, strings.TrimSpace(line)) {
			return
		}
	}
}

// answer replies to one command and reports whether the session goes on. quit
// closes the shell's channel and nothing else.
func answer(channel ssh.Channel, line string) bool {
	name, _, _ := strings.Cut(line, " ")
	reply := "error id=0 msg=ok\n\r"
	switch name {
	case "version":
		reply = "version=6.0.0-beta13.1 build=1 platform=Linux\n\r" + reply
	case "whoami":
		reply = "client_id=7 client_nickname=bot\n\r" + reply
	case "clientlist":
		reply = "clid=7 client_nickname=bot client_servergroups=6\n\r" + reply
	}
	_, _ = channel.Write([]byte(reply))
	if name == "quit" {
		_ = channel.Close()

		return false
	}

	return true
}

// connectedClient is a query client connected to server, checking its host key
// against the server's, so the whole path a real connection takes is run.
func connectedClient(t *testing.T, server *sshTestServer) *Client {
	t.Helper()
	check := func(key HostKey) error {
		if key.Fingerprint != ssh.FingerprintSHA256(server.hostKey) {
			return errUnexpectedKey
		}

		return nil
	}
	c, err := New(SSHWith(server.addr(), "serveradmin", testSSHPassword, SSHOptions{HostKeyCheck: check}),
		WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return c
}

// requireClosed fails the test unless the client's connection has ended within
// a few seconds, saying what had just happened to it.
func requireClosed(t *testing.T, gone <-chan struct{}, after string) {
	t.Helper()
	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Errorf("%v after %s", errConnectionLeaked, after)
	}
}

// requireGoroutinesAtMost waits for the process to settle to want goroutines
// or fewer, and fails with the stacks of what is left if it does not.
func requireGoroutinesAtMost(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > want {
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<16)
			stacks = stacks[:runtime.Stack(stacks, true)]
			t.Errorf("%d goroutines left, want at most %d:\n%s", runtime.NumGoroutine(), want, stacks)

			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireDisconnected waits for the client to notice that the connection is
// gone and report it.
func requireDisconnected(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for c.Status() != teamspeak.StatusDisconnected {
		if time.Now().After(deadline) {
			t.Fatalf("status = %v, want disconnected", c.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Disconnect releases the connection it made: the socket is closed and the
// goroutines that served it exit. The server here ends the shell on quit and
// keeps the connection open, so nothing but the client can close it.
func TestSSH_DisconnectReleasesTheConnection(t *testing.T) {
	baseline := runtime.NumGoroutine()
	server := startSSHServer(t)
	c := connectedClient(t, server)

	_, err := c.GetVersion(t.Context())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	err = c.Disconnect(t.Context())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	requireClosed(t, server.connGone, "Disconnect")
	server.stop()
	requireGoroutinesAtMost(t, baseline)
}

// A server that ends the session on its own, without the client asking, leaves
// the client holding an SSH connection nobody will use. The client notices the
// end and has to release it itself: no Disconnect is coming to do it.
func TestSSH_ReleasesTheConnectionWhenTheServerEndsTheSession(t *testing.T) {
	baseline := runtime.NumGoroutine()
	server := startSSHServer(t)
	c := connectedClient(t, server)

	_, err := c.Exec(t.Context(), "quit")
	if err != nil {
		t.Fatalf("quit: %v", err)
	}
	requireDisconnected(t, c)

	requireClosed(t, server.connGone, "the server ended the session")
	server.stop()
	requireGoroutinesAtMost(t, baseline)
}
