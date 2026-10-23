package serverquery

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// keepAliveServer answers every command on a pipe, the way a ServerQuery
// session does, and counts the `version` commands it is sent.
func keepAliveServer(t *testing.T) (TCPOptions, *atomic.Int32) {
	t.Helper()
	var versions atomic.Int32
	dial := func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			_, _ = server.Write([]byte("TS3\n\rWelcome\n\r"))
			scanner := bufio.NewScanner(server)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				if line == "version" {
					versions.Add(1)
					_, _ = server.Write([]byte("version=3.13.8 build=1 platform=Linux\n\r"))
				}
				_, _ = server.Write([]byte("error id=0 msg=ok\n\r"))
				if line == "quit" {
					return
				}
			}
		}()

		return client, nil
	}

	return TCPOptions{Dial: dial}, &versions
}

// A TCP session is kept open with `version` once it has been idle for the
// interval: the server closes one that sent no command for 300 seconds.
func TestKeepAlive_SendsVersionWhileIdle(t *testing.T) {
	opts, versions := keepAliveServer(t)
	c, err := New(TCPWith("x:1", opts), WithoutEvents(), WithKeepAlive(40*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := versions.Load(); got != 1 {
		t.Fatalf("versions after connecting = %d, want 1", got)
	}
	time.Sleep(250 * time.Millisecond)
	if got := versions.Load(); got < 3 {
		t.Errorf("versions after 250ms idle = %d, want at least 3", got)
	}
	_ = c.Disconnect(t.Context())
	after := versions.Load()
	time.Sleep(120 * time.Millisecond)
	if got := versions.Load(); got != after {
		t.Errorf("a keep-alive was sent after Disconnect: %d, was %d", got, after)
	}
}

// A busy client sends nothing extra, and WithKeepAlive(0) sends nothing.
func TestKeepAlive_BusyAndOff(t *testing.T) {
	opts, versions := keepAliveServer(t)
	busy, err := New(TCPWith("x:1", opts), WithoutEvents(), WithKeepAlive(80*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	err = busy.Connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for range 12 {
		_, err = busy.Exec(t.Context(), "whoami")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := versions.Load(); got != 1 {
		t.Errorf("versions while busy = %d, want only the connect's", got)
	}
	_ = busy.Disconnect(t.Context())

	opts, versions = keepAliveServer(t)
	off, err := New(TCPWith("x:1", opts), WithoutEvents(), WithKeepAlive(0))
	if err != nil {
		t.Fatal(err)
	}
	err = off.Connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := versions.Load(); got != 1 {
		t.Errorf("versions with the keep-alive off = %d, want 1", got)
	}
	_ = off.Disconnect(t.Context())

	_, err = New(TCPWith("x:1", opts), WithKeepAlive(-time.Second))
	if err == nil {
		t.Error("a negative interval was accepted")
	}
}
