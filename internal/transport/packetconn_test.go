package transport_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
)

func listenPacket(t *testing.T) net.PacketConn {
	t.Helper()

	var lc net.ListenConfig

	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() {
		closeErr := pc.Close()
		if closeErr != nil {
			t.Errorf("close packet conn: %v", closeErr)
		}
	})

	return pc
}

func exchange(t *testing.T, conn transport.PacketConnWriter, server net.PacketConn, want string) {
	t.Helper()

	_, err := conn.Write([]byte(want))
	if err != nil {
		t.Fatalf("Write(%q): %v", want, err)
	}

	deadlineErr := server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if deadlineErr != nil {
		t.Fatalf("SetReadDeadline: %v", deadlineErr)
	}

	buf := make([]byte, 64)
	n, _, readErr := server.ReadFrom(buf)
	if readErr != nil {
		t.Fatalf("ReadFrom: %v", readErr)
	}
	if got := string(buf[:n]); got != want {
		t.Errorf("server received %q, want %q", got, want)
	}
}

// A net.PacketConn is unconnected and addresses every datagram; the handler
// wants a plain io.ReadWriteCloser. The adapter is what reconciles the two, so
// it has to preserve datagram boundaries in both directions.
func TestPacketConnAdapterPreservesDatagrams(t *testing.T) {
	server := listenPacket(t)
	client := listenPacket(t)

	remote, err := net.ResolveUDPAddr("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	conn := transport.NewPacketConnAdapter(client, remote)
	defer func() {
		closeErr := conn.Close()
		if closeErr != nil {
			t.Errorf("close adapter: %v", closeErr)
		}
	}()

	for _, want := range []string{"one", "two", "three"} {
		exchange(t, conn, server, want)
	}
}

func TestPacketConnAdapterReadsReplies(t *testing.T) {
	server := listenPacket(t)
	client := listenPacket(t)

	remote, err := net.ResolveUDPAddr("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	conn := transport.NewPacketConnAdapter(client, remote)
	defer func() { _ = conn.Close() }()

	_, err = server.WriteTo([]byte("reply"), client.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if got := string(buf[:n]); got != "reply" {
		t.Errorf("adapter read %q, want %q", got, "reply")
	}
}

func TestPacketConnAdapterWithoutRemoteFailsToWrite(t *testing.T) {
	pc := listenPacket(t)

	conn := transport.NewPacketConnAdapter(pc, nil)
	defer func() { _ = conn.Close() }()

	_, writeErr := conn.Write([]byte("x"))
	if writeErr == nil {
		t.Error("expected a write error without a remote address")
	}
}

// Closing an adapter unblocks its reader, without closing the PacketConn, so
// a second adapter on the same PacketConn is its only reader.
func TestPacketConnAdapterCloseUnblocksItsReader(t *testing.T) {
	server := listenPacket(t)
	pc := listenPacket(t)

	first := transport.NewPacketConnAdapter(pc, server.LocalAddr())
	readErr := make(chan error, 1)
	go func() {
		_, err := first.Read(make([]byte, 64))
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	closeErr := first.Close()
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Read after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the adapter's Read")
	}

	second := transport.NewPacketConnAdapter(pc, server.LocalAddr())
	_, err := server.WriteTo([]byte("for the second"), pc.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	n, err := second.Read(buf)
	if err != nil {
		t.Fatalf("second adapter Read: %v", err)
	}
	if got := string(buf[:n]); got != "for the second" {
		t.Errorf("second adapter read %q", got)
	}
}

// pc is unconnected, so anyone who can reach it can send to it; only the
// server's datagrams may reach the session.
func TestPacketConnAdapterDropsDatagramsFromOtherSources(t *testing.T) {
	server := listenPacket(t)
	stranger := listenPacket(t)
	client := listenPacket(t)

	remote, err := net.ResolveUDPAddr("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn := transport.NewPacketConnAdapter(client, remote)
	defer func() { _ = conn.Close() }()

	_, err = stranger.WriteTo([]byte("forged"), client.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let the stranger's datagram arrive first
	_, err = server.WriteTo([]byte("reply"), client.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if got := string(buf[:n]); got != "reply" {
		t.Errorf("adapter read %q, want only the server's %q", got, "reply")
	}
}
