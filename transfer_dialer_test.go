package teamspeak_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go"
)

// dialerFunc adapts a function to teamspeak.FileTransferDialer.
type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// pipeDialer hands out one end of a pipe and returns the other, standing in
// for the file transfer server.
func pipeDialer(t *testing.T) (teamspeak.FileTransferDialer, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	return dialerFunc(func(context.Context, string, string) (net.Conn, error) { return client, nil }), server
}

// The transfer dialer is the seam for routing file transfers through a proxy.
// It has to be used rather than merely accepted: without it the SDK always
// dials its own connection.
func TestDialFileTransfer_UsesTheSuppliedDialer(t *testing.T) {
	var asked []string

	// A pipe stands in for a real connection; nil error with a live conn means
	// the caller proceeds to the ftkey write.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
	}()

	dialer := dialerFunc(func(_ context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, network+" "+addr)

		return client, nil
	})

	conn, err := teamspeak.DialFileTransfer(t.Context(), "transfer.example", 30033, "the-key", viaDialer(dialer))
	if err != nil {
		t.Fatalf("DialFileTransfer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if len(asked) != 1 || asked[0] != "tcp transfer.example:30033" {
		t.Errorf("dialer asked for %v, want [tcp transfer.example:30033]", asked)
	}
}

// A net.Dialer is a FileTransferDialer as it is, so a caller configuring one
// (a local address, a keep-alive) needs no adapter.
var _ teamspeak.FileTransferDialer = (*net.Dialer)(nil)

func TestDialFileTransfer_ReportsADialFailure(t *testing.T) {
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.AddrError{Err: "no route to host", Addr: "transfer.example:30033"}
	})

	_, err := teamspeak.DialFileTransfer(t.Context(), "transfer.example", 30033, "k", viaDialer(dialer))
	if err == nil {
		t.Fatal("expected a dial error")
	}
}

// The dial is the step most likely to hang — a port nobody answers — so it is
// the one the caller's deadline has to reach.
func TestDialFileTransfer_RespectsTheDeadline(t *testing.T) {
	dialer := dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("dialer got a context with no deadline")
		}
		<-ctx.Done()

		return nil, ctx.Err()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := teamspeak.DialFileTransfer(ctx, "transfer.example", 30033, "k", viaDialer(dialer))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("dial took %v after a 20ms deadline", elapsed)
	}
}

// The default dialer has to honour the deadline too, not only a supplied one.
func TestDialFileTransfer_DefaultDialerRespectsTheDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := teamspeak.DialFileTransfer(ctx, "127.0.0.1", 9, "k", teamspeak.FileTransferOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestDownloadFileData_StopsWhenCancelled(t *testing.T) {
	dialer, server := pipeDialer(t)
	ctx, cancel := context.WithCancel(t.Context())

	// The server takes the key, sends part of the file, then stalls.
	go func() {
		key := make([]byte, len("key"))
		_, _ = io.ReadFull(server, key)
		_, _ = server.Write([]byte("partial"))
		cancel()
	}()

	var got bytes.Buffer
	info := &teamspeak.FileDownloadInfo{FileTransferKey: "key", Port: 30033, Size: 1 << 20}
	err := teamspeak.DownloadFileData(ctx, "transfer.example", info, &got, viaDialer(dialer))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got.String() != "partial" {
		t.Errorf("dest = %q, want what arrived before the cancel", got.String())
	}
}

func TestUploadFileData_StopsWhenCancelled(t *testing.T) {
	dialer, server := pipeDialer(t)
	ctx, cancel := context.WithCancel(t.Context())

	// The server takes the key and some data, then stops reading, so the
	// upload blocks in Write until the cancel closes the connection.
	go func() {
		buf := make([]byte, 16)
		_, _ = io.ReadFull(server, buf)
		cancel()
	}()

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 30033}
	data := bytes.NewReader(make([]byte, 1<<20))
	err := teamspeak.UploadFileData(ctx, "transfer.example", info, data, viaDialer(dialer))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestDownloadFileData_ReadsUntilTheServerCloses(t *testing.T) {
	dialer, server := pipeDialer(t)

	go func() {
		key := make([]byte, len("key"))
		_, _ = io.ReadFull(server, key)
		_, _ = server.Write([]byte("whole file"))
		_ = server.Close()
	}()

	var got bytes.Buffer
	info := &teamspeak.FileDownloadInfo{FileTransferKey: "key", Port: 30033, Size: 10}
	err := teamspeak.DownloadFileData(t.Context(), "transfer.example", info, &got, viaDialer(dialer))
	if err != nil {
		t.Fatalf("DownloadFileData: %v", err)
	}
	if got.String() != "whole file" {
		t.Errorf("dest = %q, want %q", got.String(), "whole file")
	}
}

func viaDialer(d teamspeak.FileTransferDialer) teamspeak.FileTransferOptions {
	return teamspeak.FileTransferOptions{Dialer: d}
}
