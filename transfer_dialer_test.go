package teamspeak_test

import (
	"context"
	"net"
	"testing"

	"github.com/honeybbq/teamspeak-go"
)

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

	dialer := func(_ context.Context, addr string) (net.Conn, error) {
		asked = append(asked, addr)

		return client, nil
	}

	conn, err := teamspeak.DialFileTransfer("transfer.example", 30033, "the-key", dialer)
	if err != nil {
		t.Fatalf("DialFileTransfer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if len(asked) != 1 || asked[0] != "transfer.example:30033" {
		t.Errorf("dialer asked for %v, want [transfer.example:30033]", asked)
	}
}

func TestDialFileTransfer_ReportsADialFailure(t *testing.T) {
	dialer := func(_ context.Context, _ string) (net.Conn, error) {
		return nil, &net.AddrError{Err: "no route to host", Addr: "transfer.example:30033"}
	}

	_, err := teamspeak.DialFileTransfer("transfer.example", 30033, "k", dialer)
	if err == nil {
		t.Fatal("expected a dial error")
	}
}
