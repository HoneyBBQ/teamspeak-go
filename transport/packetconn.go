package transport

import (
	"errors"
	"io"
	"net"
	"time"
)

var errNoRemoteAddress = errors.New("packet conn adapter has no remote address")

// packetConnAdapter gives a net.PacketConn the io.ReadWriteCloser shape the
// handler expects: one datagram per Read and Write.
//
// The handler's contract is "each Write produces one discrete message", which
// is what PacketConn already does — it just spells the operations ReadFrom and
// WriteTo because a PacketConn is unconnected and may serve many peers. The
// session talks to one peer only, so the addresses are ignored.
type packetConnAdapter struct {
	pc     net.PacketConn
	remote net.Addr
}

// PacketConnWriter is the write half of the adapter, useful to callers that
// only need to send.
type PacketConnWriter interface {
	Write(p []byte) (int, error)
}

// NewPacketConnAdapter exposes pc as an io.ReadWriteCloser of datagrams,
// sending to remote.
//
// Closing the adapter does not close pc: the caller supplied it and may be
// using it for other traffic, so it is the caller's to close. The handler
// closes what it was given on disconnect, which must not tear down a socket the
// application still owns.
func NewPacketConnAdapter(pc net.PacketConn, remote net.Addr) io.ReadWriteCloser {
	return &packetConnAdapter{pc: pc, remote: remote}
}

func (a *packetConnAdapter) Read(p []byte) (int, error) {
	n, _, err := a.pc.ReadFrom(p)

	return n, err
}

func (a *packetConnAdapter) Write(p []byte) (int, error) {
	if a.remote == nil {
		return 0, errNoRemoteAddress
	}

	return a.pc.WriteTo(p, a.remote)
}

func (a *packetConnAdapter) Close() error {
	return nil
}

// SetReadDeadline is used by the handler's ping loop.
func (a *packetConnAdapter) SetReadDeadline(t time.Time) error {
	return a.pc.SetReadDeadline(t)
}
