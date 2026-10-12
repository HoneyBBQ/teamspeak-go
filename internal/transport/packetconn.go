package transport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
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
	closed atomic.Bool
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
// application still owns. Instead Close sets pc's read deadline to now, which
// unblocks a Read in progress, and every later Read returns net.ErrClosed, so
// no reader outlives the adapter. pc must therefore honour SetReadDeadline.
//
// A new adapter clears pc's read deadline, so pc can serve one adapter after
// another; the caller must let the previous adapter's reader stop first (see
// PacketHandler.WaitReaderStopped), or the two would read the same datagrams.
func NewPacketConnAdapter(pc net.PacketConn, remote net.Addr) io.ReadWriteCloser {
	_ = pc.SetReadDeadline(time.Time{})

	return &packetConnAdapter{pc: pc, remote: remote}
}

func (a *packetConnAdapter) Read(p []byte) (int, error) {
	if a.closed.Load() {
		return 0, net.ErrClosed
	}
	n, _, err := a.pc.ReadFrom(p)
	if a.closed.Load() {
		return 0, net.ErrClosed
	}

	return n, err
}

func (a *packetConnAdapter) Write(p []byte) (int, error) {
	if a.remote == nil {
		return 0, errNoRemoteAddress
	}

	return a.pc.WriteTo(p, a.remote)
}

// Close stops the adapter's reader without closing pc.
func (a *packetConnAdapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	return a.pc.SetReadDeadline(time.Now())
}
