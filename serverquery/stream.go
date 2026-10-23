package serverquery

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// streamOptions are what a byte-stream connection is built from.
type streamOptions struct {
	// write hands one command line to the connection, terminator added.
	write func(line string) error
	// closeConn ends the underlying connection; it is what stops the reader.
	closeConn func() error
	// identity names the connection for Stats.
	identity streamIdentity
	// maxLine is the longest line read, ErrLineTooLong beyond it. Zero is
	// maxLineBytes.
	maxLine int
	// banner is how many greeting lines are still to be skipped: the server
	// opens every stream with "TS3" and a welcome sentence.
	banner int
}

// maxLineBytes is the longest line a connection reads: 256 MiB. A line is a
// whole answer, and a client database listing is about 240 bytes a client, so
// this holds about a million of them; the permission list, the longest answer
// measured on TeamSpeak 3 and 6, is under 50 KiB. See [ErrLineTooLong].
const maxLineBytes = 256 << 20

// streamIdentity is what Stats reports about a connection beyond its counters.
type streamIdentity struct {
	opened    time.Time
	transport string
	address   string
}

// stream is a ServerQuery connection over a byte stream: raw TCP, or an SSH
// shell. It reads whole lines in a goroutine of its own and hands them to the
// engine one at a time.
//
// The server writes "\n\r" after each line, so the carriage return leads the
// next line rather than ending this one; both ends are trimmed. A line is
// decoded only once it is whole, so a character split across two reads arrives
// intact.
type stream struct {
	closeErr      error
	lines         chan string
	done          chan struct{}
	write         func(line string) error
	closeConn     func() error
	identity      streamIdentity
	banner        int
	maxLine       int
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	closeOnce     sync.Once
	mu            sync.Mutex
}

// newStream starts reading r with the options applied, which include the
// banner lines to skip and the identity Stats reports.
func newStream(r io.Reader, opts streamOptions) *stream {
	s := &stream{
		lines:     make(chan string, 64),
		done:      make(chan struct{}),
		banner:    opts.banner,
		write:     opts.write,
		closeConn: opts.closeConn,
		identity:  opts.identity,
		maxLine:   cmp.Or(opts.maxLine, maxLineBytes),
	}
	go s.readLoop(bufio.NewReader(r))

	return s
}

// WriteLine sends one command line; the transport adds the terminator.
func (s *stream) WriteLine(_ context.Context, line string) error {
	select {
	case <-s.done:
		return io.ErrClosedPipe
	default:
	}

	err := s.write(line)
	if err == nil {
		s.bytesSent.Add(uint64(len(line)) + 1)
	}

	return err
}

// ReadLine returns the next line the server sent, or an error once the
// connection has ended.
func (s *stream) ReadLine() (string, error) {
	select {
	case line := <-s.lines:
		return line, nil
	case <-s.done:
		s.mu.Lock()
		err := s.closeErr
		s.mu.Unlock()
		if err == nil {
			return "", io.EOF
		}

		return "", err
	}
}

// Close ends the connection. A line not yet delivered is dropped.
func (s *stream) Close() error {
	s.finish(nil)

	if s.closeConn != nil {
		return s.closeConn()
	}

	return nil
}

// stats reports the connection's identity and counters.
func (s *stream) stats() TransportStats {
	return TransportStats{
		Transport:     s.identity.transport,
		Address:       s.identity.address,
		ConnectedAt:   s.identity.opened,
		BytesSent:     s.bytesSent.Load(),
		BytesReceived: s.bytesReceived.Load(),
	}
}

func (s *stream) readLoop(r *bufio.Reader) {
	for {
		line, err := readBoundedLine(r, s.maxLine)
		if line != "" {
			s.bytesReceived.Add(uint64(len(line)))
			line = strings.TrimRight(line, "\r\n")
			if !s.deliver(line) {
				s.finish(err)

				return
			}
		}
		if err != nil {
			s.finish(err)

			return
		}
	}
}

// deliver hands one line on, returning false once the connection has ended so
// the reader stops rather than blocking on a full channel.
func (s *stream) deliver(line string) bool {
	if s.banner > 0 {
		s.banner--

		return true
	}
	select {
	case s.lines <- line:
		return true
	case <-s.done:
		return false
	}
}

// finish records why the connection ended and closes done, once.
func (s *stream) finish(err error) {
	s.closeOnce.Do(func() {
		if errors.Is(err, io.EOF) {
			err = nil
		}
		s.mu.Lock()
		s.closeErr = err
		s.mu.Unlock()
		close(s.done)
	})
}

// readBoundedLine reads up to the next newline, which it returns with the
// line, as bufio.Reader.ReadString does, but fails with ErrLineTooLong once the
// line passes limit bytes rather than buffering without end. The work is linear
// in the line: each byte is looked at once.
func readBoundedLine(r *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return "", fmt.Errorf("%w (%d bytes)", ErrLineTooLong, limit)
		}
		if line == nil && err == nil {
			// The common case: the whole line was in the buffer.
			return string(chunk), nil
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		return string(line), err
	}
}
