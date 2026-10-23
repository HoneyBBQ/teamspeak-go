package teamspeak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"time"
)

// defaultFileTransferIdleTimeout is FileTransferOptions.IdleTimeout when it is
// zero.
const defaultFileTransferIdleTimeout = 30 * time.Second

// fileTransferChunk is the most one Write call hands the connection, so the
// idle deadline is renewed as an upload progresses even when the caller's
// reader hands over its data in one piece.
const fileTransferChunk = 32 << 10

// fileTransferDialTimeout bounds the default dialer's connect, so a transfer
// started without a deadline cannot hang on a port nobody answers.
const fileTransferDialTimeout = 10 * time.Second

// FileTransferDialer opens the TCP connection a file transfer runs over.
//
// File transfers dial their own connection to a different port, on demand, so
// this is a separate seam from the voice client's WithPacketConn. Supplying one
// lets an application route file transfers through a proxy or tunnel, or drive
// them from something that is not a real connection; without it the SDK dials
// its own.
//
// It is the shape of net.Dialer and of golang.org/x/net/proxy's ContextDialer,
// so either can be passed as it is. network is always "tcp".
type FileTransferDialer interface {
	// DialContext connects to address over network, as net.Dialer.DialContext
	// does.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// FileTransferOptions are the optional parameters of DialFileTransfer,
// UploadFileData and DownloadFileData. The zero value dials directly.
type FileTransferOptions struct {
	// Dialer opens the connection; nil uses a net.Dialer with a 10 second
	// timeout.
	Dialer FileTransferDialer
	// Trace, when set, reports the milestones of the call; see
	// FileTransferTrace. It is read when the call starts.
	Trace *FileTransferTrace
	// IdleTimeout is the longest a transfer may go without moving any byte:
	// the deadline of the transfer key's write and of each read from, and
	// write to, the connection, renewed every time it is called. A transfer
	// that exceeds it fails with an error wrapping ErrFileTransfer and
	// os.ErrDeadlineExceeded. Zero means the default, 30 seconds; a negative
	// value disables it. It does not cover the wait on an upload's own reader
	// or a download's own writer, and not the connection DialFileTransfer
	// returns, which the caller drives.
	IdleTimeout time.Duration
}

// idle returns the idle timeout in effect, 0 when there is none.
func (o FileTransferOptions) idle() time.Duration {
	switch {
	case o.IdleTimeout == 0:
		return defaultFileTransferIdleTimeout
	case o.IdleTimeout < 0:
		return 0
	}

	return o.IdleTimeout
}

// idleConn renews the connection's deadlines before every read and write, so
// that they measure idleness rather than the length of the transfer. A
// connection that does not support deadlines is used without them.
type idleConn struct {
	conn net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.idle))
	}

	return c.conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	total := 0
	for {
		chunk := p[total:min(len(p), total+fileTransferChunk)]
		if c.idle > 0 {
			_ = c.conn.SetWriteDeadline(time.Now().Add(c.idle))
		}
		n, err := c.conn.Write(chunk)
		total += n
		if err != nil || total >= len(p) {
			return total, err
		}
	}
}

// errTooMuchData is a download that sent more than the size announced.
var errTooMuchData = errors.New("the server sent more data than the announced size")

// errTooMuchUpload is an upload whose data gave more than the size declared.
var errTooMuchUpload = errors.New("the data is longer than the declared size")

// bytesToMove is how many bytes a negotiated transfer moves: the file's size
// less the position it starts from. A position past the end is an error
// wrapping ErrFileTransfer.
func bytesToMove(size, seekPosition uint64) (uint64, error) {
	if seekPosition > size {
		return 0, fmt.Errorf("%w: the transfer starts at %d, outside a file of %d bytes",
			ErrFileTransfer, seekPosition, size)
	}
	if size-seekPosition > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %d bytes are more than a transfer can move", ErrFileTransfer, size-seekPosition)
	}

	return size - seekPosition, nil
}

// sizedWriter writes to w at most size bytes, and fails on the first byte
// beyond that without writing it.
type sizedWriter struct {
	w       io.Writer
	size    uint64
	written uint64
}

func (s *sizedWriter) Write(p []byte) (int, error) {
	room := s.size - s.written
	if uint64(len(p)) > room {
		n, err := s.w.Write(p[:room])
		s.written += uint64(n) //nolint:gosec // n is never negative
		if err != nil {
			return n, err
		}

		return n, errTooMuchData
	}
	n, err := s.w.Write(p)
	s.written += uint64(n) //nolint:gosec // n is never negative

	return n, err
}

// fileTransferProgressStep is how many bytes move between two Progress calls.
const fileTransferProgressStep = 64 << 10

// FileTransferDialStartInfo describes the DialStart milestone.
type FileTransferDialStartInfo struct {
	// Addr is the host:port of the file transfer port about to be dialled.
	Addr string
}

// FileTransferDialDoneInfo describes the DialDone milestone.
type FileTransferDialDoneInfo struct {
	// Addr is the host:port of the file transfer port.
	Addr string
	// LocalAddr is the host:port of the local end of the connection, or ""
	// when the connection does not say.
	LocalAddr string
	// Duration is the time since DialStart.
	Duration time.Duration
}

// FileTransferProgressInfo describes the Progress milestone.
type FileTransferProgressInfo struct {
	// Bytes is how many bytes have moved so far.
	Bytes int64
	// Total is how many bytes the transfer will move, as its info fixes them:
	// the file's size less the position it starts from. 0 for
	// DialFileTransfer, which moves none.
	Total int64
}

// FileTransferDoneInfo describes the Done milestone.
type FileTransferDoneInfo struct {
	// Bytes is how many bytes moved.
	Bytes int64
	// Duration is the time since DialStart.
	Duration time.Duration
}

// FileTransferStage is where a file transfer failed.
type FileTransferStage string

const (
	// FileTransferStageDial is connecting and sending the transfer key.
	FileTransferStageDial FileTransferStage = "dial"
	// FileTransferStageTransfer is moving the data.
	FileTransferStageTransfer FileTransferStage = "transfer"
)

// FileTransferFailedInfo describes the Failed milestone.
type FileTransferFailedInfo struct {
	// Err is the error the call returns.
	Err error
	// Stage is where the transfer failed: "dial" or "transfer".
	Stage FileTransferStage
	// Bytes is how many bytes had moved.
	Bytes int64
	// Duration is the time since DialStart.
	Duration time.Duration
}

// FileTransferTrace observes one call of UploadFileData, DownloadFileData or
// DialFileTransfer; set it in FileTransferOptions. Every hook is optional.
//
// DialStart, then DialDone, then Progress as data moves and, last, exactly one
// of Done and Failed: UploadFileData and DownloadFileData end with one of
// them. DialFileTransfer alone calls DialStart and then DialDone, or Failed
// with stage dial. The file transfer key is never in any info.
//
// A hook is called synchronously, on the goroutine doing the transfer, and its
// return value is ignored. It must be quick. Progress is called at most once
// per 64 KiB moved, and once more at the end with the final count.
//
// There is no logger here and the hooks run on the caller's own goroutine, so a
// panic in a hook is not recovered: it propagates to the caller of the transfer
// function, after the connection is closed, as a panic in the caller's own code
// would.
type FileTransferTrace struct {
	// DialStart is called before the file transfer port is dialled.
	DialStart func(FileTransferDialStartInfo)
	// DialDone is called when the connection is open and the transfer key
	// sent.
	DialDone func(FileTransferDialDoneInfo)
	// Progress is called while data moves.
	Progress func(FileTransferProgressInfo)
	// Done is called when the transfer function is about to return success.
	Done func(FileTransferDoneInfo)
	// Failed is called when the transfer function is about to return an error,
	// dialling included.
	Failed func(FileTransferFailedInfo)
}

// transferRun is the trace of one call.
type transferRun struct {
	start time.Time
	trace FileTransferTrace
	total int64
	moved int64
	last  int64
}

func newTransferRun(opts FileTransferOptions, total uint64) *transferRun {
	r := &transferRun{start: time.Now(), total: math.MaxInt64}
	if total <= math.MaxInt64 {
		r.total = int64(total)
	}

	if opts.Trace != nil {
		r.trace = *opts.Trace
	}

	return r
}

// dial opens the transfer connection with the dial milestones. The caller
// reports a failure with failed.
func (r *transferRun) dial(
	ctx context.Context, host string, port uint16, key string, opts FileTransferOptions,
) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if port == 0 {
		return nil, fmt.Errorf("%w: dial %s: the file transfer port is 0, not 1 to 65535", ErrFileTransfer, addr)
	}
	if r.trace.DialStart != nil {
		r.trace.DialStart(FileTransferDialStartInfo{Addr: addr})
	}
	conn, err := dialFileTransfer(ctx, addr, key, opts)
	if err != nil {
		return nil, err
	}
	if r.trace.DialDone != nil {
		// A panic in the hook leaves no caller holding the connection to close.
		returned := false
		defer func() {
			if !returned {
				_ = conn.Close()
			}
		}()
		localAddr := ""
		if a := conn.LocalAddr(); a != nil {
			localAddr = a.String()
		}
		r.trace.DialDone(FileTransferDialDoneInfo{Addr: addr, LocalAddr: localAddr, Duration: time.Since(r.start)})
		returned = true
	}

	return conn, nil
}

// failed reports Failed with err, returning err.
func (r *transferRun) failed(stage FileTransferStage, err error) error {
	if r.trace.Failed != nil {
		r.trace.Failed(FileTransferFailedInfo{Err: err, Stage: stage, Bytes: r.moved, Duration: time.Since(r.start)})
	}

	return err
}

// finish reports the final Progress and Done.
func (r *transferRun) finish() {
	r.progress(true)
	if r.trace.Done != nil {
		r.trace.Done(FileTransferDoneInfo{Bytes: r.moved, Duration: time.Since(r.start)})
	}
}

// progress reports Progress when a step has moved since the last report, or
// when final.
func (r *transferRun) progress(final bool) {
	if r.trace.Progress == nil || (!final && r.moved-r.last < fileTransferProgressStep) {
		return
	}
	r.last = r.moved
	r.trace.Progress(FileTransferProgressInfo{Bytes: r.moved, Total: r.total})
}

// countingReader counts what passes through it, for Progress. Only when a
// Progress hook is set is a reader wrapped at all.
type countingReader struct {
	r   io.Reader
	run *transferRun
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.run.moved += int64(n)
	c.run.progress(false)

	return n, err
}

// countingWriter counts what passes through it, for Progress.
type countingWriter struct {
	w   io.Writer
	run *transferRun
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.run.moved += int64(n)
	c.run.progress(false)

	return n, err
}

// DialFileTransfer opens TCP to the TeamSpeak file-transfer port and performs
// the ftkey handshake. The caller is responsible for closing the returned
// connection.
//
// ctx bounds the dial and the handshake, not the connection returned. Every
// error wraps ErrFileTransfer, one that ctx ended wraps ctx's error too.
func DialFileTransfer(
	ctx context.Context, host string, port uint16, key string, opts FileTransferOptions,
) (net.Conn, error) {
	run := newTransferRun(opts, 0)
	conn, err := run.dial(ctx, host, port, key, opts)
	if err != nil {
		return nil, run.failed(FileTransferStageDial, err)
	}

	return conn, nil
}

// neverConnectedError is a dial that failed before the connection opened, so
// nothing reached the server: not the key, and no byte of the file. Not one the
// caller's context ended, nor one after the connection opened.
type neverConnectedError struct{ error }

func (e *neverConnectedError) Unwrap() error { return e.error }

// dialFileTransfer dials addr and sends the transfer key.
func dialFileTransfer(ctx context.Context, addr, key string, opts FileTransferOptions) (net.Conn, error) {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: fileTransferDialTimeout}
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		err = fmt.Errorf("%w: dial %s: %w", ErrFileTransfer, addr, err)
		if ctx.Err() == nil {
			err = &neverConnectedError{err}
		}

		return nil, err
	}

	err = runOnConn(ctx, conn, func() error {
		if idle := opts.idle(); idle > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(idle))
			// The caller, or the transfer, sets its own from here.
			defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
		}
		_, writeErr := io.WriteString(conn, key)

		return writeErr
	})
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("%w: send key: %w", ErrFileTransfer, err)
	}

	return conn, nil
}

// UploadFileData transfers data to the server using credentials from
// InitFileUpload. data is the file from info.SeekPosition on, and must give
// exactly the bytes left of info.Size and then end: a reader that gives fewer
// fails the upload with an error wrapping io.ErrUnexpectedEOF, one that gives
// more fails it after the declared size, and the excess is not sent. In both
// cases the connection is closed, which ends the transfer on the server.
//
// It returns once the server has closed the transfer connection, which it
// does when it has the file. Measured on TeamSpeak 3 3.13.8 and TeamSpeak 6
// 6.0.0: the server closes about 200 ms after the last byte of a 100000-byte
// file. A connection that closes before every byte is written fails the
// upload, and so does one that stays open for the idle timeout.
//
// A close after the last byte is not proof that the file is stored: the server
// sends nothing on the transfer connection, and over the voice protocol its
// status notification comes only for a failure (2066 canceled, 2063 lost
// connection, 2052 more than declared), after the close, never for success;
// over ServerQuery nothing comes. Commands.UploadFile therefore asks the
// server for the file's size before it returns.
//
// If ctx is done first the connection is closed and the upload stops with an
// error wrapping ctx's error. An upload waiting on data's Read notices at its
// next write. Every error wraps ErrFileTransfer.
func UploadFileData(
	ctx context.Context, host string, info *FileUploadInfo, data io.Reader, opts FileTransferOptions,
) error {
	expected, err := bytesToMove(info.Size, info.SeekPosition)
	if err != nil {
		return err
	}
	run := newTransferRun(opts, expected)
	conn, err := run.dial(ctx, host, info.Port, info.FileTransferKey, opts)
	if err != nil {
		return run.failed(FileTransferStageDial, err)
	}
	defer func() { _ = conn.Close() }()

	src := data
	if run.trace.Progress != nil {
		src = countingReader{r: data, run: run}
	}
	err = runOnConn(ctx, conn, func() error {
		moving := idleConn{conn: conn, idle: opts.idle()}
		n, copyErr := io.CopyN(moving, src, int64(expected)) //nolint:gosec // bytesToMove bounds it
		if errors.Is(copyErr, io.EOF) {
			return fmt.Errorf("%d of the declared %d bytes: %w", n, expected, io.ErrUnexpectedEOF)
		}
		if copyErr != nil {
			return copyErr
		}
		// One more byte would be more than was declared. The server closes
		// the connection at the declared size and ignores the rest, so the
		// excess is only looked for, never sent.
		var extra [1]byte
		got, readErr := io.ReadFull(data, extra[:])
		if got > 0 {
			return errTooMuchUpload
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		// The bytes have left; the upload is over when the server says so.
		_, waitErr := io.Copy(io.Discard, moving)

		return waitErr
	})
	if err != nil {
		return run.failed(FileTransferStageTransfer, fmt.Errorf("%w: upload: %w", ErrFileTransfer, err))
	}
	run.finish()

	return nil
}

// DownloadFileData receives data from the server using credentials from
// InitFileDownload, writing it to dest until the server closes the connection.
// dest is not closed.
//
// The server sends the file from info.SeekPosition to its end, so the size to
// expect is info.Size less that: measured on TeamSpeak 3 3.13.8 and TeamSpeak
// 6 6.0.0, a seekpos of 40000 on a 100000-byte file is answered with the whole
// size and then 60000 bytes. A download that ends short of it fails with an
// error wrapping io.ErrUnexpectedEOF; one that sends more fails after the
// expected size, and the excess is not written to dest.
//
// If ctx is done first the connection is closed and the download stops with
// an error wrapping ctx's error; dest keeps whatever had arrived. Every error
// wraps ErrFileTransfer.
func DownloadFileData(
	ctx context.Context, host string, info *FileDownloadInfo, dest io.Writer, opts FileTransferOptions,
) error {
	expected, err := bytesToMove(info.Size, info.SeekPosition)
	if err != nil {
		return err
	}
	run := newTransferRun(opts, expected)
	conn, err := run.dial(ctx, host, info.Port, info.FileTransferKey, opts)
	if err != nil {
		return run.failed(FileTransferStageDial, err)
	}
	defer func() { _ = conn.Close() }()

	sized := &sizedWriter{w: dest, size: expected}
	var sink io.Writer = sized
	if run.trace.Progress != nil {
		sink = countingWriter{w: sized, run: run}
	}
	err = runOnConn(ctx, conn, func() error {
		_, copyErr := io.Copy(sink, idleConn{conn: conn, idle: opts.idle()})
		if copyErr == nil && sized.written < expected {
			// The connection closed before the expected size arrived.
			return fmt.Errorf("%d of %d bytes: %w", sized.written, expected, io.ErrUnexpectedEOF)
		}

		return copyErr
	})
	if err != nil {
		return run.failed(FileTransferStageTransfer, fmt.Errorf("%w: download: %w", ErrFileTransfer, err))
	}
	run.finish()

	return nil
}

// runOnConn runs op, which reads or writes conn, until it returns or ctx is
// done.
//
// A blocked Read or Write takes no context, so the only way to stop one is to
// close the connection under it. That surfaces as "use of closed network
// connection", which says nothing about why; the context's own error does.
func runOnConn(ctx context.Context, conn net.Conn, op func() error) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	err := op()
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	return err
}
