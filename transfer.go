package teamspeak

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"time"
)

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
	// Total is the size from the upload or download info; 0 when it is not
	// known, as for an upload, whose info does not carry one.
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
	r := &transferRun{start: time.Now(), total: int64(min(total, math.MaxInt64))}
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
// ctx bounds the dial and the handshake, not the connection returned.
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

// dialFileTransfer dials addr and sends the transfer key.
func dialFileTransfer(ctx context.Context, addr, key string, opts FileTransferOptions) (net.Conn, error) {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: fileTransferDialTimeout}
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to file transfer server %s: %w", addr, err)
	}

	err = runOnConn(ctx, conn, func() error {
		_, writeErr := io.WriteString(conn, key)

		return writeErr
	})
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("failed to send transfer key: %w", err)
	}

	return conn, nil
}

// UploadFileData transfers data to the server using credentials from
// InitFileUpload.
//
// If ctx is done first the connection is closed and the upload stops with
// ctx's error. An upload waiting on data's Read notices at its next write.
func UploadFileData(
	ctx context.Context, host string, info *FileUploadInfo, data io.Reader, opts FileTransferOptions,
) error {
	run := newTransferRun(opts, 0)
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
		_, copyErr := io.Copy(conn, src)

		return copyErr
	})
	if err != nil {
		return run.failed(FileTransferStageTransfer, fmt.Errorf("failed to upload file data: %w", err))
	}
	run.finish()

	return nil
}

// DownloadFileData receives data from the server using credentials from
// InitFileDownload, writing it to dest until the server closes the connection.
//
// If ctx is done first the connection is closed and the download stops with
// ctx's error; dest keeps whatever had arrived.
func DownloadFileData(
	ctx context.Context, host string, info *FileDownloadInfo, dest io.Writer, opts FileTransferOptions,
) error {
	run := newTransferRun(opts, info.Size)
	conn, err := run.dial(ctx, host, info.Port, info.FileTransferKey, opts)
	if err != nil {
		return run.failed(FileTransferStageDial, err)
	}
	defer func() { _ = conn.Close() }()

	sink := dest
	if run.trace.Progress != nil {
		sink = countingWriter{w: dest, run: run}
	}
	err = runOnConn(ctx, conn, func() error {
		_, copyErr := io.Copy(sink, conn)

		return copyErr
	})
	if err != nil {
		return run.failed(FileTransferStageTransfer, fmt.Errorf("failed to download file data: %w", err))
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
