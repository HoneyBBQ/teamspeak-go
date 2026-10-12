package teamspeak

import (
	"context"
	"fmt"
	"io"
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
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialFileTransfer opens TCP to the TeamSpeak file-transfer port and performs
// the ftkey handshake. The caller is responsible for closing the returned
// connection.
//
// ctx bounds the dial and the handshake, not the connection returned. dialer
// may be nil, in which case a net.Dialer with a 10 second timeout is used.
func DialFileTransfer(
	ctx context.Context, host string, port uint16, key string, dialer FileTransferDialer,
) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))

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
	ctx context.Context, host string, info *FileUploadInfo, data io.Reader, dialer FileTransferDialer,
) error {
	conn, err := DialFileTransfer(ctx, host, info.Port, info.FileTransferKey, dialer)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	err = runOnConn(ctx, conn, func() error {
		_, copyErr := io.Copy(conn, data)

		return copyErr
	})
	if err != nil {
		return fmt.Errorf("failed to upload file data: %w", err)
	}

	return nil
}

// DownloadFileData receives data from the server using credentials from
// InitFileDownload, writing it to dest until the server closes the connection.
//
// If ctx is done first the connection is closed and the download stops with
// ctx's error; dest keeps whatever had arrived.
func DownloadFileData(
	ctx context.Context, host string, info *FileDownloadInfo, dest io.Writer, dialer FileTransferDialer,
) error {
	conn, err := DialFileTransfer(ctx, host, info.Port, info.FileTransferKey, dialer)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	err = runOnConn(ctx, conn, func() error {
		_, copyErr := io.Copy(dest, conn)

		return copyErr
	})
	if err != nil {
		return fmt.Errorf("failed to download file data: %w", err)
	}

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
