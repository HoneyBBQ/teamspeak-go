package teamspeak

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// FileTransferDialer opens the TCP connection a file transfer runs over.
//
// File transfers dial their own connection to a different port, on demand, so
// this is a separate seam from WithPacketConn. Supplying one lets an
// application route file transfers through a proxy or tunnel, or drive them
// from something that is not a real connection; without it the SDK dials its
// own.
type FileTransferDialer func(ctx context.Context, addr string) (net.Conn, error)

// DialFileTransfer opens TCP to the TeamSpeak file-transfer port
// and performs the ftkey handshake. The caller is responsible for closing the
// returned connection.
//
// dialer may be nil, in which case a default dialer with a 10 second timeout is
// used.
func DialFileTransfer(host string, port uint16, key string, dialer FileTransferDialer) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if dialer == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dialer = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}

	conn, err := dialer(context.Background(), addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to file transfer server %s: %w", addr, err)
	}

	_, err = conn.Write([]byte(key))
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("failed to send transfer key: %w", err)
	}

	return conn, nil
}

// UploadFileData transfers data to the server using credentials from InitFileUpload.
func UploadFileData(host string, info *FileUploadInfo, data io.Reader, dialer FileTransferDialer) error {
	conn, err := DialFileTransfer(host, info.Port, info.FileTransferKey, dialer)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_, err = io.Copy(conn, data)
	if err != nil {
		return fmt.Errorf("failed to upload file data: %w", err)
	}

	return nil
}

// DownloadFileData receives data from the server using credentials from InitFileDownload.
func DownloadFileData(host string, info *FileDownloadInfo, dest io.Writer, dialer FileTransferDialer) error {
	conn, err := DialFileTransfer(host, info.Port, info.FileTransferKey, dialer)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_, err = io.Copy(dest, conn)
	if err != nil {
		return fmt.Errorf("failed to download file data: %w", err)
	}

	return nil
}
