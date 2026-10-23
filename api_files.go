package teamspeak

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// File transfer commands.
//
// These are the control-plane half: they list, move and delete files, and they
// negotiate an upload or download. The bytes travel over a separate TCP
// connection to the file transfer port, which UploadFileData and
// DownloadFileData handle.
//
// Every command here takes the channel's password in its options, "" for a
// channel with none. Pass it as the user typed it: the client encodes it as
// its protocol requires.

// FileOptions are the optional parameters of the file commands that take only
// a channel password.
type FileOptions struct {
	// Password is the channel's password, "" for none.
	Password string
}

// FileEntry is one entry of a directory listing.
type FileEntry struct {
	// Modified is when the entry was last changed (datetime).
	Modified time.Time
	// Name is the entry's name, without its directory (name).
	Name string
	// Size is the file's size in bytes (size); 0 for a directory.
	Size uint64
	// IsDirectory reports a directory. The listing sends type=0 for a
	// directory and type=1 for a file; GetFileInfo's answer carries no type,
	// so there it is always false.
	IsDirectory bool
}

func parseFileEntry(row map[string]string) FileEntry {
	return FileEntry{
		Name:        fieldStr(row, "name"),
		Size:        fieldUint(row, "size"),
		Modified:    fieldTime(row, "datetime"),
		IsDirectory: row["type"] == "0",
	}
}

// asPath makes a path absolute, which is the form the server expects.
func asPath(path string) string {
	if path == "" || path[0] != '/' {
		return "/" + path
	}

	return path
}

// ListFiles returns the directory listing for one path in a channel's file area.
func (c *Commands) ListFiles(
	ctx context.Context, channelID ChannelID, path string, opts FileOptions,
) ([]FileEntry, error) {
	rows, err := c.list(ctx, "ftgetfilelist", []param{
		idArg("cid", channelID),
		strArg("path", asPath(path)),
		strArg("cpw", opts.Password),
	}, "cpw")
	if err != nil {
		return nil, err
	}

	out := make([]FileEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseFileEntry(row))
	}

	return out, nil
}

// GetFileInfo returns the size and timestamp of one file.
func (c *Commands) GetFileInfo(
	ctx context.Context, channelID ChannelID, path string, opts FileOptions,
) (FileEntry, error) {
	row, err := c.queryRow(ctx, "ftgetfileinfo", "", []param{
		idArg("cid", channelID),
		strArg("name", asPath(path)),
		strArg("cpw", opts.Password),
	}, "cpw")
	if err != nil {
		return FileEntry{}, err
	}

	return parseFileEntry(row), nil
}

// DeleteFile removes one or more files in one command; deleting none does
// nothing.
func (c *Commands) DeleteFile(ctx context.Context, channelID ChannelID, paths []string, opts FileOptions) error {
	if len(paths) == 0 {
		return nil
	}

	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, asPath(path))
	}

	return c.exec(ctx, "ftdeletefile", []param{
		idArg("cid", channelID),
		strArg("cpw", opts.Password),
		rowsArg("name", names),
	}, "cpw")
}

// CreateDirectory creates a directory. The parent must exist: a path under a
// missing one is refused with 2052, "file input/output error", on TeamSpeak 3
// and 6.
func (c *Commands) CreateDirectory(ctx context.Context, channelID ChannelID, dirname string, opts FileOptions) error {
	return c.exec(ctx, "ftcreatedir", []param{
		idArg("cid", channelID),
		strArg("dirname", asPath(dirname)),
		strArg("cpw", opts.Password),
	}, "cpw")
}

// FileRenameOptions describe a move, optionally into another channel.
type FileRenameOptions struct {
	// Password is the source channel's password, "" for none.
	Password string
	// TargetChannelPassword is the target channel's password, "" for none.
	TargetChannelPassword string
	// TargetChannelID moves the file into another channel's file area; 0
	// keeps it in the same channel.
	TargetChannelID ChannelID
}

// RenameFile renames or moves a file. cpw is always sent, empty for none, as
// the command requires it; tcid and tcpw only with a TargetChannelID, tcpw
// then empty for none.
func (c *Commands) RenameFile(
	ctx context.Context, channelID ChannelID, oldName, newName string, opts FileRenameOptions,
) error {
	params := []param{
		idArg("cid", channelID),
		strArg("oldname", asPath(oldName)),
		strArg("newname", asPath(newName)),
		strArg("cpw", opts.Password),
	}
	if opts.TargetChannelID != 0 {
		params = append(params,
			idArg("tcid", opts.TargetChannelID),
			strArg("tcpw", opts.TargetChannelPassword))
	}

	return c.exec(ctx, "ftrenamefile", params, "cpw", "tcpw")
}

// FileTransferStopOptions are StopFileTransfer's optional parameters.
type FileTransferStopOptions struct {
	// RemovePartialFile deletes what was transferred so far, which is usually
	// what you want after a failed upload.
	RemovePartialFile bool
}

// StopFileTransfer cancels a running transfer.
//
// Stop only your own transfers: TeamSpeak 6 6.0.0-beta13.1 crashes on a
// ServerQuery ftstop for a transfer that is not the connection's own (one that
// does not exist, or another client's), and nothing here guards against it.
// See the "Server behaviour the SDK works around" section of the
// serverquery package documentation.
func (c *Commands) StopFileTransfer(
	ctx context.Context, serverFileTransferID ServerFileTransferID, opts FileTransferStopOptions,
) error {
	return c.exec(ctx, "ftstop", []param{
		idArg("serverftfid", serverFileTransferID),
		boolArg("delete", opts.RemovePartialFile),
	})
}

// ActiveTransfer is a file transfer in progress.
type ActiveTransfer struct {
	// Path is the directory the file is in (path).
	Path string
	// Name is the file's name (name).
	Name string
	// Sender is the transfer's sender, as the server names it (sender).
	Sender string
	// Size is the file's size in bytes (size).
	Size uint64
	// SizeDone is how many bytes have been transferred (sizedone).
	SizeDone uint64
	// Runtime is how long the transfer has been running, reported in whole
	// seconds.
	Runtime time.Duration
	// ClientFileTransferID is the id the transferring client chose
	// (clientftfid).
	ClientFileTransferID ClientFileTransferID
	// ServerFileTransferID is the id the server assigned (serverftfid).
	ServerFileTransferID ServerFileTransferID
	// ClientID is the client transferring the file (clid).
	ClientID ClientID
	// Status is the transfer's state as the server reports it (status). The
	// server's values are not documented, so it is the number sent.
	Status int
	// CurrentSpeed and AverageSpeed are in bytes per second.
	CurrentSpeed float32
	// AverageSpeed is the average speed since the transfer began
	// (average_speed).
	AverageSpeed float32
}

// ListActiveTransfers returns file transfers in progress. Requires the
// file-transfer-info permission.
func (c *Commands) ListActiveTransfers(ctx context.Context) ([]ActiveTransfer, error) {
	rows, err := c.list(ctx, "ftlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]ActiveTransfer, 0, len(rows))
	for _, row := range rows {
		out = append(out, ActiveTransfer{
			ClientID:             ClientID(fieldUint16(row, "clid")),
			Path:                 fieldStr(row, "path"),
			Name:                 fieldStr(row, "name"),
			Size:                 fieldUint(row, "size"),
			SizeDone:             fieldUint(row, "sizedone"),
			ClientFileTransferID: ClientFileTransferID(fieldUint16(row, "clientftfid")),
			ServerFileTransferID: ServerFileTransferID(fieldUint16(row, "serverftfid")),
			Sender:               fieldStr(row, "sender"),
			Status:               fieldEnum(row, "status"),
			CurrentSpeed:         fieldFloat32(row, "current_speed"),
			AverageSpeed:         fieldFloat32(row, "average_speed"),
			Runtime:              fieldDuration(row, "runtime", time.Second),
		})
	}

	return out, nil
}

// nextFileTransferID returns the clientftfid for the next negotiation.
//
// The server echoes it in its answer, and the echo is the only thing tying the
// answer to the request — it arrives after the command has already returned —
// so two transfers negotiated at once must not share one. Zero is skipped: it
// is what a request without the field would echo.
func (c *Commands) nextFileTransferID() uint64 {
	for {
		id := uint64(c.fileTransferID.Add(1) % 65536)
		if id != 0 {
			return id
		}
	}
}

// FileUploadOptions are InitFileUpload's optional parameters.
type FileUploadOptions struct {
	// Password is the channel's password, "" for none.
	Password string
	// Overwrite replaces a file of the same name, which the server otherwise
	// refuses.
	Overwrite bool
	// Resume continues an earlier, interrupted upload of the same file. The
	// server keeps what the interrupted upload had received, and the answer's
	// SeekPosition says how much that is: send the file from there. Measured
	// on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0: resuming a file that is not
	// there is refused with 2054 (errcode.FileInvalidPath), and Overwrite
	// together with Resume with 2056 (errcode.FileOverwriteExcludesResume).
	Resume bool
}

// transferRefusal is the refusal a file transfer negotiation reports inside a
// successful answer, or nil when the rows hold none.
//
// Over ServerQuery ftinitupload and ftinitdownload answer "error id=0" even
// when they refuse, and say so in the row instead (clientftfid=2 status=2058
// msg=file\sis\sin\suse), with no ftkey. Left as it is, the answer reads as
// no data and the reason is lost; this turns the row into the ServerError it
// is. The voice protocol reports the refusal as a failure and never gets here.
func transferRefusal(rows []map[string]string) error {
	if len(rows) == 0 || rows[0]["ftkey"] != "" {
		return nil
	}
	status, err := strconv.ParseUint(rows[0]["status"], 10, 32)
	if err == nil && status != 0 {
		return &ServerError{Code: errcode.Code(status), Message: rows[0]["msg"]}
	}

	return nil
}

// transferRow sends a negotiation and returns its answer row, or the server's
// refusal; see transferRefusal.
func (c *Commands) transferRow(ctx context.Context, command string, params []param) (map[string]string, error) {
	rows, err := c.query(ctx, command, params, "cpw")
	if err != nil {
		return nil, err
	}
	err = transferRefusal(rows)
	if err != nil {
		return nil, err
	}

	return requireRow(rows, command, "ftkey")
}

// transferPort reads the file transfer port of a negotiation, which must be a
// real one: the field is 16 bits wide, and neither 0 nor a larger number is a
// port to dial.
func transferPort(row map[string]string) (uint16, error) {
	port := fieldUint(row, "port")
	if port < 1 || port > math.MaxUint16 {
		return 0, fmt.Errorf("%w: the server named the file transfer port %q, not 1 to 65535",
			ErrFileTransfer, row["port"])
	}

	return uint16(port), nil
}

// InitFileUpload negotiates an upload and returns the key and port to dial.
//
// Pass the result to UploadFileData to send the data; it does not go through
// this client. A refusal — no permission to upload, say — is returned as a
// *ServerError, even though the voice protocol reports it in a separate
// notification after the command itself has succeeded and ServerQuery in the
// answer's row. The port is on the host the connection to the server uses:
// measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0, neither the voice
// protocol nor ServerQuery ever sends another address.
func (c *Commands) InitFileUpload(
	ctx context.Context, channelID ChannelID, path string, size uint64, opts FileUploadOptions,
) (*FileUploadInfo, error) {
	row, err := c.transferRow(ctx, "ftinitupload", []param{
		uintArg("clientftfid", c.nextFileTransferID()),
		strArg("name", asPath(path)),
		idArg("cid", channelID),
		strArg("cpw", opts.Password),
		uintArg("size", size),
		boolArg("overwrite", opts.Overwrite),
		boolArg("resume", opts.Resume),
		// proto is required: omitting it fails the whole call with 1539
		// (parameter not found) rather than defaulting.
		uintArg("proto", 0),
	})
	if err != nil {
		return nil, err
	}
	port, err := transferPort(row)
	if err != nil {
		return nil, err
	}

	return &FileUploadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 port,
		Size:                 size,
		SeekPosition:         fieldUint(row, "seekpos"),
		ClientFileTransferID: ClientFileTransferID(fieldUint16(row, "clientftfid")),
		ServerFileTransferID: ServerFileTransferID(fieldUint16(row, "serverftfid")),
	}, nil
}

// FileDownloadOptions are InitFileDownload's optional parameters.
type FileDownloadOptions struct {
	// Password is the channel's password, "" for none.
	Password string
	// SeekPosition is the byte offset to start from, to resume a download; 0
	// is the start of the file. The answer's Size stays the whole file's, and
	// the bytes sent are those from here to the end: measured on TeamSpeak 3
	// 3.13.8 and TeamSpeak 6 6.0.0, a seekpos of 40000 on a 100000-byte file
	// is answered with size 100000 and then 60000 bytes. An offset past the end
	// is refused with 2057 (errcode.FileInvalidSize).
	SeekPosition uint64
}

// InitFileDownload negotiates a download and returns the key, port and size to
// dial. Pass the result to DownloadFileData. Refusals are returned as for
// InitFileUpload: a file that is not there is errcode.FileNotFound.
func (c *Commands) InitFileDownload(
	ctx context.Context, channelID ChannelID, path string, opts FileDownloadOptions,
) (*FileDownloadInfo, error) {
	row, err := c.transferRow(ctx, "ftinitdownload", []param{
		uintArg("clientftfid", c.nextFileTransferID()),
		strArg("name", asPath(path)),
		idArg("cid", channelID),
		strArg("cpw", opts.Password),
		uintArg("seekpos", opts.SeekPosition),
		uintArg("proto", 0),
	})
	if err != nil {
		return nil, err
	}
	port, err := transferPort(row)
	if err != nil {
		return nil, err
	}

	return &FileDownloadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 port,
		Size:                 fieldUint(row, "size"),
		SeekPosition:         opts.SeekPosition,
		ClientFileTransferID: ClientFileTransferID(fieldUint16(row, "clientftfid")),
		ServerFileTransferID: ServerFileTransferID(fieldUint16(row, "serverftfid")),
	}, nil
}

// UploadFileOptions are UploadFile's optional parameters.
type UploadFileOptions struct {
	// Transfer configures the connection that carries the bytes: the dialer,
	// the idle timeout and the trace. The zero value dials directly.
	Transfer FileTransferOptions
	// Password is the channel's password, "" for none.
	Password string
	// Overwrite replaces a file of the same name, which the server otherwise
	// refuses. It cannot go with Resume.
	Overwrite bool
	// Resume continues an interrupted upload of the same file. data is still
	// the whole file: the server says how much of the file it already
	// holds, and only the rest is sent. See FileUploadOptions.Resume.
	Resume bool
}

// UploadFile uploads data as one file in one call: it negotiates the upload
// with InitFileUpload and sends the bytes with UploadFileData. host is the
// address the file transfer port is reached on, the one the client connected
// to: the servers never name another. For a stream, call the two yourself.
//
// It returns once the server has closed the transfer connection, which it does
// when it has the file: measured on TeamSpeak 3 3.13.8 and TeamSpeak 6 6.0.0,
// about 200 ms after the last byte of a 100000-byte file.
//
// A refusal, such as no permission to upload or a file that exists without
// Overwrite (errcode.FileAlreadyExists), is the server's error as
// InitFileUpload returns it. The transfer's own errors wrap ErrFileTransfer.
// WebQuery refuses the negotiation with 5120, out of the scope of the key, so
// the call needs another transport.
func (c *Commands) UploadFile(
	ctx context.Context, host string, channelID ChannelID, path string, data []byte, opts UploadFileOptions,
) error {
	info, err := c.InitFileUpload(ctx, channelID, path, uint64(len(data)), FileUploadOptions{
		Password:  opts.Password,
		Overwrite: opts.Overwrite,
		Resume:    opts.Resume,
	})
	if err != nil {
		return err
	}
	// What the server holds is not sent again. A position past the end is
	// left for the transfer to refuse.
	rest := data
	if info.SeekPosition <= uint64(len(data)) {
		rest = data[info.SeekPosition:]
	}

	return UploadFileData(ctx, host, info, bytes.NewReader(rest), opts.Transfer)
}

// defaultDownloadFileLimit is DownloadFileOptions.MaxSize when it is zero.
const defaultDownloadFileLimit = 64 << 20

// DownloadFileOptions are DownloadFile's optional parameters.
type DownloadFileOptions struct {
	// Transfer configures the connection that carries the bytes; see
	// UploadFileOptions.
	Transfer FileTransferOptions
	// Password is the channel's password, "" for none.
	Password string
	// SeekPosition starts the download there: the bytes are the file's from
	// that offset to its end, which is how to resume a partial download.
	SeekPosition uint64
	// MaxSize is the most bytes DownloadFile will hold in memory. The server
	// announces the size before the bytes, so a larger download is refused
	// without being fetched. Zero means 64 MiB.
	MaxSize uint64
}

// DownloadFile downloads one file in one call and returns its bytes: it
// negotiates the download with InitFileDownload and receives the bytes with
// DownloadFileData. host is as for UploadFile. For a file too large to hold
// call the two yourself with a writer of your own.
//
// With SeekPosition the bytes are the file's from there to its end.
//
// A download of more than MaxSize bytes fails with an error wrapping
// ErrFileTransfer before any byte is fetched, and the transfer the server had
// prepared is stopped, so none is left listed as active. A refusal is the
// server's error as InitFileDownload returns it, and a transfer error wraps
// ErrFileTransfer. WebQuery refuses the negotiation as for UploadFile.
func (c *Commands) DownloadFile(
	ctx context.Context, host string, channelID ChannelID, path string, opts DownloadFileOptions,
) ([]byte, error) {
	info, err := c.InitFileDownload(ctx, channelID, path,
		FileDownloadOptions{Password: opts.Password, SeekPosition: opts.SeekPosition})
	if err != nil {
		return nil, err
	}
	limit := opts.MaxSize
	if limit == 0 {
		limit = defaultDownloadFileLimit
	}
	wanted, err := bytesToMove(info.Size, info.SeekPosition)
	if err != nil {
		return nil, err
	}
	if wanted > limit {
		// The server holds the negotiated transfer, and lists it among the
		// active ones, until it is used or stopped: a refusal that left it
		// would leave a transfer nobody is going to dial.
		_ = c.StopFileTransfer(context.WithoutCancel(ctx), info.ServerFileTransferID, FileTransferStopOptions{})

		return nil, fmt.Errorf("%w: %s is %d bytes from %d, over the %d the call holds in memory",
			ErrFileTransfer, path, wanted, info.SeekPosition, limit)
	}

	var buf bytes.Buffer
	// Sized up front when the announcement is a size a buffer can have; a
	// larger one the caller allowed still grows as the bytes come.
	if wanted <= math.MaxInt32 {
		buf.Grow(int(wanted))
	}
	err = DownloadFileData(ctx, host, info, &buf, opts.Transfer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// FileTreeEntry is one entry of a recursive listing.
type FileTreeEntry struct {
	FileEntry

	// Path is the entry's full path from the channel's top, such as
	// "/docs/inner/a.txt".
	Path string
}

// RecursiveFilesOptions are ListFilesRecursive's optional parameters.
type RecursiveFilesOptions struct {
	// Password is the channel's password, "" for none.
	Password string
	// MaxDepth bounds how deep the listing goes, counted as find's -maxdepth
	// counts: 1 lists only the entries of the path itself, 2 adds the entries of
	// its directories, and so on. Zero means no bound; a negative value is
	// refused with ErrInvalidCommand.
	MaxDepth int
}

// ListFilesRecursive lists a directory of a channel's file area and every
// directory under it, one ListFiles per directory, and returns every entry
// with its full path. A directory comes before what it holds, and entries are
// in the order the server listed them. A directory with nothing in it adds
// nothing; a path that does not exist is the server's error, 2052 on TeamSpeak
// 3 and 2051 on 6. The listing is not atomic: files changed meanwhile can be
// missed or listed once they are gone.
func (c *Commands) ListFilesRecursive(
	ctx context.Context, channelID ChannelID, path string, opts RecursiveFilesOptions,
) ([]FileTreeEntry, error) {
	if opts.MaxDepth < 0 {
		return nil, fmt.Errorf("%w: a negative depth", ErrInvalidCommand)
	}

	var out []FileTreeEntry

	return out, c.walkFiles(ctx, channelID, asPath(path), 1, opts, &out)
}

func (c *Commands) walkFiles(
	ctx context.Context, channelID ChannelID, dir string, depth int, opts RecursiveFilesOptions, out *[]FileTreeEntry,
) error {
	entries, err := c.ListFiles(ctx, channelID, dir, FileOptions{Password: opts.Password})
	if err != nil {
		return err
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for _, entry := range entries {
		full := prefix + entry.Name
		*out = append(*out, FileTreeEntry{Path: full, FileEntry: entry})
		if entry.IsDirectory && (opts.MaxDepth == 0 || depth < opts.MaxDepth) {
			err = c.walkFiles(ctx, channelID, full, depth+1, opts, out)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
