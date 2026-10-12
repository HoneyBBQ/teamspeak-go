package teamspeak

import (
	"context"
	"time"
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

// CreateDirectory creates a directory, including any missing parents.
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
			Status:               int(fieldInt(row, "status")),
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
	// Resume continues an earlier, interrupted upload of the same file; the
	// answer's SeekPosition says where to continue from.
	Resume bool
}

// InitFileUpload negotiates an upload and returns the key and port to dial.
//
// Pass the result to UploadFileData to send the data; it does not go through
// this client. A refusal — no permission to upload, say — is returned as a
// *ServerError, even though the voice protocol reports it in a separate
// notification after the command itself has succeeded.
func (c *Commands) InitFileUpload(
	ctx context.Context, channelID ChannelID, path string, size uint64, opts FileUploadOptions,
) (*FileUploadInfo, error) {
	row, err := c.queryRow(ctx, "ftinitupload", "ftkey", []param{
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
	}, "cpw")
	if err != nil {
		return nil, err
	}

	return &FileUploadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 fieldUint16(row, "port"),
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
	// is the start of the file.
	SeekPosition uint64
}

// InitFileDownload negotiates a download and returns the key, port and size to
// dial. Pass the result to DownloadFileData. Refusals are returned as for
// InitFileUpload.
func (c *Commands) InitFileDownload(
	ctx context.Context, channelID ChannelID, path string, opts FileDownloadOptions,
) (*FileDownloadInfo, error) {
	row, err := c.queryRow(ctx, "ftinitdownload", "ftkey", []param{
		uintArg("clientftfid", c.nextFileTransferID()),
		strArg("name", asPath(path)),
		idArg("cid", channelID),
		strArg("cpw", opts.Password),
		uintArg("seekpos", opts.SeekPosition),
		uintArg("proto", 0),
	}, "cpw")
	if err != nil {
		return nil, err
	}

	return &FileDownloadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 fieldUint16(row, "port"),
		Size:                 fieldUint(row, "size"),
		ClientFileTransferID: ClientFileTransferID(fieldUint16(row, "clientftfid")),
		ServerFileTransferID: ServerFileTransferID(fieldUint16(row, "serverftfid")),
	}, nil
}
