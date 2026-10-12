package teamspeak

import "context"

// File transfer commands.
//
// These are the control-plane half: they list, move and delete files, and they
// negotiate an upload or download. The bytes travel over a separate TCP
// connection to the file transfer port, which UploadFileData and
// DownloadFileData handle.
//
// Every command here takes a channel password, and the server expects it as
// base64(sha1(password)) rather than cleartext — the same encoding clientmove
// uses. Passing "" is correct and common for a channel with no password.

// FileEntry is one entry of a directory listing.
type FileEntry struct {
	Name       string
	Size       uint64
	ModifiedAt uint64
	// Type is 0 for a file, 1 for a directory.
	Type int
}

func parseFileEntry(row map[string]string) FileEntry {
	return FileEntry{
		Name:       fieldStr(row, "name"),
		Size:       fieldUint(row, "size"),
		ModifiedAt: fieldUint(row, "datetime"),
		Type:       int(fieldInt(row, "type")),
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
func (c *Commands) ListFiles(ctx context.Context, channelID uint64, path, password string) ([]FileEntry, error) {
	rows, err := c.query(ctx, "ftgetfilelist", []param{
		uintArg("cid", channelID),
		strArg("path", asPath(path)),
		strArg("cpw", password),
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
func (c *Commands) GetFileInfo(ctx context.Context, channelID uint64, path, password string) (FileEntry, error) {
	rows, err := c.query(ctx, "ftgetfileinfo", []param{
		uintArg("cid", channelID),
		strArg("name", asPath(path)),
		strArg("cpw", password),
	}, "cpw")
	if err != nil {
		return FileEntry{}, err
	}

	if len(rows) == 0 {
		return FileEntry{}, errNoDataReturned
	}

	return parseFileEntry(rows[0]), nil
}

// DeleteFile removes one or more files.
//
// The names travel as a pipe-separated list in a single parameter, which is why
// this takes a slice rather than being called once per file.
func (c *Commands) DeleteFile(ctx context.Context, channelID uint64, paths []string, password string) error {
	if len(paths) == 0 {
		return nil
	}

	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, asPath(path))
	}

	return c.exec(ctx, "ftdeletefile", []param{
		uintArg("cid", channelID),
		strArg("name", joinPipe(names)),
		strArg("cpw", password),
	}, "cpw")
}

// CreateDirectory creates a directory, including any missing parents.
func (c *Commands) CreateDirectory(ctx context.Context, channelID uint64, dirname, password string) error {
	return c.exec(ctx, "ftcreatedir", []param{
		uintArg("cid", channelID),
		strArg("dirname", asPath(dirname)),
		strArg("cpw", password),
	}, "cpw")
}

// RenameFileOptions describes a move, optionally into another channel.
type RenameFileOptions struct {
	Password              string
	TargetChannelID       *uint64
	TargetChannelPassword *string
}

// RenameFile renames or moves a file.
func (c *Commands) RenameFile(
	ctx context.Context, channelID uint64, oldName, newName string, opts RenameFileOptions,
) error {
	return c.exec(ctx, "ftrenamefile", []param{
		uintArg("cid", channelID),
		strArg("oldname", asPath(oldName)),
		strArg("newname", asPath(newName)),
		strArg("cpw", opts.Password),
		uintPtrArg("tcid", opts.TargetChannelID),
		strPtrArg("tcpw", opts.TargetChannelPassword),
	}, "cpw", "tcpw")
}

// StopFileTransfer cancels a running transfer.
//
// removePartialFile deletes the partial file as well, which is usually what you
// want after a failed upload.
func (c *Commands) StopFileTransfer(ctx context.Context, serverFileTransferID uint16, removePartialFile bool) error {
	return c.exec(ctx, "ftstop", []param{
		uintArg("serverftfid", uint64(serverFileTransferID)),
		boolArg("delete", removePartialFile),
	})
}

// ActiveTransfer is a file transfer in progress.
type ActiveTransfer struct {
	Path                 string
	Name                 string
	Sender               string
	Size                 uint64
	SizeDone             uint64
	Runtime              uint64
	ClientFileTransferID uint16
	ServerFileTransferID uint16
	ClientID             uint16
	Status               int
	CurrentSpeed         float32
	AverageSpeed         float32
}

// ListActiveTransfers returns file transfers in progress. Requires the
// file-transfer-info permission.
func (c *Commands) ListActiveTransfers(ctx context.Context) ([]ActiveTransfer, error) {
	rows, err := c.query(ctx, "ftlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]ActiveTransfer, 0, len(rows))
	for _, row := range rows {
		out = append(out, ActiveTransfer{
			ClientID:             fieldUint16(row, "clid"),
			Path:                 fieldStr(row, "path"),
			Name:                 fieldStr(row, "name"),
			Size:                 fieldUint(row, "size"),
			SizeDone:             fieldUint(row, "sizedone"),
			ClientFileTransferID: fieldUint16(row, "clientftfid"),
			ServerFileTransferID: fieldUint16(row, "serverftfid"),
			Sender:               fieldStr(row, "sender"),
			Status:               int(fieldInt(row, "status")),
			CurrentSpeed:         float32(fieldInt(row, "current_speed")),
			AverageSpeed:         float32(fieldInt(row, "average_speed")),
			Runtime:              fieldUint(row, "runtime"),
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

// InitFileUpload negotiates an upload and returns the key and port to dial.
//
// Pass the result to UploadFileData to send the data; it does not go through
// this client. A refusal — no permission to upload, say — is returned as a
// *ServerError, even though the voice protocol reports it in a separate
// notification after the command itself has succeeded.
func (c *Commands) InitFileUpload(
	ctx context.Context, channelID uint64, path string, size uint64, password string, overwrite bool,
) (*FileUploadInfo, error) {
	rows, err := c.query(ctx, "ftinitupload", []param{
		uintArg("clientftfid", c.nextFileTransferID()),
		strArg("name", asPath(path)),
		uintArg("cid", channelID),
		strArg("cpw", password),
		uintArg("size", size),
		boolArg("overwrite", overwrite),
		boolArg("resume", false),
		// proto is required: omitting it fails the whole call with 1539
		// (parameter not found) rather than defaulting.
		uintArg("proto", 0),
	}, "cpw")
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errNoDataReturned
	}

	row := rows[0]

	return &FileUploadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 fieldUint16(row, "port"),
		SeekPosition:         fieldUint(row, "seekpos"),
		ClientFileTransferID: fieldUint16(row, "clientftfid"),
		ServerFileTransferID: fieldUint16(row, "serverftfid"),
	}, nil
}

// InitFileDownload negotiates a download and returns the key, port and size to
// dial. Pass the result to DownloadFileData. Refusals are returned as for
// InitFileUpload.
func (c *Commands) InitFileDownload(
	ctx context.Context, channelID uint64, path, password string, seekPosition uint64,
) (*FileDownloadInfo, error) {
	rows, err := c.query(ctx, "ftinitdownload", []param{
		uintArg("clientftfid", c.nextFileTransferID()),
		strArg("name", asPath(path)),
		uintArg("cid", channelID),
		strArg("cpw", password),
		uintArg("seekpos", seekPosition),
		uintArg("proto", 0),
	}, "cpw")
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errNoDataReturned
	}

	row := rows[0]

	return &FileDownloadInfo{
		FileTransferKey:      fieldStr(row, "ftkey"),
		Port:                 fieldUint16(row, "port"),
		Size:                 fieldUint(row, "size"),
		ClientFileTransferID: fieldUint16(row, "clientftfid"),
		ServerFileTransferID: fieldUint16(row, "serverftfid"),
	}, nil
}
