package teamspeak

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
func (c *Client) ListFiles(channelID uint64, path, password string) ([]FileEntry, error) {
	rows, err := c.query("ftgetfilelist", []param{
		Uint("cid", channelID),
		Str("path", asPath(path)),
		Str("cpw", password),
	}, PlainPassword("cpw"))
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
func (c *Client) GetFileInfo(channelID uint64, path, password string) (FileEntry, error) {
	rows, err := c.query("ftgetfileinfo", []param{
		Uint("cid", channelID),
		Str("name", asPath(path)),
		Str("cpw", password),
	}, PlainPassword("cpw"))
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
func (c *Client) DeleteFile(channelID uint64, paths []string, password string) error {
	if len(paths) == 0 {
		return nil
	}

	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, asPath(path))
	}

	return c.exec("ftdeletefile", []param{
		Uint("cid", channelID),
		Str("name", joinPipe(names)),
		Str("cpw", password),
	}, PlainPassword("cpw"))
}

// CreateDirectory creates a directory, including any missing parents.
func (c *Client) CreateDirectory(channelID uint64, dirname, password string) error {
	return c.exec("ftcreatedir", []param{
		Uint("cid", channelID),
		Str("dirname", asPath(dirname)),
		Str("cpw", password),
	}, PlainPassword("cpw"))
}

// RenameFileOptions describes a move, optionally into another channel.
type RenameFileOptions struct {
	Password              string
	TargetChannelID       *uint64
	TargetChannelPassword *string
}

// RenameFile renames or moves a file.
func (c *Client) RenameFile(channelID uint64, oldName, newName string, opts RenameFileOptions) error {
	return c.exec("ftrenamefile", []param{
		Uint("cid", channelID),
		Str("oldname", asPath(oldName)),
		Str("newname", asPath(newName)),
		Str("cpw", opts.Password),
		UintPtr("tcid", opts.TargetChannelID),
		StrPtr("tcpw", opts.TargetChannelPassword),
	}, PlainPassword("cpw"), PlainPassword("tcpw"))
}

// StopFileTransfer cancels a running transfer.
//
// removePartialFile deletes the partial file as well, which is usually what you
// want after a failed upload.
func (c *Client) StopFileTransfer(serverFileTransferID uint16, removePartialFile bool) error {
	return c.exec("ftstop", []param{
		Uint("serverftfid", uint64(serverFileTransferID)),
		Bool("delete", removePartialFile),
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
func (c *Client) ListActiveTransfers() ([]ActiveTransfer, error) {
	rows, err := c.query("ftlist", nil)
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
func (c *Client) nextFileTransferID() uint64 {
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
func (c *Client) InitFileUpload(
	channelID uint64, path string, size uint64, password string, overwrite bool,
) (*FileUploadInfo, error) {
	rows, err := c.query("ftinitupload", []param{
		Uint("clientftfid", c.nextFileTransferID()),
		Str("name", asPath(path)),
		Uint("cid", channelID),
		Str("cpw", password),
		Uint("size", size),
		Bool("overwrite", overwrite),
		Bool("resume", false),
		// proto is required: omitting it fails the whole call with 1539
		// (parameter not found) rather than defaulting.
		Uint("proto", 0),
	}, PlainPassword("cpw"))
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
func (c *Client) InitFileDownload(
	channelID uint64, path, password string, seekPosition uint64,
) (*FileDownloadInfo, error) {
	rows, err := c.query("ftinitdownload", []param{
		Uint("clientftfid", c.nextFileTransferID()),
		Str("name", asPath(path)),
		Uint("cid", channelID),
		Str("cpw", password),
		Uint("seekpos", seekPosition),
		Uint("proto", 0),
	}, PlainPassword("cpw"))
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
