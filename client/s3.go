package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/request"
)

// TeamSpeak 6 S3 file transfer.
//
// A TeamSpeak 6 server started with S3 file transfer keeps channel files in an
// S3-compatible bucket, and says so: its extensions
// (Client.ServerCapabilities) name "s3". A client asks the server for a
// presigned URL over the voice connection and moves the bytes with a plain
// HTTPS request to the storage; nothing goes through the server's file transfer
// port.
//
// TeamSpeak does not document these commands. Everything here was measured on
// TeamSpeak 6 6.0.0-beta13.1 with an S3-compatible storage behind TLS:
//
//   - They run on the voice connection, which is why they are methods of
//     Client: WebQuery refuses them as unknown commands.
//   - The server keeps each channel's file list in memory, takes a file out of
//     it when it deletes one, and reads it from the storage again when told an
//     upload is done: a file stored without CompleteS3FileUpload is not listed.
//   - Other clients are told nothing when a file is uploaded or deleted.
//   - The classic file commands (ftinitupload, ftgetfilelist, ...) still work
//     on such a server, and reach a separate store: a file uploaded one way is
//     not listed the other.
//
// Every control method takes the channel's password in its options, "" for a
// channel with none, in cleartext, and sends it the way every file command
// does.

// extensionS3 is the extension a server names when it does S3 file transfer.
const extensionS3 = "s3"

// defaultS3DownloadLimit is DownloadS3FileOptions.MaxSize when it is zero, the
// limit DownloadFile has.
const defaultS3DownloadLimit = 64 << 20

// s3ErrorBodyLimit is how much of a storage's error answer is read for its code.
const s3ErrorBodyLimit = 64 << 10

// S3FileOptions are the optional parameters of the S3 file commands.
type S3FileOptions struct {
	// Password is the channel's password, "" for none (chpw).
	Password string
}

// S3FileUploadInfo is an upload the server signed: where to send the file, and
// what to tell the server once it is stored.
//
// URL is a credential: whoever holds it can write the file until it expires,
// after the server's s3ft-presigned-url-expiration (300 seconds by default).
// Keep it out of logs.
type S3FileUploadInfo struct {
	// Path is the file's path from the channel's root, as the server confirmed
	// it.
	Path string
	// URL is the presigned URL to PUT the file to.
	URL string
	// Size is the size in bytes the URL is signed for. The upload must send
	// exactly this many.
	Size uint64
	// ChannelID is the channel whose file area the file goes to.
	ChannelID teamspeak.ChannelID
}

// S3FileDownloadInfo is a download the server signed. URL is a credential as an
// upload's is: whoever holds it can read the file until it expires.
type S3FileDownloadInfo struct {
	// Path is the file's path from the channel's root, as the server confirmed
	// it.
	Path string
	// URL is the presigned URL to GET the file from.
	URL string
	// ChannelID is the channel whose file area the file is in.
	ChannelID teamspeak.ChannelID
}

// S3FileEntry is one file in a channel's S3 file area.
type S3FileEntry struct {
	// ModifiedAt is when the storage last wrote the file; the zero time when the
	// server sent none it could read.
	ModifiedAt time.Time
	// Path is the file's path from the channel's root, with a leading slash:
	// /docs/a.txt.
	Path string
	// Size is the size in bytes.
	Size uint64
}

// S3TransferOptions say how an S3 transfer reaches the storage.
type S3TransferOptions struct {
	// HTTPClient sends the request; nil means http.DefaultClient. Pass one to
	// route through a proxy, trust another certificate authority, time or watch
	// the request, or to test.
	HTTPClient *http.Client
}

func (o S3TransferOptions) client() *http.Client {
	if o.HTTPClient == nil {
		return http.DefaultClient
	}

	return o.HTTPClient
}

// S3DownloadOptions are DownloadS3FileData's optional parameters.
type S3DownloadOptions struct {
	// Transfer says how the request reaches the storage.
	Transfer S3TransferOptions
	// SeekPosition is the byte offset to start from, to resume; 0 is the start
	// of the file. The bytes written are the file's from here to its end. The
	// storage answers an offset at or past the end with 416, as an
	// *S3TransferError.
	SeekPosition uint64
}

// assertS3 refuses, before anything is sent, a server that does not name the S3
// extension.
func (c *Client) assertS3() error {
	caps := c.ServerCapabilities()
	if !caps.HasExtension(extensionS3) {
		return &S3UnsupportedError{Family: caps.Family, Version: caps.Version, Extensions: caps.Extensions}
	}

	return nil
}

// s3Path returns the path as the server takes it: from the channel's root, with
// a leading slash added when missing.
//
// The server signs the URL for the path exactly as it is given, so only a plain
// path to a file is taken: a URL parser resolves a "." or ".." segment away,
// and the request would not be the one signed; an empty segment (a//b, or a
// slash at the end) names no directory or no file, and a storage may refuse it
// outright; and no file name has a control character in it. The error wraps
// teamspeak.ErrInvalidCommand.
func s3Path(path string) (string, error) {
	full := path
	if !strings.HasPrefix(full, "/") {
		full = "/" + full
	}
	for i := range len(full) {
		if full[i] < 0x20 || full[i] == 0x7f {
			return "", fmt.Errorf("%w: the S3 file path %q has a control character",
				teamspeak.ErrInvalidCommand, path)
		}
	}
	for segment := range strings.SplitSeq(full[1:], "/") {
		switch segment {
		case "":
			return "", fmt.Errorf("%w: the S3 file path %q has an empty segment, or names no file",
				teamspeak.ErrInvalidCommand, path)
		case ".", "..":
			return "", fmt.Errorf("%w: the S3 file path %q has a %q segment",
				teamspeak.ErrInvalidCommand, path, segment)
		}
	}

	return full, nil
}

// s3Request builds an S3 command: the channel and its password on the first
// row, then one row per entry of rest.
func s3Request(
	command string, channelID teamspeak.ChannelID, password string, first [][2]string, rest [][][2]string,
) teamspeak.Request {
	params := make([][2]string, 0, 2+len(first))
	params = append(params, [2]string{"chid", strconv.FormatUint(uint64(channelID), 10)}, [2]string{"chpw", password})
	params = append(params, first...)
	req := request.NewRowed(command, params, []string{"chpw"}, rest)

	return req.(teamspeak.Request) //nolint:forcetypeassert // NewRowed returns a Request
}

// presign asks for one presigned URL, and returns the path the server confirmed
// and the URL.
func (c *Client) presign(
	ctx context.Context, channelID teamspeak.ChannelID, path, verb string, length uint64, opts S3FileOptions,
) (string, string, error) {
	err := c.assertS3()
	if err != nil {
		return "", "", err
	}
	full, err := s3Path(path)
	if err != nil {
		return "", "", err
	}
	// The channel goes on the first row and each file on a row of its own: the
	// server answers a file named on the first row with no URL.
	rows, err := c.Send(ctx, s3Request("s3ft_getpresignedurl", channelID, opts.Password, nil, [][][2]string{{
		{"key", full},
		{"verb", verb},
		{"length", strconv.FormatUint(length, 10)},
	}}))
	if err != nil {
		return "", "", err
	}
	for _, row := range rows {
		if row["url"] == "" {
			continue
		}
		if row["key"] != "" {
			full = row["key"]
		}

		return full, row["url"], nil
	}

	return "", "", teamspeak.ErrNoData
}

// InitS3FileUpload asks the server to sign an upload of size bytes to path in a
// channel's S3 file area. Pass the result to UploadS3FileData to send the file,
// then to CompleteS3FileUpload; UploadS3File does all three.
//
// The upload replaces a file already at the path: the storage keeps no other
// copy, and nothing asks first. A client without upload power is refused with
// 2049 (invalid file permissions). A path into a directory the channel's file
// list does not have yet needs directory create power as well, and is refused
// with 2049 without it; an area with no files at all takes any path. The
// directory is no object of its own: it is there while a file is in it.
//
// It returns *S3UnsupportedError unless the server names "s3" among its
// extensions, and an error wrapping teamspeak.ErrInvalidCommand for a path
// that cannot be sent (see UploadS3File).
func (c *Client) InitS3FileUpload(
	ctx context.Context, channelID teamspeak.ChannelID, path string, size uint64, opts S3FileOptions,
) (*S3FileUploadInfo, error) {
	key, signed, err := c.presign(ctx, channelID, path, "PUT", size, opts)
	if err != nil {
		return nil, err
	}

	return &S3FileUploadInfo{ChannelID: channelID, Path: key, Size: size, URL: signed}, nil
}

// InitS3FileDownload asks the server to sign a download of path from a
// channel's S3 file area. Pass the result to DownloadS3FileData;
// DownloadS3File does both.
//
// The server signs a download whether or not the file is there: a missing one
// is the 404 of the download itself. A client without download power is refused
// with 2049 (invalid file permissions), as is a channel that does not exist.
func (c *Client) InitS3FileDownload(
	ctx context.Context, channelID teamspeak.ChannelID, path string, opts S3FileOptions,
) (*S3FileDownloadInfo, error) {
	key, signed, err := c.presign(ctx, channelID, path, "GET", 0, opts)
	if err != nil {
		return nil, err
	}

	return &S3FileDownloadInfo{ChannelID: channelID, Path: key, URL: signed}, nil
}

// succeeded reads the success of an answer that reports one, or returns
// teamspeak.ErrNoData for an answer without it.
func succeeded(rows []map[string]string) (bool, error) {
	for _, row := range rows {
		if v, ok := row["success"]; ok {
			return v == "1", nil
		}
	}

	return false, teamspeak.ErrNoData
}

// CompleteS3FileUpload tells the server an upload is stored, after
// UploadS3FileData. The server then reads the channel's file list from the
// storage again, and lists the file; without this it does not.
//
// It returns an *S3TransferError when the server reports that its own request
// to the storage failed.
func (c *Client) CompleteS3FileUpload(ctx context.Context, info *S3FileUploadInfo, opts S3FileOptions) error {
	err := c.assertS3()
	if err != nil {
		return err
	}
	// The server reads the channel and nothing else: measured on TeamSpeak 6
	// 6.0.0-beta13.1, it lists the channel again whatever else the command says.
	rows, err := c.Send(ctx, s3Request("s3ft_upload_done_notification", info.ChannelID, opts.Password, nil, nil))
	if err != nil {
		return err
	}
	ok, err := succeeded(rows)
	if err != nil {
		return err
	}
	if !ok {
		return &S3TransferError{
			msg: fmt.Sprintf("the server could not read the file list of channel %d from its storage", info.ChannelID),
		}
	}

	return nil
}

// ListS3Files returns every file in a channel's S3 file area, in the storage's
// order (by path), as the server last read them from the storage.
//
// The list is the whole area, files in directories included: there are no
// directories, only paths. A file uploaded without CompleteS3FileUpload is
// missing from it until the server reads the list again. A channel that does
// not exist has no files.
func (c *Client) ListS3Files(
	ctx context.Context, channelID teamspeak.ChannelID, opts S3FileOptions,
) ([]S3FileEntry, error) {
	err := c.assertS3()
	if err != nil {
		return nil, err
	}
	rows, err := c.Send(ctx, s3Request("s3ft_list_files", channelID, opts.Password, nil, nil))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if field, ok := row["b64_json"]; ok {
			return parseS3FileList(field)
		}
	}

	return nil, teamspeak.ErrNoData
}

// DeleteS3File deletes one file from a channel's S3 file area. The server
// deletes it from the storage and from the file list it keeps.
//
// Deleting a file that is not there succeeds, as the storage's delete does. A
// client without delete power is refused with 2568 (insufficient client
// permissions). It returns an *S3TransferError when the server reports that its
// own request to the storage failed.
func (c *Client) DeleteS3File(
	ctx context.Context, channelID teamspeak.ChannelID, path string, opts S3FileOptions,
) error {
	err := c.assertS3()
	if err != nil {
		return err
	}
	key, err := s3Path(path)
	if err != nil {
		return err
	}
	// One file per command: the server deletes the file on the first row and
	// passes over any further row.
	rows, err := c.Send(ctx, s3Request("s3ft_deletefile", channelID, opts.Password, [][2]string{{"key", key}}, nil))
	if err != nil {
		return err
	}
	ok, err := succeeded(rows)
	if err != nil {
		return err
	}
	if !ok {
		return &S3TransferError{msg: "the server could not delete " + key + " from its storage"}
	}

	return nil
}

// errMalformedS3FileList is a file list the server sent that cannot be read.
var errMalformedS3FileList = fmt.Errorf("%w: the server answered s3ft_list_files with a malformed file list",
	teamspeak.ErrNoData)

// parseS3FileList reads the file list the server sends for s3ft_list_files:
// base64 of the JSON {"contents":[{"key":"dir/a.txt","last_modified":"...","size":2}]},
// each key from the channel's root without a leading slash, and an empty field
// for no files. A list that is not that is an error wrapping
// teamspeak.ErrNoData.
func parseS3FileList(field string) ([]S3FileEntry, error) {
	if field == "" {
		return []S3FileEntry{}, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(field, "="))
	if err != nil {
		return nil, errMalformedS3FileList
	}
	var list struct {
		Contents *[]json.RawMessage `json:"contents"`
	}
	err = json.Unmarshal(raw, &list)
	if err != nil || list.Contents == nil {
		return nil, errMalformedS3FileList
	}

	out := make([]S3FileEntry, 0, len(*list.Contents))
	for _, item := range *list.Contents {
		entry, ok := parseS3FileEntry(item)
		if !ok {
			return nil, errMalformedS3FileList
		}
		out = append(out, entry)
	}

	return out, nil
}

// parseS3FileEntry reads one item of the file list; ok is false for one that is
// not a key (a string) and a size (a non-negative whole number).
func parseS3FileEntry(item json.RawMessage) (S3FileEntry, bool) {
	var file struct {
		Key          json.RawMessage `json:"key"`
		Size         json.RawMessage `json:"size"`
		LastModified json.RawMessage `json:"last_modified"`
	}
	var key string
	if json.Unmarshal(item, &file) != nil || !isJSONString(file.Key) || json.Unmarshal(file.Key, &key) != nil {
		return S3FileEntry{}, false
	}
	size, err := strconv.ParseUint(string(file.Size), 10, 64)
	if err != nil {
		return S3FileEntry{}, false
	}
	entry := S3FileEntry{Path: key, Size: size}
	if !strings.HasPrefix(key, "/") {
		entry.Path = "/" + key
	}
	var stamp string
	if isJSONString(file.LastModified) && json.Unmarshal(file.LastModified, &stamp) == nil {
		// RFC 3339 reads the fractional seconds the storage sends; one it
		// cannot read leaves the zero time.
		modified, parseErr := time.Parse(time.RFC3339, stamp)
		if parseErr == nil {
			entry.ModifiedAt = modified
		}
	}

	return entry, true
}

func isJSONString(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] == '"'
}

// exactBody is the body of an upload: exactly size bytes of data. A request
// signed for a length is refused by the storage when the body is another, and
// net/http would send fewer bytes or cut off the rest without saying why, so
// the body fails the request itself, with a message that says so.
type exactBody struct {
	data io.Reader
	// err is the failure the body ended the request with, kept so it is
	// reported as the cause, not as the transport's account of it.
	err  error
	size uint64
	read uint64
}

func (b *exactBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.read == b.size {
		// One more byte would be more than was declared.
		var extra [1]byte
		n, err := io.ReadFull(b.data, extra[:])
		switch {
		case n > 0:
			b.err = fmt.Errorf("%w: file transfer sent more than the declared %d bytes", teamspeak.ErrFileTransfer, b.size)
		case err != nil && !errors.Is(err, io.EOF):
			b.err = fmt.Errorf("%w: upload: %w", teamspeak.ErrFileTransfer, err)
		default:
			return 0, io.EOF
		}

		return 0, b.err
	}
	if left := b.size - b.read; uint64(len(p)) > left {
		p = p[:left]
	}
	n, err := b.data.Read(p)
	b.read += uint64(n) //nolint:gosec // n is not negative
	switch {
	case errors.Is(err, io.EOF) && b.read < b.size:
		b.err = fmt.Errorf("%w: file transfer ended after %d of the declared %d bytes: %w",
			teamspeak.ErrFileTransfer, b.read, b.size, io.ErrUnexpectedEOF)
	case err != nil && !errors.Is(err, io.EOF):
		b.err = fmt.Errorf("%w: upload: %w", teamspeak.ErrFileTransfer, err)
	default:
		return n, nil
	}

	return n, b.err
}

// noURL returns err without the URL a *url.Error names: the URL of a presigned
// request is a credential, and no message may carry it.
func noURL(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return urlErr.Err
	}

	return err
}

var s3ErrorCode = regexp.MustCompile(`<Code>([^<]{1,128})</Code>`)

// storageRefused turns the storage's answer to a request that failed into an
// *S3TransferError. The body is read only for its <Code>, and only so far.
func storageRefused(what string, resp *http.Response) *S3TransferError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, s3ErrorBodyLimit))
	msg := fmt.Sprintf("the storage refused %s: HTTP %d", what, resp.StatusCode)
	var code string
	if m := s3ErrorCode.FindSubmatch(body); m != nil {
		code = string(m[1])
		msg += " " + code
	}

	return &S3TransferError{Status: resp.StatusCode, Code: code, msg: msg}
}

// requestFailedOr is ctx's error wrapped as requestFailed has it when ctx has
// ended, and failure otherwise.
func requestFailedOr(ctx context.Context, what string, failure error) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return fmt.Errorf("%w: %s: %w", teamspeak.ErrFileTransfer, what, ctxErr)
	}

	return failure
}

// requestFailed reports a request that got no answer: ctx's error when ctx
// ended it, wrapped so that it matches both teamspeak.ErrFileTransfer and
// ctx.Err(); otherwise an *S3TransferError with the cause.
func requestFailed(ctx context.Context, what string, err error) error {
	return requestFailedOr(ctx, what, &S3TransferError{Err: noURL(err), msg: what + " got no answer from the storage"})
}

// UploadS3FileData sends a file to the storage, over an upload
// InitS3FileUpload signed. data must give exactly info.Size bytes: a reader
// that gives fewer or more fails the upload, and nothing is stored.
//
// It returns once the storage has answered that it stored the file. Then call
// CompleteS3FileUpload, or the server does not list it. A failure of the
// request is an *S3TransferError: Status 403 for a URL that expired. A data
// that is the wrong length, or fails reading, is an error wrapping
// teamspeak.ErrFileTransfer; so is one from ctx ending the request, which
// matches ctx.Err() too.
func UploadS3FileData(ctx context.Context, info *S3FileUploadInfo, data io.Reader, opts S3TransferOptions) error {
	what := "the upload of " + info.Path
	body := &exactBody{data: data, size: info.Size}
	var reader io.Reader = body
	if info.Size == 0 {
		// A zero length goes out as Content-Length: 0 only with no body at
		// all; a reader of unknown length would be sent chunked.
		reader = http.NoBody
		var extra [1]byte
		if n, _ := io.ReadFull(data, extra[:]); n > 0 {
			return fmt.Errorf("%w: file transfer sent more than the declared 0 bytes", teamspeak.ErrFileTransfer)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, info.URL, reader)
	if err != nil {
		return &S3TransferError{Err: noURL(err), msg: what + " could not be sent"}
	}
	// Signed with the URL: the storage refuses a body of another length.
	req.ContentLength = int64(info.Size) //nolint:gosec // a size the server signs is under 5 GiB
	resp, err := opts.client().Do(req)
	if err != nil {
		if body.err != nil && ctx.Err() == nil {
			return body.err
		}

		return requestFailed(ctx, what, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return storageRefused(what, resp)
	}

	return nil
}

// trackedWriter remembers the error its writer returned, to tell it from one of
// the storage's body.
type trackedWriter struct {
	w   io.Writer
	err error
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if err != nil {
		t.err = err
	}

	return n, err
}

// openS3Download asks the storage for the file from seek on, and checks that it
// answered with it. skip is how many bytes of the body to drop: those a storage
// that ignored the range sent. The caller closes the body.
func openS3Download(
	ctx context.Context, info *S3FileDownloadInfo, seek uint64, opts S3TransferOptions,
) (*http.Response, uint64, error) {
	what := "the download of " + info.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.URL, http.NoBody)
	if err != nil {
		return nil, 0, &S3TransferError{Err: noURL(err), msg: what + " could not be sent"}
	}
	if seek > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatUint(seek, 10)+"-")
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return nil, 0, requestFailed(ctx, what, err)
	}
	// 206 is the part asked for; a storage that ignores the range sends the
	// whole file with 200, and the bytes before the offset are dropped.
	switch {
	case resp.StatusCode == http.StatusOK && seek > 0:
		return resp, seek, nil
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusPartialContent && seek > 0:
		return resp, 0, nil
	}
	refusal := storageRefused(what, resp)
	_ = resp.Body.Close()

	return nil, 0, refusal
}

// writeS3Body writes a response's body into dest, less its first skip bytes.
func writeS3Body(
	ctx context.Context, info *S3FileDownloadInfo, resp *http.Response, skip uint64, dest io.Writer,
) error {
	what := "the download of " + info.Path
	if skip > 0 {
		_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(min(skip, math.MaxInt64))))
		if err != nil {
			return brokeOff(ctx, what, err)
		}
	}
	tracked := &trackedWriter{w: dest}
	_, err := io.Copy(tracked, resp.Body)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return fmt.Errorf("%w: %s: %w", teamspeak.ErrFileTransfer, what, ctx.Err())
	case tracked.err != nil:
		// The caller's writer failing is its own error, not the storage's.
		if errors.Is(err, teamspeak.ErrFileTransfer) {
			return err
		}

		return fmt.Errorf("%w: %s: %w", teamspeak.ErrFileTransfer, what, err)
	}

	return brokeOff(ctx, what, err)
}

// brokeOff reports a body that stopped before its end.
func brokeOff(ctx context.Context, what string, err error) error {
	return requestFailedOr(ctx, what, &S3TransferError{Err: noURL(err), msg: what + " broke off"})
}

// DownloadS3FileData reads a file from the storage into dest, over a download
// InitS3FileDownload signed. It returns once the file is written; dest is not
// closed.
//
// A file that is not there is an *S3TransferError with Status 404; a URL that
// expired, one with 403. A body that stops short is an *S3TransferError too,
// and dest keeps what had arrived. An error of dest, or of ctx ending the
// request, wraps teamspeak.ErrFileTransfer.
func DownloadS3FileData(
	ctx context.Context, info *S3FileDownloadInfo, dest io.Writer, opts S3DownloadOptions,
) error {
	resp, skip, err := openS3Download(ctx, info, opts.SeekPosition, opts.Transfer)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return writeS3Body(ctx, info, resp, skip, dest)
}

// UploadS3FileOptions are UploadS3File's optional parameters.
type UploadS3FileOptions struct {
	// Transfer says how the request reaches the storage.
	Transfer S3TransferOptions
	// Password is the channel's password, "" for none.
	Password string
}

// UploadS3File uploads data into a channel's S3 file area in one call: it signs
// the upload (InitS3FileUpload), sends the file to the storage
// (UploadS3FileData) and tells the server it is stored (CompleteS3FileUpload).
// It returns once the storage has stored the file and the server lists it. The
// file replaces one already at the path. For a stream, call the three yourself.
//
// path runs from the channel's root; a leading slash is added when missing. A
// path into a directory the server does not list yet needs directory create
// power, as InitS3FileUpload says. A path is refused with an error
// wrapping teamspeak.ErrInvalidCommand when an HTTP client would not send the
// URL the server signs for it: one with an empty, "." or ".." segment, a
// control character, or a slash at its end.
//
// A refusal by the server is the *teamspeak.ServerError it sends (2049 for a
// client without upload power); a failure of the storage request, or a server
// that reports its own request to the storage failed, is an *S3TransferError. A
// server that does not name "s3" among its extensions is refused with an
// *S3UnsupportedError before anything is sent.
func (c *Client) UploadS3File(
	ctx context.Context, channelID teamspeak.ChannelID, path string, data []byte, opts UploadS3FileOptions,
) error {
	files := S3FileOptions{Password: opts.Password}
	info, err := c.InitS3FileUpload(ctx, channelID, path, uint64(len(data)), files)
	if err != nil {
		return err
	}
	err = UploadS3FileData(ctx, info, bytes.NewReader(data), opts.Transfer)
	if err != nil {
		return err
	}

	return c.CompleteS3FileUpload(ctx, info, files)
}

// DownloadS3FileOptions are DownloadS3File's optional parameters.
type DownloadS3FileOptions struct {
	// Transfer says how the request reaches the storage.
	Transfer S3TransferOptions
	// Password is the channel's password, "" for none.
	Password string
	// SeekPosition starts the download there: the bytes are the file's from that
	// offset to its end.
	SeekPosition uint64
	// MaxSize is the most bytes DownloadS3File will hold in memory. A larger
	// download is refused before its body is read when the storage announces its
	// size, and as it arrives when it does not. Zero means 64 MiB.
	MaxSize uint64
}

// DownloadS3File downloads a file from a channel's S3 file area into memory in
// one call: it signs the download (InitS3FileDownload) and reads the file
// (DownloadS3FileData). For a file too large to hold call the two yourself with
// a writer of your own.
//
// A file that is not there is an *S3TransferError with Status 404. A download
// of more than MaxSize bytes fails with an error wrapping
// teamspeak.ErrFileTransfer. Paths and refusals are as for UploadS3File.
func (c *Client) DownloadS3File(
	ctx context.Context, channelID teamspeak.ChannelID, path string, opts DownloadS3FileOptions,
) ([]byte, error) {
	limit := opts.MaxSize
	if limit == 0 {
		limit = defaultS3DownloadLimit
	}
	info, err := c.InitS3FileDownload(ctx, channelID, path, S3FileOptions{Password: opts.Password})
	if err != nil {
		return nil, err
	}
	resp, skip, err := openS3Download(ctx, info, opts.SeekPosition, opts.Transfer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf limitedBuffer
	buf.limit = limit
	if resp.ContentLength >= 0 {
		announced := uint64(resp.ContentLength)
		if announced > skip && announced-skip > limit {
			return nil, fmt.Errorf("%w: the download is %d bytes, over the %d the call holds in memory",
				teamspeak.ErrFileTransfer, announced-skip, limit)
		}
		// Sized up front when the announcement is a size a buffer can have.
		if announced <= math.MaxInt32 {
			buf.buf.Grow(int(announced))
		}
	}
	err = writeS3Body(ctx, info, resp, skip, &buf)
	if err != nil {
		return nil, err
	}

	return buf.buf.Bytes(), nil
}

// limitedBuffer collects at most limit bytes, and fails on the first byte
// beyond that. A storage that announced no length is held to the limit as it
// sends.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit uint64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	held := uint64(b.buf.Len()) //nolint:gosec // a length is not negative
	if held+uint64(len(p)) > b.limit {
		return 0, fmt.Errorf("%w: the download is over the %d bytes the call holds in memory",
			teamspeak.ErrFileTransfer, b.limit)
	}

	return b.buf.Write(p)
}
