//go:build integration

package serverquery_test

// Integration tests for the one-call file transfers and the recursive listing,
// over each query transport that reaches the file commands and over the voice
// protocol. Each makes a channel of its own, and the files in it go with it.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// fileClient is what both the query client and the voice client offer.
type fileClient interface {
	CreateDirectory(ctx context.Context, cid teamspeak.ChannelID, dir string, opts teamspeak.FileOptions) error
	UploadFile(
		ctx context.Context, host string, cid teamspeak.ChannelID, path string, data []byte,
		opts teamspeak.UploadFileOptions,
	) error
	DownloadFile(
		ctx context.Context, host string, cid teamspeak.ChannelID, path string, opts teamspeak.DownloadFileOptions,
	) ([]byte, error)
	ListFilesRecursive(
		ctx context.Context, cid teamspeak.ChannelID, path string, opts teamspeak.RecursiveFilesOptions,
	) ([]teamspeak.FileTreeEntry, error)
	InitFileUpload(
		ctx context.Context, cid teamspeak.ChannelID, path string, size uint64, opts teamspeak.FileUploadOptions,
	) (*teamspeak.FileUploadInfo, error)
	GetFileInfo(
		ctx context.Context, cid teamspeak.ChannelID, path string, opts teamspeak.FileOptions,
	) (teamspeak.FileEntry, error)
	StopFileTransfer(
		ctx context.Context, id teamspeak.ServerFileTransferID, opts teamspeak.FileTransferStopOptions,
	) error
}

// waitForFiles lists recursively until the server shows want, the sizes
// included.
func waitForFiles(
	ctx context.Context, t *testing.T, c fileClient, cid teamspeak.ChannelID, want map[string]uint64,
) []teamspeak.FileTreeEntry {
	t.Helper()
	var got []teamspeak.FileTreeEntry
	deadline := time.Now().Add(15 * time.Second)
	for {
		var err error
		got, err = c.ListFilesRecursive(ctx, cid, "/", teamspeak.RecursiveFilesOptions{})
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListFilesRecursive: %v", err)
		}
		have := map[string]uint64{}
		for _, e := range got {
			have[e.Path] = e.Size
		}
		if reflect.DeepEqual(have, want) || time.Now().After(deadline) {
			if !reflect.DeepEqual(have, want) {
				t.Errorf("the listing = %v, want %v", have, want)
			}

			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

//nolint:funlen // one scenario, step by step
func runFileTransfers(t *testing.T, actor fileClient, c *serverquery.Client) {
	t.Helper()
	ctx := adminCtx(t)
	cid := scratchChannel(t, c, "ts-go-oneshot-")
	opts := teamspeak.UploadFileOptions{Overwrite: true}

	err := actor.CreateDirectory(ctx, cid, "/docs", teamspeak.FileOptions{})
	skipOutOfScope(t, err, "CreateDirectory")
	skipUnlessAllowed(t, err, "CreateDirectory")
	if err != nil {
		t.Fatalf("CreateDirectory: %v", err)
	}
	cleanup(t, "the files", func(ctx context.Context) error {
		names := []string{"/docs", "/top.txt", "/whole.bin", "/part.bin", "/short.bin", "/long.bin", "/stopped.bin"}
		delErr := c.DeleteFile(ctx, cid, names, teamspeak.FileOptions{})
		if delErr != nil && !errors.Is(delErr, errcode.FileNotFound) && !errors.Is(delErr, errcode.FileInvalidPath) &&
			serverCode(delErr) != 5120 {
			return delErr
		}

		return nil
	})
	err = actor.CreateDirectory(ctx, cid, "/docs/inner", teamspeak.FileOptions{})
	if err != nil {
		t.Fatalf("CreateDirectory under it: %v", err)
	}

	// A file with every byte value, larger than one transfer chunk.
	big := make([]byte, 100<<10)
	for i := range big {
		big[i] = byte(i)
	}
	files := map[string][]byte{"/top.txt": []byte("hello"), "/docs/a.bin": big, "/docs/inner/b.txt": []byte("deep")}
	for path, data := range files {
		err = actor.UploadFile(ctx, transferHost, cid, path, data, opts)
		skipUnlessAllowed(t, err, "UploadFile")
		if err != nil {
			t.Fatalf("UploadFile %s: %v", path, err)
		}
	}

	want := map[string]uint64{
		"/top.txt": 5, "/docs": 0, "/docs/a.bin": uint64(len(big)), "/docs/inner": 0, "/docs/inner/b.txt": 4,
	}
	listed := waitForFiles(ctx, t, actor, cid, want)
	// A directory is listed before what it holds.
	index := func(path string) int {
		return slices.IndexFunc(listed, func(e teamspeak.FileTreeEntry) bool { return e.Path == path })
	}
	if index("/docs") > index("/docs/a.bin") || index("/docs/inner") > index("/docs/inner/b.txt") {
		t.Errorf("the listing is %v, want each directory before its contents", listed)
	}
	for _, e := range listed {
		if e.IsDirectory != (e.Path == "/docs" || e.Path == "/docs/inner") {
			t.Errorf("%s: IsDirectory = %v", e.Path, e.IsDirectory)
		}
	}

	for path, data := range files {
		got, dlErr := actor.DownloadFile(ctx, transferHost, cid, path, teamspeak.DownloadFileOptions{})
		if dlErr != nil || !bytes.Equal(got, data) {
			t.Errorf("DownloadFile %s = %d bytes, %v, want the %d uploaded", path, len(got), dlErr, len(data))
		}
	}

	assertRecursiveBounds(ctx, t, actor, cid)
	assertTransferRefusals(ctx, t, actor, c, cid)
	assertResumeAndSizes(ctx, t, actor, c, cid)
	assertTransfersThatDoNotComplete(ctx, t, actor, c, cid)
}

var errConnectionRefused = errors.New("connection refused")

// refusedDialer is a TCP connect that is refused: nothing reaches the server.
type refusedDialer struct{}

func (refusedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errConnectionRefused
}

// stoppingDialer opens the real connection, and has the transfer stopped by its
// own connection while the data is going, after the first chunks.
type stoppingDialer struct {
	stop func()
}

func (d stoppingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	return &stoppingConn{Conn: conn, stop: d.stop}, nil
}

type stoppingConn struct {
	net.Conn

	stop   func()
	writes int
}

func (c *stoppingConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 3 { // the key, then two chunks
		c.stop()
		time.Sleep(300 * time.Millisecond)
	}

	return c.Conn.Write(p)
}

// assertTransfersThatDoNotComplete checks that a transfer whose dial is refused
// is stopped on the server, and that an upload the server stopped fails
// though its connection closed. Measured on TeamSpeak 3 3.13.8 and TeamSpeak 6
// 6.0.0: left alone, a negotiated transfer nobody dialled is dropped after 10
// s. Only the connection's own transfer is stopped: ftstop of anyone else's
// crashes TeamSpeak 6.
func assertTransfersThatDoNotComplete(
	ctx context.Context, t *testing.T, actor fileClient, c *serverquery.Client, cid teamspeak.ChannelID,
) {
	t.Helper()
	data := make([]byte, 100_000)

	err := actor.UploadFile(ctx, transferHost, cid, "/never.bin", data,
		teamspeak.UploadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: refusedDialer{}}})
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("UploadFile to a refused port: %v, want ErrFileTransfer", err)
	}
	// Seconds, not the 10 the server would take on its own.
	waitNoTransfersWithin(ctx, t, c, cid, 4*time.Second)
	_, err = actor.DownloadFile(ctx, transferHost, cid, "/whole.bin",
		teamspeak.DownloadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: refusedDialer{}}})
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("DownloadFile from a refused port: %v, want ErrFileTransfer", err)
	}
	waitNoTransfersWithin(ctx, t, c, cid, 4*time.Second)

	stop := func() {
		active, listErr := c.ListActiveTransfers(ctx)
		if listErr != nil {
			t.Errorf("ListActiveTransfers: %v", listErr)

			return
		}
		for _, a := range active {
			if strings.HasSuffix(a.Path, "channel_"+strconv.FormatUint(uint64(cid), 10)) {
				stopErr := actor.StopFileTransfer(ctx, a.ServerFileTransferID, teamspeak.FileTransferStopOptions{})
				if stopErr != nil {
					t.Errorf("StopFileTransfer: %v", stopErr)
				}
			}
		}
	}
	err = actor.UploadFile(ctx, transferHost, cid, "/stopped.bin", make([]byte, 200_000),
		teamspeak.UploadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: stoppingDialer{stop: stop}}})
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("UploadFile the server stopped: %v, want ErrFileTransfer", err)
	}
	waitNoTransfers(ctx, t, c, cid)
}

// waitNoTransfersWithin is waitNoTransfers with a deadline of its own.
func waitNoTransfersWithin(
	ctx context.Context, t *testing.T, c *serverquery.Client, cid teamspeak.ChannelID, within time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		active, err := c.ListActiveTransfers(ctx)
		if err != nil && serverCode(err) != 5120 {
			t.Fatalf("ListActiveTransfers: %v", err)
		}
		mine := slices.DeleteFunc(slices.Clone(active), func(a teamspeak.ActiveTransfer) bool {
			return !strings.HasSuffix(a.Path, "channel_"+strconv.FormatUint(uint64(cid), 10))
		})
		if len(mine) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the refused transfer is still active after %v: %+v", within, mine)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// assertRecursiveBounds checks MaxDepth and a listing that starts below the top.
func assertRecursiveBounds(ctx context.Context, t *testing.T, actor fileClient, cid teamspeak.ChannelID) {
	t.Helper()
	// One level is the top's own entries, two reach into docs.
	for depth, wantPaths := range map[int][]string{
		1: {"/docs", "/top.txt"},
		2: {"/docs", "/docs/a.bin", "/docs/inner", "/top.txt"},
	} {
		got, listErr := actor.ListFilesRecursive(ctx, cid, "/", teamspeak.RecursiveFilesOptions{MaxDepth: depth})
		if listErr != nil {
			t.Fatalf("ListFilesRecursive depth %d: %v", depth, listErr)
		}
		paths := make([]string, len(got))
		for i, e := range got {
			paths[i] = e.Path
		}
		slices.Sort(paths)
		if !slices.Equal(paths, wantPaths) {
			t.Errorf("depth %d: %v, want %v", depth, paths, wantPaths)
		}
	}
	below, err := actor.ListFilesRecursive(ctx, cid, "/docs", teamspeak.RecursiveFilesOptions{})
	if err != nil || len(below) != 3 || below[0].Path != "/docs/a.bin" && below[0].Path != "/docs/inner" {
		t.Errorf("below /docs = %+v, %v, want its three entries with full paths", below, err)
	}
}

// assertTransferRefusals checks what the calls do when the server or the limit says no.
func assertTransferRefusals(
	ctx context.Context, t *testing.T, actor fileClient, c *serverquery.Client, cid teamspeak.ChannelID,
) {
	t.Helper()
	// A file that is there is refused without Overwrite, as the server says.
	err := actor.UploadFile(ctx, transferHost, cid, "/top.txt", []byte("again"), teamspeak.UploadFileOptions{})
	if !errors.Is(err, errcode.FileAlreadyExists) || serverCode(err) != 2050 {
		t.Errorf("UploadFile over an existing file without Overwrite: %v, want the server's 2050", err)
	}
	// A file over the limit is refused before it is fetched.
	_, err = actor.DownloadFile(ctx, transferHost, cid, "/docs/a.bin", teamspeak.DownloadFileOptions{MaxSize: 1000})
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("DownloadFile over the limit: %v, want ErrFileTransfer", err)
	}
	// The refused download left no transfer behind on the server.
	active, err := c.ListActiveTransfers(ctx)
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) && serverCode(err) != 5120 {
		t.Fatalf("ListActiveTransfers: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("after the refusals the server lists active transfers %+v, want none", active)
	}
	_, err = actor.DownloadFile(ctx, transferHost, cid, "/nothing.txt", teamspeak.DownloadFileOptions{})
	if !errors.Is(err, errcode.FileNotFound) || serverCode(err) != 2051 {
		t.Errorf("DownloadFile of a missing file: %v, want the server's 2051", err)
	}
	_, err = actor.ListFilesRecursive(ctx, cid, "/nothing", teamspeak.RecursiveFilesOptions{})
	if !errors.Is(err, errcode.FileNotFound) && !errors.Is(err, errcode.FileInvalidPath) && serverCode(err) != 2052 {
		t.Errorf("ListFilesRecursive of a missing path: %v, want the server's refusal", err)
	}
}

// cutUpload starts an upload of data into path and breaks it off after 40000
// bytes, then waits until the server shows the partial file.
func cutUpload(
	ctx context.Context, t *testing.T, actor fileClient, cid teamspeak.ChannelID, path string, data []byte,
) {
	t.Helper()
	up, err := actor.InitFileUpload(ctx, cid, path, uint64(len(data)), teamspeak.FileUploadOptions{})
	if err != nil {
		t.Fatalf("InitFileUpload: %v", err)
	}
	conn, err := teamspeak.DialFileTransfer(
		ctx, transferHost, up.Port, up.FileTransferKey, teamspeak.FileTransferOptions{})
	if err != nil {
		t.Fatalf("DialFileTransfer: %v", err)
	}
	_, err = conn.Write(data[:40_000])
	_ = conn.Close()
	if err != nil {
		t.Fatalf("writing the first part: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		info, infoErr := actor.GetFileInfo(ctx, cid, path, teamspeak.FileOptions{})
		if infoErr == nil && info.Size == 40_000 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the partial file is %+v, %v, want 40000 bytes", info, infoErr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitNoTransfers waits until none of the channel's transfers is running.
// Closing the connection ends a transfer on the server. Other suites may
// transfer too, so only this channel's files count.
func waitNoTransfers(ctx context.Context, t *testing.T, c *serverquery.Client, cid teamspeak.ChannelID) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		active, err := c.ListActiveTransfers(ctx)
		if err != nil && serverCode(err) != 5120 {
			t.Fatalf("ListActiveTransfers: %v", err)
		}
		mine := slices.DeleteFunc(slices.Clone(active), func(a teamspeak.ActiveTransfer) bool {
			return !strings.HasSuffix(a.Path, "channel_"+strconv.FormatUint(uint64(cid), 10))
		})
		if len(mine) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("transfers still active in the channel: %+v", mine)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// assertResumeAndSizes checks what the upload and download calls promise about
// the server's state: the file is there when the upload returns, a cut-off
// upload resumes and a download starts from an offset, and a reader of the
// wrong length fails.
func assertResumeAndSizes(
	ctx context.Context, t *testing.T, actor fileClient, c *serverquery.Client, cid teamspeak.ChannelID,
) {
	t.Helper()
	data := make([]byte, 100_000)
	for i := range data {
		data[i] = byte(i * 7)
	}

	// The upload returns when the server has the file: the size is there at
	// once, with no waiting.
	err := actor.UploadFile(ctx, transferHost, cid, "/whole.bin", data, teamspeak.UploadFileOptions{})
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	info, err := actor.GetFileInfo(ctx, cid, "/whole.bin", teamspeak.FileOptions{})
	if err != nil || info.Size != uint64(len(data)) {
		t.Errorf("right after UploadFile the file is %+v, %v, want %d bytes", info, err, len(data))
	}

	// An upload cut off leaves a partial file, and resuming sends the rest.
	cutUpload(ctx, t, actor, cid, "/part.bin", data)
	err = actor.UploadFile(ctx, transferHost, cid, "/part.bin", data, teamspeak.UploadFileOptions{Resume: true})
	if err != nil {
		t.Fatalf("UploadFile with Resume: %v", err)
	}
	got, err := actor.DownloadFile(ctx, transferHost, cid, "/part.bin", teamspeak.DownloadFileOptions{})
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("the resumed file is %d bytes, %v, want the %d uploaded", len(got), err, len(data))
	}

	// A download from an offset brings the rest of the file.
	tail, err := actor.DownloadFile(ctx, transferHost, cid, "/whole.bin",
		teamspeak.DownloadFileOptions{SeekPosition: 40_000})
	if err != nil || !bytes.Equal(tail, data[40_000:]) {
		t.Errorf("DownloadFile from 40000 = %d bytes, %v, want the last %d", len(tail), err, len(data)-40_000)
	}

	// A reader of the wrong length fails, whichever way it is wrong.
	for name, size := range map[string]int{"/short.bin": 1000, "/long.bin": 100} {
		up, initErr := actor.InitFileUpload(ctx, cid, name, uint64(size), teamspeak.FileUploadOptions{})
		if initErr != nil {
			t.Fatalf("InitFileUpload %s: %v", name, initErr)
		}
		err = teamspeak.UploadFileData(ctx, transferHost, up, bytes.NewReader(data[:500]),
			teamspeak.FileTransferOptions{})
		if !errors.Is(err, teamspeak.ErrFileTransfer) {
			t.Errorf("UploadFileData of 500 bytes declared as %d: %v, want ErrFileTransfer", size, err)
		}
	}
	waitNoTransfers(ctx, t, c, cid)
}

func TestQueryFiles_OneCallTransfers(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		runFileTransfers(t, c, c)
	})
}

func TestVoiceFiles_OneCallTransfers(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		if transport != "ssh" {
			t.Skip("the voice variant runs once, beside the SSH connection")
		}
		ctx := adminCtx(t)
		groups, err := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
		if err != nil {
			t.Fatalf("ListServerGroups: %v", err)
		}
		i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool {
			return g.Type == teamspeak.GroupRegular && g.Name == "Server Admin"
		})
		if i < 0 {
			t.Skip("no regular Server Admin group for a voice client to manage files with")
		}
		// Voice connects are kept to one a second, as the servers limit them.
		time.Sleep(1100 * time.Millisecond)
		voice := voiceClient(t, "ts-go-ft-"+strconv.FormatInt(time.Now().UnixNano()%1e6, 36))
		dbid := databaseIDOf(ctx, t, c, voice)
		err = c.AddClientToServerGroup(ctx, groups[i].ID, dbid)
		if err != nil {
			t.Fatalf("making the voice client an admin: %v", err)
		}
		cleanup(t, "the voice client's group", func(ctx context.Context) error {
			delErr := c.RemoveClientFromServerGroup(ctx, groups[i].ID, dbid)
			if errors.Is(delErr, errcode.PermissionEmptyResult) {
				return nil
			}

			return delErr
		})
		runFileTransfers(t, voice, c)
	})
}
