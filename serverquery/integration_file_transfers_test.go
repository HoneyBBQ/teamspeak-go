//go:build integration

package serverquery_test

// Integration tests for the one-call file transfers and the recursive listing,
// over each query transport that reaches the file commands and over the voice
// protocol. Each makes a channel of its own, and the files in it go with it.

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
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
}

// waitForFiles lists recursively until the server shows want, the sizes
// included: it finishes writing an upload a moment after the connection closes.
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
		delErr := c.DeleteFile(ctx, cid, []string{"/docs", "/top.txt"}, teamspeak.FileOptions{})
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
	assertTransferRefusals(ctx, t, actor, cid)
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
func assertTransferRefusals(ctx context.Context, t *testing.T, actor fileClient, cid teamspeak.ChannelID) {
	t.Helper()
	// A file that is there is refused without Overwrite, as the server says.
	err := actor.UploadFile(ctx, transferHost, cid, "/top.txt", []byte("again"), teamspeak.UploadFileOptions{})
	if err == nil {
		t.Error("UploadFile over an existing file without Overwrite succeeded")
	}
	// A file over the limit is refused before it is fetched.
	_, err = actor.DownloadFile(ctx, transferHost, cid, "/docs/a.bin", teamspeak.DownloadFileOptions{MaxSize: 1000})
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("DownloadFile over the limit: %v, want ErrFileTransfer", err)
	}
	_, err = actor.DownloadFile(ctx, transferHost, cid, "/nothing.txt", teamspeak.DownloadFileOptions{})
	if err == nil {
		t.Error("DownloadFile of a missing file succeeded")
	}
	_, err = actor.ListFilesRecursive(ctx, cid, "/nothing", teamspeak.RecursiveFilesOptions{})
	if !errors.Is(err, errcode.FileNotFound) && !errors.Is(err, errcode.FileInvalidPath) && serverCode(err) != 2052 {
		t.Errorf("ListFilesRecursive of a missing path: %v, want the server's refusal", err)
	}
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
