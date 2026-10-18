//go:build integration

package serverquery_test

// Integration tests for the file and icon commands over each query transport:
// directories and renames in a channel's file area, a transfer held in flight
// and stopped, and the icon of a client, a channel, a group and the server.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/perm"
	"github.com/honeybbq/teamspeak-go/prop"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// scratchChannel makes a permanent channel of its own and removes it at the
// end of the test.
func scratchChannel(t *testing.T, c *serverquery.Client, prefix string) teamspeak.ChannelID {
	t.Helper()
	ctx := adminCtx(t)
	name := prefix + uniqueStamp()
	cid, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: name, IsPermanent: new(true)})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	cleanup(t, "the scratch channel", func(ctx context.Context) error { return deleteChannelsNamed(ctx, c, name) })

	return cid
}

// skipOutOfScope skips a test for a command that the transport's api key is
// not scoped for, which WebQuery answers with 5120 for the file commands the
// fixture's key reaches only through the transfer port.
func skipOutOfScope(t *testing.T, err error, what string) {
	t.Helper()
	if serverCode(err) == 5120 {
		t.Skipf("%s: %v", what, err)
	}
}

// fileNames lists a directory of a channel's file area by name. A directory
// with nothing in it is answered with an error on one generation and an empty
// list on the other, and both read as no files.
func fileNames(
	ctx context.Context, t *testing.T, c *serverquery.Client, cid teamspeak.ChannelID, dir string,
) map[string]teamspeak.FileEntry {
	t.Helper()
	files, err := c.ListFiles(ctx, cid, dir, teamspeak.FileOptions{})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) && !errors.Is(err, errcode.FileNotFound) {
		t.Fatalf("ListFiles(%s): %v", dir, err)
	}
	out := make(map[string]teamspeak.FileEntry, len(files))
	for _, f := range files {
		out[f.Name] = f
	}

	return out
}

// A directory is made in a channel's file area, renamed, and deleted, and a
// file in it is renamed and moved to the channel's top.
//
//nolint:gocognit,gocyclo,cyclop,funlen // one scenario, step by step
func TestQueryFiles_DirectoryAndRename(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		cid := scratchChannel(t, c, "ts-go-files-")

		// The server does not make the parents on the way: a path whose parent
		// is missing is refused with 2052, file input/output error (measured
		// on TeamSpeak 3 and 6).
		err := c.CreateDirectory(ctx, cid, "/docs/inner", teamspeak.FileOptions{})
		skipOutOfScope(t, err, "CreateDirectory")
		skipUnlessAllowed(t, err, "CreateDirectory")
		if code := serverCode(err); code != 2052 {
			t.Errorf("CreateDirectory under a missing parent: %v, want code 2052", err)
		}
		err = c.CreateDirectory(ctx, cid, "/docs", teamspeak.FileOptions{})
		if err != nil {
			t.Fatalf("CreateDirectory: %v", err)
		}
		err = c.CreateDirectory(ctx, cid, "/docs/inner", teamspeak.FileOptions{})
		if err != nil {
			t.Fatalf("CreateDirectory under it: %v", err)
		}
		cleanup(t, "the files", func(ctx context.Context) error {
			delErr := c.DeleteFile(ctx, cid, []string{"/docs", "/notes"}, teamspeak.FileOptions{})
			if delErr != nil && !errors.Is(delErr, errcode.FileNotFound) && !errors.Is(delErr, errcode.FileInvalidPath) &&
				serverCode(delErr) != 5120 {
				return delErr
			}

			return nil
		})

		top := fileNames(ctx, t, c, cid, "/")
		if d, ok := top["docs"]; !ok || !d.IsDirectory {
			t.Fatalf("the channel's top = %+v, want the directory docs", top)
		}
		if d, ok := fileNames(ctx, t, c, cid, "/docs")["inner"]; !ok || !d.IsDirectory {
			t.Errorf("/docs = %+v, want the directory inner", fileNames(ctx, t, c, cid, "/docs"))
		}

		uploadFile(ctx, t, c, cid, "/docs/a.txt", []byte("hello"))
		// The listing shows the size once the server has finished writing the
		// file, a moment after the upload connection closes.
		var inDocs map[string]teamspeak.FileEntry
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			inDocs = fileNames(ctx, t, c, cid, "/docs")
			if inDocs["a.txt"].Size == 5 || time.Now().After(deadline) {
				break
			}
		}
		if f, ok := inDocs["a.txt"]; !ok || f.IsDirectory || f.Size != 5 {
			t.Errorf("/docs = %+v, want a.txt of 5 bytes", inDocs)
		}

		err = c.RenameFile(ctx, cid, "/docs/a.txt", "/docs/b.txt", teamspeak.FileRenameOptions{})
		if err != nil {
			t.Fatalf("RenameFile within a directory: %v", err)
		}
		inDocs = fileNames(ctx, t, c, cid, "/docs")
		if _, old := inDocs["a.txt"]; old {
			t.Errorf("/docs = %+v, want a.txt gone after the rename", inDocs)
		}
		if _, ok := inDocs["b.txt"]; !ok {
			t.Errorf("/docs = %+v, want b.txt", inDocs)
		}

		err = c.RenameFile(ctx, cid, "/docs/b.txt", "/notes", teamspeak.FileRenameOptions{})
		if err != nil {
			t.Fatalf("RenameFile to the top: %v", err)
		}
		top = fileNames(ctx, t, c, cid, "/")
		if f, ok := top["notes"]; !ok || f.Size != 5 {
			t.Errorf("the channel's top = %+v, want notes of 5 bytes", top)
		}

		err = c.DeleteFile(ctx, cid, []string{"/docs", "/notes"}, teamspeak.FileOptions{})
		if err != nil {
			t.Fatalf("DeleteFile: %v", err)
		}
		left := fileNames(ctx, t, c, cid, "/")
		if len(left) != 0 {
			t.Errorf("after the deletes the channel's top = %+v, want empty", left)
		}
	})
}

// transferHost is where the file-transfer port is dialled: the query
// connection's own server, which the tests reach on the loopback address.
const transferHost = "127.0.0.1"

// uploadFile sends data to path in a channel's file area over the transfer
// port.
func uploadFile(
	ctx context.Context, t *testing.T, c *serverquery.Client, cid teamspeak.ChannelID, path string, data []byte,
) {
	t.Helper()
	info, err := c.InitFileUpload(ctx, cid, path, uint64(len(data)), teamspeak.FileUploadOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("InitFileUpload %s: %v", path, err)
	}
	err = teamspeak.UploadFileData(ctx, transferHost, info, bytes.NewReader(data), teamspeak.FileTransferOptions{})
	if err != nil {
		t.Fatalf("UploadFileData %s: %v", path, err)
	}
}

// A transfer is held open by a connection that has sent part of its file, seen
// in the list of active transfers, and stopped by its id; the connection then
// ends and the list is empty again.
//
//nolint:funlen // one transfer, step by step
func TestQueryFiles_ActiveTransferStopped(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		cid := scratchChannel(t, c, "ts-go-ftstop-")
		const path = "/held.bin"
		cleanup(t, "the partial file", func(ctx context.Context) error {
			delErr := c.DeleteFile(ctx, cid, []string{path}, teamspeak.FileOptions{})
			if delErr != nil && !errors.Is(delErr, errcode.FileNotFound) && !errors.Is(delErr, errcode.FileInvalidPath) &&
				serverCode(delErr) != 5120 {
				return delErr
			}

			return nil
		})

		idle, err := c.ListActiveTransfers(ctx)
		skipOutOfScope(t, err, "ListActiveTransfers")
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListActiveTransfers with none running: %v", err)
		}
		if len(idle) != 0 {
			t.Fatalf("ListActiveTransfers = %+v before the test started one", idle)
		}

		const announced = 1 << 20
		info, err := c.InitFileUpload(ctx, cid, path, announced, teamspeak.FileUploadOptions{Overwrite: true})
		if err != nil {
			t.Fatalf("InitFileUpload: %v", err)
		}
		conn, err := teamspeak.DialFileTransfer(ctx, transferHost, info.Port, info.FileTransferKey,
			teamspeak.FileTransferOptions{})
		if err != nil {
			t.Fatalf("DialFileTransfer: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		sent := bytes.Repeat([]byte("x"), 1000)
		_, err = conn.Write(sent)
		if err != nil {
			t.Fatalf("writing part of the file: %v", err)
		}

		running := waitForTransfer(ctx, t, c, info.ServerFileTransferID, true)
		t.Logf("the running transfer: %+v", running)
		if running.Size != announced || running.Name != "held.bin" {
			t.Errorf("the running transfer = %+v, want held.bin of %d bytes", running, announced)
		}
		if running.SizeDone > announced {
			t.Errorf("SizeDone %d is past the announced size", running.SizeDone)
		}

		err = c.StopFileTransfer(ctx, info.ServerFileTransferID, teamspeak.FileTransferStopOptions{RemovePartialFile: true})
		if err != nil {
			t.Fatalf("StopFileTransfer: %v", err)
		}
		waitForTransfer(ctx, t, c, info.ServerFileTransferID, false)

		// The server closed its side: a read on the held connection ends.
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Errorf("the held connection after StopFileTransfer: read = %v, want it closed", err)
		} else if !errors.Is(err, io.EOF) {
			t.Logf("the held connection ended with %v", err)
		}
		left := fileNames(ctx, t, c, cid, "/")
		if _, ok := left["held.bin"]; ok {
			t.Errorf("the partial file is still there after a stop that removes it: %+v", left)
		}
	})
}

// waitForTransfer polls the active transfers until the one with id is in the
// list (present) or out of it, and returns it for the first case.
func waitForTransfer(
	ctx context.Context, t *testing.T, c *serverquery.Client, id teamspeak.ServerFileTransferID, present bool,
) teamspeak.ActiveTransfer {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		list, err := c.ListActiveTransfers(ctx)
		skipOutOfScope(t, err, "ListActiveTransfers")
		if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
			t.Fatalf("ListActiveTransfers: %v", err)
		}
		i := slices.IndexFunc(list, func(a teamspeak.ActiveTransfer) bool { return a.ServerFileTransferID == id })
		if (i >= 0) == present {
			if present {
				return list[i]
			}

			return teamspeak.ActiveTransfer{}
		}
		if time.Now().After(deadline) {
			t.Fatalf("transfer %d: wanted present=%t, still not so after 15s: %+v", id, present, list)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// iconStep is one kind of thing that carries an icon: how to set it, and how
// to read it back from the record that holds it.
type iconStep struct {
	set  func(id teamspeak.IconID) error
	read func() (teamspeak.IconID, bool)
	name string
}

// Each kind of thing that can carry an icon is given one and has it taken
// away again: a client, a channel, a channel group, a server group and the
// server. The id is read back from the record that carries it, and the icon
// permission is gone once the icon is cleared.
//
//nolint:gocognit,gocyclo,cyclop,funlen // one scenario, step by step
func TestQueryFiles_Icons(t *testing.T) {
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		stamp := uniqueStamp()
		// An id above 2^31, which the server stores as a negative number.
		const icon = teamspeak.IconID(3000000001)

		dbid := scratchClientRecord(t, c, "ts-go-icon-"+stamp[len(stamp)-6:])
		cid := scratchChannel(t, c, "ts-go-icon-")
		cgid, err := c.CreateChannelGroup(ctx, "ts-go-icon-"+stamp, teamspeak.GroupRegular)
		if err != nil {
			t.Fatalf("CreateChannelGroup: %v", err)
		}
		cleanup(t, "the channel group", func(ctx context.Context) error {
			return c.DeleteChannelGroup(ctx, cgid, teamspeak.GroupDeleteOptions{Force: true})
		})
		sgid, err := c.CreateServerGroup(ctx, "ts-go-icon-"+stamp, teamspeak.GroupRegular)
		if err != nil {
			t.Fatalf("CreateServerGroup: %v", err)
		}
		cleanup(t, "the server group", func(ctx context.Context) error {
			return c.DeleteServerGroup(ctx, sgid, teamspeak.GroupDeleteOptions{Force: true})
		})
		info, err := c.GetServerInfo(ctx)
		if err != nil {
			t.Fatalf("GetServerInfo: %v", err)
		}
		originalServerIcon := info[prop.VirtualServerIconID]
		cleanup(t, "the server's icon", func(ctx context.Context) error {
			return c.EditServer(ctx, teamspeak.Properties{prop.VirtualServerIconID: originalServerIcon})
		})

		serverIcon := func() string {
			props, getErr := c.GetServerInfo(ctx)
			if getErr != nil {
				t.Fatalf("GetServerInfo: %v", getErr)
			}

			return props[prop.VirtualServerIconID]
		}
		iconPermID := permissionRef(ctx, t, c, perm.IconID)
		hasIconPerm := func(list func() ([]teamspeak.PermissionEntry, error)) (int32, bool) {
			entries, listErr := list()
			if listErr != nil && !errors.Is(listErr, errcode.DatabaseEmptyResult) {
				t.Fatalf("listing permissions: %v", listErr)
			}
			// The client's list names its permissions by id only.
			if e := permissionIn(entries, iconPermID); e != nil {
				return e.Value, true
			}

			return 0, false
		}

		for _, step := range []iconStep{
			{
				name: "client",
				set:  func(id teamspeak.IconID) error { return c.SetClientIcon(ctx, dbid, id) },
				read: func() (teamspeak.IconID, bool) {
					v, ok := hasIconPerm(func() ([]teamspeak.PermissionEntry, error) {
						return c.ListClientPermissions(ctx, dbid)
					})

					return teamspeak.IconID(uint32(v)), ok
				},
			},
			{
				name: "channel",
				set:  func(id teamspeak.IconID) error { return c.SetChannelIcon(ctx, cid, id) },
				read: func() (teamspeak.IconID, bool) {
					ch, getErr := c.GetChannelInfo(ctx, cid)
					if getErr != nil {
						t.Fatalf("GetChannelInfo: %v", getErr)
					}

					return ch.IconID, ch.IconID != 0
				},
			},
			{
				name: "channel group",
				set:  func(id teamspeak.IconID) error { return c.SetChannelGroupIcon(ctx, cgid, id) },
				read: func() (teamspeak.IconID, bool) {
					groups, listErr := c.ListChannelGroups(ctx, teamspeak.ChannelGroupListOptions{})
					if listErr != nil {
						t.Fatalf("ListChannelGroups: %v", listErr)
					}
					i := slices.IndexFunc(groups, func(g teamspeak.ChannelGroup) bool { return g.ID == cgid })
					if i < 0 {
						t.Fatalf("the channel group %d is not listed", cgid)
					}

					return groups[i].IconID, groups[i].IconID != 0
				},
			},
			{
				name: "server group",
				set:  func(id teamspeak.IconID) error { return c.SetServerGroupIcon(ctx, sgid, id) },
				read: func() (teamspeak.IconID, bool) {
					groups, listErr := c.ListServerGroups(ctx, teamspeak.ServerGroupListOptions{})
					if listErr != nil {
						t.Fatalf("ListServerGroups: %v", listErr)
					}
					i := slices.IndexFunc(groups, func(g teamspeak.ServerGroup) bool { return g.ID == sgid })
					if i < 0 {
						t.Fatalf("the server group %d is not listed", sgid)
					}

					return groups[i].IconID, groups[i].IconID != 0
				},
			},
			{
				name: "server",
				set:  func(id teamspeak.IconID) error { return c.SetServerIcon(ctx, id) },
				read: func() (teamspeak.IconID, bool) {
					v := serverIcon()
					if v == "" || v == "0" {
						return 0, false
					}
					n, parseErr := strconv.ParseUint(v, 10, 32)
					if parseErr != nil {
						t.Fatalf("virtualserver_icon_id %q: %v", v, parseErr)
					}

					return teamspeak.IconID(n), true
				},
			},
		} {
			t.Run(step.name, func(t *testing.T) {
				err := step.set(icon)
				skipUnlessAllowed(t, err, "setting the "+step.name+" icon")
				if err != nil {
					t.Fatalf("set: %v", err)
				}
				if got, ok := step.read(); !ok || got != icon {
					t.Errorf("after the set the icon = %d (set %t), want %d", got, ok, icon)
				}
				err = step.set(0)
				if err != nil {
					t.Fatalf("clear: %v", err)
				}
				if got, ok := step.read(); ok {
					t.Errorf("after clearing it the icon is still %d", got)
				}
			})
		}
	})
}
