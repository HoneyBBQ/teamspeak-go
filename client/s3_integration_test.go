//go:build integration

package client_test

// Live tests of TeamSpeak 6 S3 file transfer. The S3 tests run when
// TEAMSPEAK_S3_ADDR names a TeamSpeak 6 server with S3 file transfer on, as
// scripts/s3-lab.sh starts one; the one that says a server without it is
// refused runs against TEAMSPEAK_ADDR.
//
//	./scripts/s3-lab.sh /tmp/s3-lab   # appends TEAMSPEAK_S3_* to the fixture's file
//	set -a; . /tmp/ts3-fixture.env; set +a
//	go test -tags integration -run S3 -v ./client
//
// The storage's certificate is from the CA in TEAMSPEAK_S3_CA, which the
// transfers are told to trust through S3TransferOptions.HTTPClient.
//
// A rename that succeeds needs a storage that checks no signature (see
// RenameS3File), so those tests run against a second lab, started beside the
// first with S3_LAB_STORAGE=s3mock and other ports and a prefix, whose
// variables are TEAMSPEAK_S3_UNCHECKED_ADDR, _SERVER_PASSWORD, _CA, _QUERY_URL
// and _QUERY_API_KEY.

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // an avatar's flag on the wire is its MD5
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// s3Lab is a client of the S3 server and what its transfers need.
type s3Lab struct {
	c        *client.Client
	transfer client.S3TransferOptions
	dir      string
	cid      teamspeak.ChannelID
}

func s3Run() string { return strings.ToLower(strings.TrimLeft(time.Now().Format("0405.000"), "0")) }

// dialS3 connects a new client to addr, retrying as the rest of the suite does,
// and waits until it knows its channel.
func dialS3(t *testing.T, addr, serverPassword, nickname string, extra ...client.Option) *client.Client {
	t.Helper()
	id, err := identity.Generate(context.Background(), 8)
	requireNoErr(t, err)
	opts := extra
	if serverPassword != "" {
		opts = append(opts, client.WithServerPassword(serverPassword))
	}
	c := newClient(t, id, addr, nickname, opts...)
	requireNoErr(t, connectWithRetries(context.Background(), t, c))
	for deadline := time.Now().Add(liveEventWait); c.ChannelID() == 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}

	return c
}

// connectS3 connects a client for one test, disconnected when the test ends.
func connectS3(t *testing.T, addr, serverPassword, nickname string, opts ...client.Option) *client.Client {
	t.Helper()
	c := dialS3(t, addr, serverPassword, nickname, opts...)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = c.Disconnect(ctx)
	})

	return c
}

// s3HTTPClient trusts the storage's certificate authority.
func s3HTTPClient(t *testing.T) *http.Client {
	t.Helper()

	return s3HTTPClientFor(t, "TEAMSPEAK_S3")
}

// s3HTTPClientFor trusts the certificate authority named by <prefix>_CA.
func s3HTTPClientFor(t *testing.T, prefix string) *http.Client {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if path := os.Getenv(prefix + "_CA"); path != "" {
		pem, readErr := os.ReadFile(path) //nolint:gosec // the path is the environment's CA file
		requireNoErr(t, readErr)
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("%s holds no certificate", path)
		}
	}

	tlsConfig := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
}

var (
	s3LabOnce sync.Once
	s3LabC    *client.Client
)

func requireS3Lab(t *testing.T) *s3Lab {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_S3_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_S3_ADDR not set — skip S3 file transfer test (scripts/s3-lab.sh starts a server)")
	}
	// One client for every S3 test, as the shared client is: it lives as long as
	// the test binary.
	s3LabOnce.Do(func() {
		s3LabC = dialS3(t, addr, os.Getenv("TEAMSPEAK_S3_SERVER_PASSWORD"), "ts-go-s3")
	})
	if s3LabC == nil {
		t.Fatal("the S3 client could not be set up")
	}

	return &s3Lab{
		c:        s3LabC,
		cid:      s3LabC.ChannelID(),
		transfer: client.S3TransferOptions{HTTPClient: s3HTTPClient(t)},
		dir:      "/ts-go-" + s3Run(),
	}
}

func (l *s3Lab) upload(t *testing.T, path string, data []byte) {
	t.Helper()
	requireNoErr(t, l.c.UploadS3File(t.Context(), l.cid, path, data, client.UploadS3FileOptions{Transfer: l.transfer}))
}

func (l *s3Lab) download(t *testing.T, path string, opts client.DownloadS3FileOptions) ([]byte, error) {
	t.Helper()
	opts.Transfer = l.transfer

	return l.c.DownloadS3File(t.Context(), l.cid, path, opts)
}

func (l *s3Lab) remove(t *testing.T, cid teamspeak.ChannelID, path string) {
	t.Helper()
	requireNoErr(t, l.c.DeleteS3File(t.Context(), cid, path, client.S3FileOptions{}))
}

func (l *s3Lab) listed(t *testing.T, path string) (client.S3FileEntry, bool) {
	t.Helper()
	files, err := l.c.ListS3Files(t.Context(), l.cid, client.S3FileOptions{})
	requireNoErr(t, err)
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}

	return client.S3FileEntry{}, false
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	requireNoErr(t, err)

	return b
}

func requireServerCode(t *testing.T, err error, want errcode.Code) {
	t.Helper()
	var serverErr *teamspeak.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != want {
		t.Fatalf("err = %v, want the server's error %d", err, want)
	}
}

func TestLive_S3NamedAmongTheServersExtensions(t *testing.T) {
	l := requireS3Lab(t)
	if !l.c.ServerCapabilities().HasExtension(teamspeak.ServerExtensionS3) {
		t.Errorf("extensions = %v, want s3 among them", l.c.ServerCapabilities().Extensions)
	}
}

func TestLive_S3UploadsListsDownloadsAndDeletesAFile(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/round-trip.bin"
	data := randomBytes(t, 200_000)
	l.upload(t, path, data)

	entry, ok := l.listed(t, path)
	if !ok || entry.Size != 200_000 || entry.ModifiedAt.IsZero() {
		t.Errorf("listed = %+v, %v", entry, ok)
	}
	got, err := l.download(t, path, client.DownloadS3FileOptions{})
	requireNoErr(t, err)
	if !bytes.Equal(got, data) {
		t.Errorf("downloaded %d bytes that differ from the %d uploaded", len(got), len(data))
	}

	l.remove(t, l.cid, path)
	if _, ok = l.listed(t, path); ok {
		t.Error("the file is still listed after its delete")
	}
	_, err = l.download(t, path, client.DownloadS3FileOptions{})
	var transfer *client.S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != http.StatusNotFound {
		t.Errorf("download of a deleted file: err = %v, want 404", err)
	}
}

func TestLive_S3AFileOfSizeZero(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/empty.bin"
	l.upload(t, path, nil)
	entry, ok := l.listed(t, path)
	if !ok || entry.Size != 0 {
		t.Errorf("listed = %+v, %v", entry, ok)
	}
	l.remove(t, l.cid, path)
}

func TestLive_S3DownloadsTheRestOfAFileFromSeekPosition(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/seek.bin"
	data := randomBytes(t, 10_000)
	l.upload(t, path, data)
	defer l.remove(t, l.cid, path)

	rest, err := l.download(t, path, client.DownloadS3FileOptions{SeekPosition: 9_000})
	requireNoErr(t, err)
	if !bytes.Equal(rest, data[9_000:]) {
		t.Errorf("got %d bytes, want the last 1000 of the file", len(rest))
	}
}

func TestLive_S3KeepsNamesTheServerHasToEncode(t *testing.T) {
	l := requireS3Lab(t)
	paths := []string{l.dir + "/a b+c#d?e&f=g.txt", l.dir + "/ünï€ (1).txt", l.dir + "/nested/deeper/x.txt"}
	for _, path := range paths {
		l.upload(t, path, []byte(path))
	}
	for _, path := range paths {
		if _, ok := l.listed(t, path); !ok {
			t.Errorf("%q is not listed", path)
		}
		got, err := l.download(t, path, client.DownloadS3FileOptions{})
		requireNoErr(t, err)
		if string(got) != path {
			t.Errorf("%q downloaded as %q", path, got)
		}
		l.remove(t, l.cid, path)
	}
}

func TestLive_S3ReplacesAFileAlreadyAtThePath(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/replace.txt"
	l.upload(t, path, []byte("first"))
	l.upload(t, path, []byte("second"))
	got, err := l.download(t, path, client.DownloadS3FileOptions{})
	requireNoErr(t, err)
	if string(got) != "second" {
		t.Errorf("got %q, want the second upload", got)
	}
	l.remove(t, l.cid, path)
}

func TestLive_S3ListsAStoredFileOnlyOnceTheServerIsToldTheUploadIsDone(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/uncompleted.txt"
	ctx := t.Context()
	info, err := l.c.InitS3FileUpload(ctx, l.cid, path, 3, client.S3FileOptions{})
	requireNoErr(t, err)
	requireNoErr(t, client.UploadS3FileData(ctx, info, strings.NewReader("abc"), l.transfer))
	// A test that expects nothing measures once.
	time.Sleep(time.Second)
	if _, ok := l.listed(t, path); ok {
		t.Error("the file is listed before the server was told the upload is done")
	}
	requireNoErr(t, l.c.CompleteS3FileUpload(ctx, info, client.S3FileOptions{}))
	if _, ok := l.listed(t, path); !ok {
		t.Error("the file is not listed after CompleteS3FileUpload")
	}
	l.remove(t, l.cid, path)
}

func TestLive_S3SignsADownloadOfAFileThatIsNotThereAndTheStorageAnswers404(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/never-uploaded.txt"
	info, err := l.c.InitS3FileDownload(t.Context(), l.cid, path, client.S3FileOptions{})
	requireNoErr(t, err)
	if !strings.HasPrefix(info.URL, "https://") {
		t.Errorf("URL is not https")
	}
	_, err = l.download(t, path, client.DownloadS3FileOptions{})
	var transfer *client.S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != http.StatusNotFound {
		t.Errorf("err = %v, want 404", err)
	}
	// Deleting a file that is not there succeeds as well.
	l.remove(t, l.cid, path)
}

func TestLive_S3AChannelThatDoesNotExistHasNoFilesAndSignsNoDownload(t *testing.T) {
	l := requireS3Lab(t)
	const missing teamspeak.ChannelID = 999_999
	files, err := l.c.ListS3Files(t.Context(), missing, client.S3FileOptions{})
	if err != nil || len(files) != 0 {
		t.Errorf("files = %v, %v, want none", files, err)
	}
	_, err = l.c.InitS3FileDownload(t.Context(), missing, "/a.txt", client.S3FileOptions{})
	requireServerCode(t, err, errcode.FileInvalidPermissions)
}

// The two commands that change files tell no other client about it.
func TestLive_S3TellsOtherClientsNothing(t *testing.T) {
	l := requireS3Lab(t)
	other := connectS3(t, os.Getenv("TEAMSPEAK_S3_ADDR"), os.Getenv("TEAMSPEAK_S3_SERVER_PASSWORD"), "ts-go-s3-other")
	var mu sync.Mutex
	var names []string
	other.OnNotification(func(n client.NotificationEvent) {
		mu.Lock()
		names = append(names, n.Name)
		mu.Unlock()
	})
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	names = nil
	mu.Unlock()

	path := l.dir + "/quiet.txt"
	l.upload(t, path, []byte("quiet"))
	l.remove(t, l.cid, path)
	time.Sleep(time.Second)

	mu.Lock()
	defer mu.Unlock()
	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "s3") || strings.Contains(lower, "file") || strings.Contains(lower, "presigned") {
			t.Errorf("the other client was sent %q", name)
		}
	}
}

func TestLive_S3KeepsItsFilesApartFromTheClassicFileArea(t *testing.T) {
	l := requireS3Lab(t)
	classicName := "/ts-go-classic-" + s3Run() + ".txt"
	err := l.c.UploadFile(t.Context(), l.c.Host(), l.cid, classicName, []byte("classic"), teamspeak.UploadFileOptions{})
	requireNoErr(t, err)
	defer func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = l.c.DeleteFile(ctx, l.cid, []string{classicName}, teamspeak.FileOptions{})
	}()
	if _, ok := l.listed(t, classicName); ok {
		t.Error("a file uploaded the classic way is listed by the S3 list")
	}
}

// s3Admin connects an administrator over the S3 server's WebQuery.
func s3Admin(t *testing.T) *serverquery.Client {
	t.Helper()
	admin, err := serverquery.New(
		serverquery.Web(os.Getenv("TEAMSPEAK_S3_QUERY_URL"), os.Getenv("TEAMSPEAK_S3_QUERY_API_KEY")),
		serverquery.WithServer(1))
	requireNoErr(t, err)
	requireNoErr(t, admin.Connect(t.Context()))
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.Disconnect(ctx)
	})

	return admin
}

//nolint:funlen // one subtest per measured refusal
func TestLive_S3Permissions(t *testing.T) {
	l := requireS3Lab(t)
	if os.Getenv("TEAMSPEAK_S3_QUERY_URL") == "" {
		t.Skip("TEAMSPEAK_S3_QUERY_URL not set — an administrator is needed to set permissions")
	}
	admin := s3Admin(t)
	create := func(name string, perms ...string) teamspeak.ChannelID {
		cid, createErr := admin.CreateChannel(t.Context(), teamspeak.ChannelCreateOptions{Name: name + "-" + s3Run()})
		requireNoErr(t, createErr)
		t.Cleanup(func() {
			ctx, cancel := cleanupContext()
			defer cancel()
			_ = admin.DeleteChannel(ctx, cid, teamspeak.ChannelDeleteOptions{Force: true})
		})
		// The fixture gives every client 100 of each file power.
		for _, perm := range perms {
			requireNoErr(t, admin.AddChannelPermission(t.Context(), cid, teamspeak.PermissionByName(perm), 200))
		}

		return cid
	}
	ctx := t.Context()
	locked := create("ts-go-s3-locked",
		"i_ft_needed_file_upload_power", "i_ft_needed_file_download_power", "i_ft_needed_file_delete_power",
		"i_ft_needed_file_rename_power")
	noDirectories := create("ts-go-s3-nodirs", "i_ft_needed_directory_create_power")

	t.Run("a directory the list does not have needs directory create power", func(t *testing.T) {
		upload := func(path string) error {
			return l.c.UploadS3File(ctx, noDirectories, path, []byte("x"), client.UploadS3FileOptions{Transfer: l.transfer})
		}
		// Into an area with no files any path is taken.
		requireNoErr(t, upload("/first/a.txt"))
		defer func() {
			for _, path := range []string{"/first/a.txt", "/first/b.txt", "/top.txt"} {
				_ = l.c.DeleteS3File(ctx, noDirectories, path, client.S3FileOptions{})
			}
		}()
		requireNoErr(t, upload("/first/b.txt"))
		requireNoErr(t, upload("/top.txt"))
		_, err := l.c.InitS3FileUpload(ctx, noDirectories, "/second/c.txt", 1, client.S3FileOptions{})
		requireServerCode(t, err, errcode.FileInvalidPermissions)
	})
	t.Run("an upload without the power is refused with 2049", func(t *testing.T) {
		_, err := l.c.InitS3FileUpload(ctx, locked, "/a.txt", 1, client.S3FileOptions{})
		requireServerCode(t, err, errcode.FileInvalidPermissions)
	})
	t.Run("a download without the power is refused with 2049", func(t *testing.T) {
		_, err := l.c.InitS3FileDownload(ctx, locked, "/a.txt", client.S3FileOptions{})
		requireServerCode(t, err, errcode.FileInvalidPermissions)
	})
	t.Run("a delete without the power is refused with 2568", func(t *testing.T) {
		err := l.c.DeleteS3File(ctx, locked, "/a.txt", client.S3FileOptions{})
		requireServerCode(t, err, errcode.PermissionsClientInsufficient)
		err = l.c.DeleteS3Files(ctx, locked, []string{"/a.txt", "/b.txt"}, client.S3FileOptions{})
		requireServerCode(t, err, errcode.PermissionsClientInsufficient)
	})
	t.Run("a rename without the power is refused with 2568", func(t *testing.T) {
		err := l.c.RenameS3File(ctx, locked, "/a.txt", "/b.txt", client.S3FileOptions{})
		requireServerCode(t, err, errcode.PermissionsClientInsufficient)
		err = l.c.RenameS3Files(ctx, locked, []client.S3FileRename{{OldPath: "/a.txt", NewPath: "/b.txt"}},
			client.S3FileOptions{})
		requireServerCode(t, err, errcode.PermissionsClientInsufficient)
	})
	// ServerQuery has no presigned URLs to hand out.
	t.Run("WebQuery does not know the commands", func(t *testing.T) {
		_, err := admin.Exec(ctx, "s3ft_list_files chid="+strconv.FormatUint(uint64(l.cid), 10)+" chpw=")
		requireServerCode(t, err, 1538)
	})
}

func TestLive_S3DeletesSeveralFilesInOneCommand(t *testing.T) {
	l := requireS3Lab(t)
	files := []string{l.dir + "/batch/a.txt", l.dir + "/batch/b.txt", l.dir + "/batch/c.txt"}
	for _, path := range files {
		l.upload(t, path, []byte(path))
	}
	requireNoErr(t, l.c.DeleteS3Files(t.Context(), l.cid, files[:2], client.S3FileOptions{}))
	for i, path := range files {
		if _, ok := l.listed(t, path); ok != (i == 2) {
			t.Errorf("%s listed = %v after the batch delete of the first two", path, ok)
		}
	}
	l.remove(t, l.cid, files[2])
}

// The server's copy leaves x-amz-copy-source unsigned, which RustFS, as every
// storage that checks signatures, refuses.
func TestLive_S3ARenameOnAStorageThatChecksSignaturesFailsAndTheFileStays(t *testing.T) {
	l := requireS3Lab(t)
	path := l.dir + "/stays.txt"
	l.upload(t, path, []byte("stays"))
	defer l.remove(t, l.cid, path)

	err := l.c.RenameS3File(t.Context(), l.cid, path, l.dir+"/moved.txt", client.S3FileOptions{})
	if _, ok := errors.AsType[*client.S3TransferError](err); !ok {
		t.Fatalf("err = %v, want an *S3TransferError", err)
	}
	if _, ok := l.listed(t, path); !ok {
		t.Error("the file is gone from its path")
	}
	if _, ok := l.listed(t, l.dir+"/moved.txt"); ok {
		t.Error("the file is listed at the new path")
	}
}

// s3Avatars is the S3 lab with a bystander and a Server Admin client, as the
// avatar and icon tests need.
type s3Avatars struct {
	*s3Lab

	bystander *client.Client
	owner     *client.Client
}

func requireS3Avatars(t *testing.T) *s3Avatars {
	t.Helper()
	l := requireS3Lab(t)
	if os.Getenv("TEAMSPEAK_S3_QUERY_URL") == "" {
		t.Skip("TEAMSPEAK_S3_QUERY_URL not set — an administrator is needed for a Server Admin key")
	}
	admin := s3Admin(t)
	groups, err := admin.ListServerGroups(t.Context(), teamspeak.ServerGroupListOptions{})
	requireNoErr(t, err)
	re := regexp.MustCompile(`(?i)server admin`)
	var group teamspeak.ServerGroupID
	for _, g := range groups {
		if g.Type == teamspeak.GroupRegular && re.MatchString(g.Name) {
			group = g.ID
		}
	}
	if group == 0 {
		t.Skip("the server has no regular Server Admin group")
	}
	// Icons need b_icon_manage and i_max_icon_filesize, which a Server Admin has.
	token, err := admin.AddPrivilegeKey(t.Context(), teamspeak.PrivilegeKeyOptions{
		ServerGroupID: group, Description: "s3-" + s3Run(),
	})
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = admin.DeletePrivilegeKey(ctx, token)
	})
	addr, password := os.Getenv("TEAMSPEAK_S3_ADDR"), os.Getenv("TEAMSPEAK_S3_SERVER_PASSWORD")

	return &s3Avatars{
		s3Lab:     l,
		bystander: connectS3(t, addr, password, "ts-go-s3-bystander"),
		owner:     connectS3(t, addr, password, "ts-go-s3-icons", client.WithPrivilegeKey(token)),
	}
}

func TestLive_S3AvatarIsSeenFlaggedAndDownloadedByteForByte(t *testing.T) {
	a := requireS3Avatars(t)
	updated := listen(t, a.bystander.OnClientUpdated)
	data := []byte("not really a picture " + s3Run())
	sum := md5.Sum(data) //nolint:gosec // an avatar's flag on the wire is its MD5
	want := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = a.c.RemoveS3Avatar(ctx)
	})

	got, err := a.c.UploadS3Avatar(t.Context(), data, a.transfer)
	requireNoErr(t, err)
	if got != want {
		t.Fatalf("UploadS3Avatar = %q, want the MD5 %q", got, want)
	}
	await(t, updated, "the avatar flag in clientUpdated", func(e teamspeak.ClientUpdatedEvent) bool {
		return e.ClientID == a.c.ClientID() && e.Changes.Avatar != nil && *e.Changes.Avatar == want
	})
	blob, ok, err := a.bystander.DownloadS3Avatar(t.Context(), a.c.UID(), a.transfer)
	requireNoErr(t, err)
	if !ok || !bytes.Equal(blob, data) {
		t.Fatalf("DownloadS3Avatar = %q, %v, want the uploaded bytes", blob, ok)
	}
	// Kept in channel 0 under the uploader's avatar name.
	name, err := teamspeak.AvatarFileName(a.c.UID())
	requireNoErr(t, err)
	files, err := a.owner.ListS3Files(t.Context(), 0, client.S3FileOptions{})
	requireNoErr(t, err)
	found := false
	for _, f := range files {
		found = found || f.Path == "/"+name
	}
	if !found {
		t.Errorf("channel 0 lists no /%s", name)
	}

	requireS3AvatarRemoved(t, a)
}

// requireS3AvatarRemoved removes the S3 lab client's avatar, and checks the
// bystander sees the flag emptied and finds no file.
func requireS3AvatarRemoved(t *testing.T, a *s3Avatars) {
	t.Helper()
	cleared := listen(t, a.bystander.OnClientUpdated)
	requireNoErr(t, a.c.RemoveS3Avatar(t.Context()))
	await(t, cleared, "the avatar flag emptied", func(e teamspeak.ClientUpdatedEvent) bool {
		return e.ClientID == a.c.ClientID() && e.Changes.Avatar != nil && *e.Changes.Avatar == ""
	})
	_, ok, err := a.bystander.DownloadS3Avatar(t.Context(), a.c.UID(), a.transfer)
	requireNoErr(t, err)
	if ok {
		t.Error("the avatar is still there after RemoveS3Avatar")
	}
}

func TestLive_S3AnotherClientsAvatarIsRefusedToDelete(t *testing.T) {
	a := requireS3Avatars(t)
	_, err := a.c.UploadS3Avatar(t.Context(), []byte("mine"), a.transfer)
	requireNoErr(t, err)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = a.c.RemoveS3Avatar(ctx)
	})
	name, err := teamspeak.AvatarFileName(a.c.UID())
	requireNoErr(t, err)
	err = a.bystander.DeleteS3File(t.Context(), 0, "/"+name, client.S3FileOptions{})
	requireServerCode(t, err, errcode.PermissionsClientInsufficient)
}

func TestLive_S3AnAvatarOverTheSizeLimitIsRefusedWith2049(t *testing.T) {
	a := requireS3Avatars(t)
	_, err := a.c.UploadS3Avatar(t.Context(), make([]byte, 200_001), a.transfer)
	requireServerCode(t, err, errcode.FileInvalidPermissions)
}

func TestLive_S3IconIsDownloadedByABystanderAndDeleted(t *testing.T) {
	a := requireS3Avatars(t)
	data := []byte("\x89PNG icon " + s3Run())
	id, err := a.owner.UploadS3Icon(t.Context(), data, a.transfer)
	requireNoErr(t, err)
	if id != teamspeak.IconIDOf(data) {
		t.Errorf("id = %d, want %d", id, teamspeak.IconIDOf(data))
	}
	blob, ok, err := a.bystander.DownloadS3Icon(t.Context(), id, a.transfer)
	requireNoErr(t, err)
	if !ok || !bytes.Equal(blob, data) {
		t.Fatalf("DownloadS3Icon = %q, %v, want the uploaded bytes", blob, ok)
	}
	requireNoErr(t, a.owner.DeleteS3Icon(t.Context(), id))
	_, ok, err = a.bystander.DownloadS3Icon(t.Context(), id, a.transfer)
	requireNoErr(t, err)
	if ok {
		t.Error("the icon is still there after DeleteS3Icon")
	}
}

func TestLive_S3IconsAreRefusedWithoutBIconManage(t *testing.T) {
	a := requireS3Avatars(t)
	data := []byte("icon " + s3Run())
	_, err := a.bystander.UploadS3Icon(t.Context(), data, a.transfer)
	requireServerCode(t, err, errcode.FileInvalidPermissions)
	err = a.bystander.DeleteS3Icon(t.Context(), teamspeak.IconIDOf(data))
	requireServerCode(t, err, errcode.PermissionsClientInsufficient)
}

// uncheckedLab is a client of the second lab, whose storage checks no
// signature, so the server's copy for a rename is taken.
type uncheckedLab struct {
	*s3Lab
}

func requireUncheckedLab(t *testing.T) *uncheckedLab {
	t.Helper()
	addr := os.Getenv("TEAMSPEAK_S3_UNCHECKED_ADDR")
	if addr == "" {
		t.Skip("TEAMSPEAK_S3_UNCHECKED_ADDR not set — skip the rename tests (S3_LAB_STORAGE=s3mock ./scripts/s3-lab.sh)")
	}
	c := connectS3(t, addr, os.Getenv("TEAMSPEAK_S3_UNCHECKED_SERVER_PASSWORD"), "ts-go-s3u-"+s3Run())
	l := &s3Lab{
		c:        c,
		cid:      c.ChannelID(),
		transfer: client.S3TransferOptions{HTTPClient: s3HTTPClientFor(t, "TEAMSPEAK_S3_UNCHECKED")},
		dir:      "/ts-go-" + s3Run(),
	}
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		files, err := c.ListS3Files(ctx, l.cid, client.S3FileOptions{})
		if err != nil {
			return
		}
		for _, f := range files {
			if strings.HasPrefix(f.Path, l.dir+"/") {
				_ = c.DeleteS3File(ctx, l.cid, f.Path, client.S3FileOptions{})
			}
		}
	})

	return &uncheckedLab{l}
}

func TestLive_S3RenameMovesAFileWhichTheListShowsAtOnce(t *testing.T) {
	l := requireUncheckedLab(t)
	l.upload(t, l.dir+"/a.txt", []byte("content of a"))
	requireNoErr(t, l.c.RenameS3File(t.Context(), l.cid, l.dir+"/a.txt", l.dir+"/sub/renamed.txt", client.S3FileOptions{}))
	if _, ok := l.listed(t, l.dir+"/sub/renamed.txt"); !ok {
		t.Error("the file is not listed at the new path")
	}
	if _, ok := l.listed(t, l.dir+"/a.txt"); ok {
		t.Error("the file is still listed at the old path")
	}
	got, err := l.download(t, l.dir+"/sub/renamed.txt", client.DownloadS3FileOptions{})
	requireNoErr(t, err)
	if string(got) != "content of a" {
		t.Errorf("got %q", got)
	}
}

func TestLive_S3RenameReplacesAFileAtTheNewPath(t *testing.T) {
	l := requireUncheckedLab(t)
	l.upload(t, l.dir+"/from.txt", []byte("from"))
	l.upload(t, l.dir+"/to.txt", []byte("to"))
	requireNoErr(t, l.c.RenameS3File(t.Context(), l.cid, l.dir+"/from.txt", l.dir+"/to.txt", client.S3FileOptions{}))
	got, err := l.download(t, l.dir+"/to.txt", client.DownloadS3FileOptions{})
	requireNoErr(t, err)
	if string(got) != "from" {
		t.Errorf("got %q, want the renamed file's bytes", got)
	}
}

func TestLive_S3RenameOfAMissingFileOrOntoItselfIsReported(t *testing.T) {
	l := requireUncheckedLab(t)
	var failed *client.S3TransferError
	err := l.c.RenameS3File(t.Context(), l.cid, l.dir+"/missing.txt", l.dir+"/x.txt", client.S3FileOptions{})
	if !errors.As(err, &failed) {
		t.Errorf("a missing file: err = %v, want an *S3TransferError", err)
	}
	l.upload(t, l.dir+"/self.txt", []byte("self"))
	err = l.c.RenameS3File(t.Context(), l.cid, l.dir+"/self.txt", l.dir+"/self.txt", client.S3FileOptions{})
	if !errors.As(err, &failed) {
		t.Errorf("onto itself: err = %v, want an *S3TransferError", err)
	}
}

// One answer for the batch, the last rename's.
func TestLive_S3RenameFilesAnswersForItsLastRenameAlone(t *testing.T) {
	l := requireUncheckedLab(t)
	ctx := t.Context()
	l.upload(t, l.dir+"/b1.txt", []byte("b1"))
	err := l.c.RenameS3Files(ctx, l.cid, []client.S3FileRename{
		{OldPath: l.dir + "/nothing.txt", NewPath: l.dir + "/n1.txt"},
		{OldPath: l.dir + "/b1.txt", NewPath: l.dir + "/batch/b1.txt"},
	}, client.S3FileOptions{})
	requireNoErr(t, err)
	if _, ok := l.listed(t, l.dir+"/batch/b1.txt"); !ok {
		t.Error("the last rename was not done")
	}

	l.upload(t, l.dir+"/b2.txt", []byte("b2"))
	err = l.c.RenameS3Files(ctx, l.cid, []client.S3FileRename{
		{OldPath: l.dir + "/b2.txt", NewPath: l.dir + "/batch/b2.txt"},
		{OldPath: l.dir + "/nothing.txt", NewPath: l.dir + "/n2.txt"},
	}, client.S3FileOptions{})
	if _, ok := errors.AsType[*client.S3TransferError](err); !ok {
		t.Errorf("err = %v, want an *S3TransferError for the failed last rename", err)
	}
	// The earlier rename was done all the same; the list catches up a moment later.
	listed := false
	for attempt := 0; attempt < 20 && !listed; attempt++ {
		time.Sleep(250 * time.Millisecond)
		_, listed = l.listed(t, l.dir+"/batch/b2.txt")
	}
	if !listed {
		t.Error("the first rename was not tried")
	}
}

func TestLive_S3AServerWithoutItIsRefusedBeforeAnythingIsSent(t *testing.T) {
	c := requireSharedClient(t)
	caps := c.ServerCapabilities()
	if caps.HasExtension(teamspeak.ServerExtensionS3) {
		t.Skip("TEAMSPEAK_ADDR is a server with S3 file transfer")
	}
	_, err := c.ListS3Files(t.Context(), c.ChannelID(), client.S3FileOptions{})
	var unsupported *client.S3UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Family != caps.Family {
		t.Fatalf("err = %v, want *S3UnsupportedError for the server's family", err)
	}

	// Why the methods refuse first: TeamSpeak 3 answers with an error that names
	// no command, so the command never ends; TeamSpeak 6 says 1035.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err = c.Exec(ctx, "s3ft_list_files chid="+strconv.FormatUint(uint64(c.ChannelID()), 10)+" chpw=")
	if caps.Family == client.ServerFamilyTS3 {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("TeamSpeak 3: err = %v, want the command to time out", err)
		}

		return
	}
	requireServerCode(t, err, 1035)
}
