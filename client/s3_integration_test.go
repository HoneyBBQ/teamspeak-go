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

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
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

// connectS3 connects a new client to addr, retrying as the rest of the suite does.
func connectS3(t *testing.T, addr, serverPassword, nickname string) *client.Client {
	t.Helper()
	id, err := identity.Generate(t.Context(), 8)
	requireNoErr(t, err)
	var opts []client.Option
	if serverPassword != "" {
		opts = append(opts, client.WithServerPassword(serverPassword))
	}
	c := newClient(t, id, addr, nickname, opts...)
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
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
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if path := os.Getenv("TEAMSPEAK_S3_CA"); path != "" {
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
	s3LabOnce.Do(func() {
		s3LabC = connectS3(t, addr, os.Getenv("TEAMSPEAK_S3_SERVER_PASSWORD"), "ts-go-s3")
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
	if !l.c.ServerCapabilities().HasExtension("s3") {
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
		"i_ft_needed_file_upload_power", "i_ft_needed_file_download_power", "i_ft_needed_file_delete_power")
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
	})
	// ServerQuery has no presigned URLs to hand out.
	t.Run("WebQuery does not know the commands", func(t *testing.T) {
		_, err := admin.Exec(ctx, "s3ft_list_files chid="+strconv.FormatUint(uint64(l.cid), 10)+" chpw=")
		requireServerCode(t, err, 1538)
	})
}

func TestLive_S3AServerWithoutItIsRefusedBeforeAnythingIsSent(t *testing.T) {
	c := requireSharedClient(t)
	caps := c.ServerCapabilities()
	if caps.HasExtension("s3") {
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
