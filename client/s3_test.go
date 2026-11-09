package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/wire"
)

func TestS3Path(t *testing.T) {
	for path, want := range map[string]string{
		"a.txt":       "/a.txt",
		"/a.txt":      "/a.txt",
		"dir/a b.txt": "/dir/a b.txt",
		"/dir/.hid":   "/dir/.hid",
		"a..b":        "/a..b",
	} {
		got, err := s3Path(path)
		if err != nil || got != want {
			t.Errorf("s3Path(%q) = %q, %v, want %q", path, got, err, want)
		}
	}
	for _, path := range []string{
		"", "/", "a/", "a//b", "//a", "/a/./b", "../a", "a/..", ".", "a\nb", "a\x00b", "a\x7fb", "a\tb",
	} {
		_, err := s3Path(path)
		if !errors.Is(err, teamspeak.ErrInvalidCommand) {
			t.Errorf("s3Path(%q) err = %v, want one wrapping ErrInvalidCommand", path, err)
		}
	}
}

var errDisk = errors.New("disk gone")

func listField(json string) string { return base64.StdEncoding.EncodeToString([]byte(json)) }

func TestParseS3FileList(t *testing.T) {
	got, err := parseS3FileList(listField(
		`{"contents":[{"key":"dir/a.txt","last_modified":"2026-11-08T19:52:49.518Z","size":2},` +
			`{"key":"/b","size":0,"last_modified":"nonsense"},{"key":"c","size":7}]}`))
	if err != nil || len(got) != 3 {
		t.Fatalf("got %+v, %v", got, err)
	}
	want := time.Date(2026, 11, 8, 19, 52, 49, 518_000_000, time.UTC)
	if got[0].Path != "/dir/a.txt" || got[0].Size != 2 || !got[0].ModifiedAt.Equal(want) {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Path != "/b" || got[1].Size != 0 || !got[1].ModifiedAt.IsZero() {
		t.Errorf("second = %+v, want an unreadable time to be zero", got[1])
	}
	if got[2].Path != "/c" || got[2].Size != 7 || !got[2].ModifiedAt.IsZero() {
		t.Errorf("third = %+v", got[2])
	}
}

func TestParseS3FileList_EmptyFieldAndEmptyListAreNoFiles(t *testing.T) {
	for _, field := range []string{"", listField(`{"contents":[]}`)} {
		got, err := parseS3FileList(field)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("parseS3FileList(%q) = %#v, %v, want an empty list", field, got, err)
		}
	}
}

func TestParseS3FileList_AcceptsUnpaddedBase64(t *testing.T) {
	field := strings.TrimRight(listField(`{"contents":[{"key":"a","size":1}]}`), "=")
	got, err := parseS3FileList(field)
	if err != nil || len(got) != 1 {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestParseS3FileList_MalformedIsNoData(t *testing.T) {
	for name, field := range map[string]string{
		"not base64":        "!!!",
		"not json":          listField("nope"),
		"json null":         listField("null"),
		"an array":          listField(`[]`),
		"no contents":       listField(`{}`),
		"contents null":     listField(`{"contents":null}`),
		"contents a string": listField(`{"contents":"x"}`),
		"item not object":   listField(`{"contents":[1]}`),
		"item null":         listField(`{"contents":[null]}`),
		"no key":            listField(`{"contents":[{"size":1}]}`),
		"key number":        listField(`{"contents":[{"key":1,"size":1}]}`),
		"key null":          listField(`{"contents":[{"key":null,"size":1}]}`),
		"no size":           listField(`{"contents":[{"key":"a"}]}`),
		"size string":       listField(`{"contents":[{"key":"a","size":"1"}]}`),
		"size negative":     listField(`{"contents":[{"key":"a","size":-1}]}`),
		"size fraction":     listField(`{"contents":[{"key":"a","size":1.5}]}`),
	} {
		_, err := parseS3FileList(field)
		if !errors.Is(err, teamspeak.ErrNoData) || !strings.Contains(err.Error(), "malformed file list") {
			t.Errorf("%s: err = %v, want a malformed file list wrapping ErrNoData", name, err)
		}
	}
}

// fakeS3Server answers the S3 commands through a line middleware, recording the
// lines it was sent, as the server would answer them.
type fakeS3Server struct {
	answer func(line teamspeak.CommandLine) ([]map[string]string, error)
	lines  []string
	mu     sync.Mutex
}

func (f *fakeS3Server) middleware(_ teamspeak.LineSender) teamspeak.LineSender {
	return func(_ context.Context, line teamspeak.CommandLine) ([]map[string]string, error) {
		f.mu.Lock()
		f.lines = append(f.lines, line.Text)
		f.mu.Unlock()

		return f.answer(line)
	}
}

type s3Answer func(teamspeak.CommandLine) ([]map[string]string, error)

func newS3Client(t *testing.T, extensions []string, answer s3Answer) (*Client, *fakeS3Server) {
	t.Helper()
	server := &fakeS3Server{answer: answer}
	c := newTestClient(t, WithLineMiddleware(server.middleware))
	c.mu.Lock()
	c.capabilities.Family = teamspeak.ServerFamilyTS6
	c.capabilities.Version = "6.0.0-beta13.1"
	c.capabilities.Extensions = extensions
	c.mu.Unlock()

	return c, server
}

func noAnswer(teamspeak.CommandLine) ([]map[string]string, error) { return nil, nil }

func TestS3_RefusesAServerWithoutTheExtensionBeforeSending(t *testing.T) {
	c, server := newS3Client(t, []string{"FILETIME"}, noAnswer)
	ctx := t.Context()
	info := &S3FileUploadInfo{ChannelID: 2}

	calls := map[string]func() error{
		"InitS3FileUpload": func() error {
			_, err := c.InitS3FileUpload(ctx, 2, "a", 1, S3FileOptions{})

			return err
		},
		"InitS3FileDownload": func() error {
			_, err := c.InitS3FileDownload(ctx, 2, "a", S3FileOptions{})

			return err
		},
		"CompleteS3FileUpload": func() error { return c.CompleteS3FileUpload(ctx, info, S3FileOptions{}) },
		"ListS3Files": func() error {
			_, err := c.ListS3Files(ctx, 2, S3FileOptions{})

			return err
		},
		"DeleteS3File": func() error { return c.DeleteS3File(ctx, 2, "a", S3FileOptions{}) },
		"UploadS3File": func() error { return c.UploadS3File(ctx, 2, "a", []byte("x"), UploadS3FileOptions{}) },
		"DownloadS3File": func() error {
			_, err := c.DownloadS3File(ctx, 2, "a", DownloadS3FileOptions{})

			return err
		},
	}
	for name, call := range calls {
		var unsupported *S3UnsupportedError
		err := call()
		if !errors.As(err, &unsupported) {
			t.Errorf("%s: err = %v, want *S3UnsupportedError", name, err)

			continue
		}
		if unsupported.Family != teamspeak.ServerFamilyTS6 || unsupported.Version != "6.0.0-beta13.1" ||
			len(unsupported.Extensions) != 1 || unsupported.Extensions[0] != "FILETIME" {
			t.Errorf("%s: %+v does not carry what the server named", name, unsupported)
		}
	}
	if len(server.lines) != 0 {
		t.Errorf("sent %q, want nothing", server.lines)
	}
}

func TestS3UnsupportedError_Message(t *testing.T) {
	err := &S3UnsupportedError{Family: ServerFamilyTS3, Version: "3.13.8", Extensions: []string{"A", "B"}}
	want := "S3 file transfer needs a server that names s3 among its extensions; this is " +
		ServerFamilyTS3.String() + " (3.13.8), which names A, B"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	unknown := &S3UnsupportedError{}
	want = "S3 file transfer needs a server that names s3 among its extensions; " +
		"this is an unknown server, which names none"
	if unknown.Error() != want {
		t.Errorf("Error() = %q, want %q", unknown.Error(), want)
	}
}

func TestInitS3FileUpload_SendsTheChannelAndTheFileOnRowsOfTheirOwn(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{
			{"key": "/dir/a b.txt"},
			{"url": "https://storage.example/k?sig=1", "key": "/dir/a b.txt"},
		}, nil
	})
	info, err := c.InitS3FileUpload(t.Context(), 7, "dir/a b.txt", 42, S3FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := `s3ft_getpresignedurl chid=7 chpw=|key=\/dir\/a\sb.txt verb=PUT length=42`
	if len(server.lines) != 1 || server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines, want)
	}
	if info.ChannelID != 7 || info.Path != "/dir/a b.txt" || info.Size != 42 ||
		info.URL != "https://storage.example/k?sig=1" {
		t.Errorf("info = %+v", info)
	}
}

func TestInitS3FileUpload_HashesTheChannelPassword(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"url": "u"}}, nil
	})
	info, err := c.InitS3FileUpload(t.Context(), 7, "a", 1, S3FileOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "/a" {
		t.Errorf("Path = %q, want ours when the answer names none", info.Path)
	}
	if len(server.lines) != 1 || strings.Contains(server.lines[0], "chpw=secret") ||
		!strings.Contains(server.lines[0], "chpw="+wire.Escape(prepareClientPassword("secret"))+"|key=") {
		t.Errorf("sent %q, want the password encoded", server.lines)
	}
}

func TestInitS3FileDownload_SendsGETWithLength0(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"url": "u", "key": "/a"}}, nil
	})
	info, err := c.InitS3FileDownload(t.Context(), 3, "/a", S3FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := `s3ft_getpresignedurl chid=3 chpw=|key=\/a verb=GET length=0`
	if server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}
	if info.ChannelID != 3 || info.Path != "/a" || info.URL != "u" {
		t.Errorf("info = %+v", info)
	}
}

func TestInitS3File_AnAnswerWithoutAURLIsNoData(t *testing.T) {
	c, _ := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"key": "/a"}}, nil
	})
	_, err := c.InitS3FileUpload(t.Context(), 1, "a", 1, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrNoData) {
		t.Errorf("err = %v, want ErrNoData", err)
	}
}

func TestInitS3File_ARefusedPathIsNotSent(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, noAnswer)
	_, err := c.InitS3FileUpload(t.Context(), 1, "a/../b", 1, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) || len(server.lines) != 0 {
		t.Errorf("err = %v, sent %q", err, server.lines)
	}
	err = c.DeleteS3File(t.Context(), 1, "a//b", S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) || len(server.lines) != 0 {
		t.Errorf("delete: err = %v, sent %q", err, server.lines)
	}
}

func TestCompleteS3FileUpload(t *testing.T) {
	success := "1"
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	})
	info := &S3FileUploadInfo{ChannelID: 9, Path: "/a"}
	err := c.CompleteS3FileUpload(t.Context(), info, S3FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "s3ft_upload_done_notification chid=9 chpw="; server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	success = "0"
	err = c.CompleteS3FileUpload(t.Context(), info, S3FileOptions{})
	var failed *S3TransferError
	if !errors.As(err, &failed) || failed.Status != 0 || !errors.Is(err, teamspeak.ErrFileTransfer) ||
		err.Error() != "the server could not read the file list of channel 9 from its storage" {
		t.Errorf("err = %v, want an *S3TransferError for the storage", err)
	}
}

func TestCompleteS3FileUpload_NoSuccessIsNoData(t *testing.T) {
	c, _ := newS3Client(t, []string{"s3"}, noAnswer)
	err := c.CompleteS3FileUpload(t.Context(), &S3FileUploadInfo{ChannelID: 9}, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrNoData) {
		t.Errorf("err = %v, want ErrNoData", err)
	}
}

func TestDeleteS3File(t *testing.T) {
	success := "1"
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	})
	err := c.DeleteS3File(t.Context(), 4, "dir/a.txt", S3FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := `s3ft_deletefile chid=4 chpw= key=\/dir\/a.txt`; server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	success = "0"
	err = c.DeleteS3File(t.Context(), 4, "dir/a.txt", S3FileOptions{})
	var failed *S3TransferError
	if !errors.As(err, &failed) || err.Error() != "the server could not delete /dir/a.txt from its storage" {
		t.Errorf("err = %v, want an *S3TransferError", err)
	}
}

func TestDeleteS3File_NoSuccessIsNoData(t *testing.T) {
	c, _ := newS3Client(t, []string{"s3"}, noAnswer)
	err := c.DeleteS3File(t.Context(), 4, "/a.txt", S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrNoData) {
		t.Errorf("err = %v, want ErrNoData", err)
	}
}

func TestListS3Files(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"b64_json": listField(`{"contents":[{"key":"a","size":3}]}`)}}, nil
	})
	files, err := c.ListS3Files(t.Context(), 5, S3FileOptions{})
	if err != nil || len(files) != 1 || files[0].Path != "/a" || files[0].Size != 3 {
		t.Fatalf("files = %+v, %v", files, err)
	}
	if want := "s3ft_list_files chid=5 chpw="; server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	empty, _ := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"b64_json": ""}}, nil
	})
	files, err = empty.ListS3Files(t.Context(), 5, S3FileOptions{})
	if err != nil || files == nil || len(files) != 0 {
		t.Errorf("an empty field: files = %#v, %v", files, err)
	}

	none, _ := newS3Client(t, []string{"s3"}, noAnswer)
	_, err = none.ListS3Files(t.Context(), 5, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrNoData) {
		t.Errorf("no row: err = %v, want ErrNoData", err)
	}
}

// s3Storage is an S3-compatible storage behind TLS, and the requests it saw.
type s3Storage struct {
	*httptest.Server

	requests []*http.Request
	bodies   [][]byte
	mu       sync.Mutex
}

func newS3Storage(t *testing.T, handler http.HandlerFunc) *s3Storage {
	t.Helper()
	s := &s3Storage{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r)
		s.bodies = append(s.bodies, body)
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(s.Close)

	return s
}

func (s *s3Storage) transfer() S3TransferOptions { return S3TransferOptions{HTTPClient: s.Client()} }

func (s *s3Storage) upload(t *testing.T, size uint64, data io.Reader) error {
	t.Helper()
	info := &S3FileUploadInfo{
		ChannelID: 1, Path: "/dir/a.txt", Size: size, URL: s.URL + "/bucket/dir/a.txt?X-Amz-Signature=secret",
	}

	return UploadS3FileData(t.Context(), info, data, s.transfer())
}

func TestUploadS3FileData_PutsExactlyTheSignedLength(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	err := s.upload(t, 5, strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	r := s.requests[0]
	if r.Method != http.MethodPut || r.ContentLength != 5 || string(s.bodies[0]) != "hello" {
		t.Errorf("%s with Content-Length %d and body %q", r.Method, r.ContentLength, s.bodies[0])
	}
	if r.Header.Get("Authorization") != "" {
		t.Errorf("Authorization = %q, want none", r.Header.Get("Authorization"))
	}
	if len(r.TransferEncoding) != 0 {
		t.Errorf("TransferEncoding = %v, want none", r.TransferEncoding)
	}
}

func TestUploadS3FileData_ASizeOfZeroSendsContentLength0(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	err := s.upload(t, 0, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	r := s.requests[0]
	if r.ContentLength != 0 || r.Header.Get("Content-Length") != "0" || len(r.TransferEncoding) != 0 {
		t.Errorf("Content-Length %d (%q), TransferEncoding %v",
			r.ContentLength, r.Header.Get("Content-Length"), r.TransferEncoding)
	}

	err = s.upload(t, 0, strings.NewReader("x"))
	if !errors.Is(err, teamspeak.ErrFileTransfer) || !strings.Contains(err.Error(), "more than the declared 0 bytes") {
		t.Errorf("data for a size of 0: err = %v", err)
	}
	if len(s.requests) != 1 {
		t.Errorf("%d requests, want the refused one not sent", len(s.requests))
	}
}

func TestUploadS3FileData_FewerBytesThanDeclaredFailTheUpload(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	err := s.upload(t, 10, strings.NewReader("short"))
	var transfer *S3TransferError
	if errors.As(err, &transfer) || !errors.Is(err, teamspeak.ErrFileTransfer) ||
		!errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "ended after 5 of the declared 10 bytes") {
		t.Errorf("err = %v, want a short body, not an S3TransferError", err)
	}
}

func TestUploadS3FileData_MoreBytesThanDeclaredFailTheUpload(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	err := s.upload(t, 3, strings.NewReader("too long"))
	var transfer *S3TransferError
	if errors.As(err, &transfer) || !errors.Is(err, teamspeak.ErrFileTransfer) ||
		!strings.Contains(err.Error(), "more than the declared 3 bytes") {
		t.Errorf("err = %v, want an excess body, not an S3TransferError", err)
	}
}

func TestUploadS3FileData_AFailingReaderIsReportedAsItself(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	boom := errDisk
	err := s.upload(t, 10, io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(boom)))
	var transfer *S3TransferError
	if errors.As(err, &transfer) || !errors.Is(err, boom) || !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("err = %v, want the reader's error wrapping ErrFileTransfer", err)
	}
}

const noSuchKey = `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>gone</Message></Error>`

func TestUploadS3FileData_AnErrorStatusIsAnS3TransferError(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>SignatureDoesNotMatch</Code></Error>`)
	})
	err := s.upload(t, 2, strings.NewReader("ab"))
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 403 || transfer.Code != "SignatureDoesNotMatch" ||
		!errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Fatalf("err = %v, want 403 SignatureDoesNotMatch", err)
	}
	want := "the storage refused the upload of /dir/a.txt: HTTP 403 SignatureDoesNotMatch"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}

func TestUploadS3FileData_ReadsTheCodeOnlyFromTheStartOfTheBody(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, strings.Repeat(" ", s3ErrorBodyLimit)+"<Code>TooLate</Code>")
	})
	err := s.upload(t, 0, strings.NewReader(""))
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 400 || transfer.Code != "" ||
		err.Error() != "the storage refused the upload of /dir/a.txt: HTTP 400" {
		t.Errorf("err = %v (%+v)", err, transfer)
	}
}

func TestUploadS3FileData_NoAnswerNeverNamesTheURL(t *testing.T) {
	s := newS3Storage(t, func(http.ResponseWriter, *http.Request) {})
	info := &S3FileUploadInfo{Path: "/dir/a.txt", Size: 1, URL: s.URL + "/bucket/k?X-Amz-Signature=secret"}
	s.Close()
	err := UploadS3FileData(t.Context(), info, strings.NewReader("a"), s.transfer())
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 0 || transfer.Err == nil ||
		!errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Fatalf("err = %v, want an *S3TransferError with a cause", err)
	}
	for _, text := range []string{err.Error(), transfer.Err.Error()} {
		if strings.Contains(text, "secret") || strings.Contains(text, "X-Amz") || strings.Contains(text, "/bucket") {
			t.Errorf("%q names the URL", text)
		}
	}
	if !strings.HasPrefix(err.Error(), "the upload of /dir/a.txt got no answer from the storage") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestUploadS3FileData_ACanceledContextIsTheContextsError(t *testing.T) {
	release := make(chan struct{})
	s := newS3Storage(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	info := &S3FileUploadInfo{Path: "/a", Size: 1, URL: s.URL + "/k?sig=secret"}
	err := UploadS3FileData(ctx, info, strings.NewReader("a"), s.transfer())
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("err = %v, want ErrFileTransfer and the context's error", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("%q names the URL", err.Error())
	}
}

func s3DownloadInfo(s *s3Storage) *S3FileDownloadInfo {
	return &S3FileDownloadInfo{ChannelID: 1, Path: "/dir/a.txt", URL: s.URL + "/bucket/dir/a.txt?X-Amz-Signature=secret"}
}

func TestDownloadS3FileData_GetsTheFile(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") })
	var out bytes.Buffer
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out, S3DownloadOptions{Transfer: s.transfer()})
	if err != nil || out.String() != "hello" {
		t.Fatalf("got %q, %v", out.String(), err)
	}
	r := s.requests[0]
	if r.Method != http.MethodGet || r.Header.Get("Range") != "" || r.Header.Get("Authorization") != "" {
		t.Errorf("%s with Range %q and Authorization %q", r.Method, r.Header.Get("Range"), r.Header.Get("Authorization"))
	}
}

func TestDownloadS3FileData_SeekAsksForARangeAndTakesTheAnswer(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader("0123456789"))
	})
	var out bytes.Buffer
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out,
		S3DownloadOptions{Transfer: s.transfer(), SeekPosition: 4})
	if err != nil || out.String() != "456789" {
		t.Fatalf("got %q, %v", out.String(), err)
	}
	if got := s.requests[0].Header.Get("Range"); got != "bytes=4-" {
		t.Errorf("Range = %q, want bytes=4-", got)
	}
}

func TestDownloadS3FileData_ASeekAnsweredWith200SkipsTheBytes(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "0123456789") })
	var out bytes.Buffer
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out,
		S3DownloadOptions{Transfer: s.transfer(), SeekPosition: 4})
	if err != nil || out.String() != "456789" {
		t.Fatalf("got %q, %v", out.String(), err)
	}

	out.Reset()
	err = DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out,
		S3DownloadOptions{Transfer: s.transfer(), SeekPosition: 40})
	if err != nil || out.Len() != 0 {
		t.Errorf("a seek past the end of a 200: got %q, %v", out.String(), err)
	}
}

func TestDownloadS3FileData_AMissingFileIs404WithItsCode(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, noSuchKey)
	})
	var out bytes.Buffer
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out, S3DownloadOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 404 || transfer.Code != "NoSuchKey" || out.Len() != 0 {
		t.Fatalf("err = %v, want 404 NoSuchKey", err)
	}
	want := "the storage refused the download of /dir/a.txt: HTTP 404 NoSuchKey"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}

func TestDownloadS3FileData_ASeekAnsweredWithAnotherStatusIsRefused(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	})
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), io.Discard,
		S3DownloadOptions{Transfer: s.transfer(), SeekPosition: 99})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 416 {
		t.Errorf("err = %v, want 416", err)
	}
}

func TestDownloadS3FileData_A206WithoutASeekIsRefused(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusPartialContent) })
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), io.Discard, S3DownloadOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 206 {
		t.Errorf("err = %v, want 206 refused", err)
	}
}

func TestDownloadS3FileData_ABodyThatBreaksOffIsAnS3TransferError(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "abc")
	})
	var out bytes.Buffer
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), &out, S3DownloadOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Err == nil || out.String() != "abc" ||
		!strings.HasPrefix(err.Error(), "the download of /dir/a.txt broke off") {
		t.Errorf("err = %v, wrote %q", err, out.String())
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("%q names the URL", err.Error())
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDownloadS3FileData_AFailingWriterIsReportedAsItself(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") })
	boom := errDisk
	err := DownloadS3FileData(t.Context(), s3DownloadInfo(s), failingWriter{boom},
		S3DownloadOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if errors.As(err, &transfer) || !errors.Is(err, boom) || !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("err = %v, want the writer's error wrapping ErrFileTransfer", err)
	}
}

func TestDownloadS3FileData_ACanceledContextIsTheContextsError(t *testing.T) {
	release := make(chan struct{})
	s := newS3Storage(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := DownloadS3FileData(ctx, s3DownloadInfo(s), io.Discard, S3DownloadOptions{Transfer: s.transfer()})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("err = %v, want ErrFileTransfer and the context's error", err)
	}
}

// signedS3Client is a client whose server signs every URL for storage.
func signedS3Client(t *testing.T, s *s3Storage) *Client {
	t.Helper()
	c, _ := newS3Client(t, []string{"s3"}, func(line teamspeak.CommandLine) ([]map[string]string, error) {
		switch {
		case strings.HasPrefix(line.Text, "s3ft_getpresignedurl"):
			return []map[string]string{{"url": s.URL + "/bucket/k?sig=secret", "key": "/k"}}, nil
		default:
			return []map[string]string{{"success": "1"}}, nil
		}
	})

	return c
}

func TestUploadS3File_SignsSendsAndCompletes(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	c, server := newS3Client(t, []string{"s3"}, func(line teamspeak.CommandLine) ([]map[string]string, error) {
		if strings.HasPrefix(line.Text, "s3ft_getpresignedurl") {
			return []map[string]string{{"url": s.URL + "/bucket/k?sig=secret", "key": "/k"}}, nil
		}

		return []map[string]string{{"success": "1"}}, nil
	})
	err := c.UploadS3File(t.Context(), 6, "k", []byte("data"), UploadS3FileOptions{Transfer: s.transfer()})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.lines) != 2 || !strings.HasPrefix(server.lines[0], "s3ft_getpresignedurl chid=6 ") ||
		!strings.HasSuffix(server.lines[0], "verb=PUT length=4") ||
		server.lines[1] != "s3ft_upload_done_notification chid=6 chpw=" {
		t.Errorf("sent %q", server.lines)
	}
	if string(s.bodies[0]) != "data" || s.requests[0].ContentLength != 4 {
		t.Errorf("stored %q with Content-Length %d", s.bodies[0], s.requests[0].ContentLength)
	}
}

func TestUploadS3File_AFailedPutIsNotCompleted(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"url": s.URL + "/k", "key": "/k"}}, nil
	})
	err := c.UploadS3File(t.Context(), 6, "k", []byte("data"), UploadS3FileOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 403 || len(server.lines) != 1 {
		t.Errorf("err = %v, sent %q", err, server.lines)
	}
}

func TestDownloadS3File_ReturnsTheBytes(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader("0123456789"))
	})
	c := signedS3Client(t, s)
	got, err := c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer()})
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer(), SeekPosition: 7})
	if err != nil || string(got) != "789" {
		t.Errorf("with a seek: got %q, %v", got, err)
	}
}

func TestDownloadS3File_ARefusedMaxSizeIsNotRead(t *testing.T) {
	var sent bool
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 100))
		sent = true
	})
	c := signedS3Client(t, s)
	got, err := c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer(), MaxSize: 99})
	if !errors.Is(err, teamspeak.ErrFileTransfer) || got != nil ||
		!strings.Contains(err.Error(), "the download is 100 bytes, over the 99 the call holds in memory") {
		t.Errorf("got %d bytes, err = %v", len(got), err)
	}
	_ = sent

	got, err = c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer(), MaxSize: 100})
	if err != nil || len(got) != 100 {
		t.Errorf("at the limit: got %d bytes, %v", len(got), err)
	}
}

func TestDownloadS3File_HoldsAnUnannouncedBodyToMaxSize(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		// Flushed chunks, so no Content-Length is announced.
		for range 4 {
			_, _ = io.WriteString(w, strings.Repeat("x", 30))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	c := signedS3Client(t, s)
	_, err := c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer(), MaxSize: 100})
	if !errors.Is(err, teamspeak.ErrFileTransfer) || !strings.Contains(err.Error(), "over the 100 bytes") {
		t.Errorf("err = %v, want the limit", err)
	}
}

func TestDownloadS3File_AMissingFileIs404(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, noSuchKey)
	})
	c := signedS3Client(t, s)
	_, err := c.DownloadS3File(t.Context(), 6, "k", DownloadS3FileOptions{Transfer: s.transfer()})
	var transfer *S3TransferError
	if !errors.As(err, &transfer) || transfer.Status != 404 || transfer.Code != "NoSuchKey" {
		t.Errorf("err = %v, want 404 NoSuchKey", err)
	}
}

func TestS3TransferError_Unwraps(t *testing.T) {
	cause := errDisk
	withCause := &S3TransferError{Err: cause, msg: "the upload of /a got no answer from the storage"}
	if !errors.Is(withCause, cause) || !errors.Is(withCause, teamspeak.ErrFileTransfer) {
		t.Errorf("%v should wrap the cause and ErrFileTransfer", withCause)
	}
	bare := &S3TransferError{Status: 404, msg: "the storage refused the download of /a: HTTP 404"}
	if errors.Is(bare, cause) || !errors.Is(bare, teamspeak.ErrFileTransfer) || len(bare.Unwrap()) != 1 {
		t.Errorf("%v should wrap ErrFileTransfer alone", bare)
	}
}

func successAnswer(success string) s3Answer {
	return func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	}
}

func TestDeleteS3Files_NoPathsSendsNothing(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, successAnswer("1"))
	err := c.DeleteS3Files(t.Context(), 4, nil, S3FileOptions{})
	if err != nil || len(server.lines) != 0 {
		t.Errorf("err = %v, sent %q, want nothing", err, server.lines)
	}
}

func TestDeleteS3Files_OnePathIsTheSingleCommand(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, successAnswer("1"))
	requireNoError(t, c.DeleteS3Files(t.Context(), 4, []string{"a.txt"}, S3FileOptions{}))
	if want := `s3ft_deletefile chid=4 chpw= key=\/a.txt`; server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}
}

func TestDeleteS3Files_SeveralPathsEachCarryTheirChannel(t *testing.T) {
	success := "1"
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	})
	paths := []string{"a b.txt", "dir/c.txt"}
	requireNoError(t, c.DeleteS3Files(t.Context(), 4, paths, S3FileOptions{}))
	want := `s3ft_deletefiles chid=4 chpw=|chid=4 key=\/a\sb.txt|chid=4 key=\/dir\/c.txt`
	if server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	success = "0"
	err := c.DeleteS3Files(t.Context(), 4, paths, S3FileOptions{})
	var failed *S3TransferError
	if !errors.As(err, &failed) || err.Error() != "the server could not delete the 2 files from its storage" {
		t.Errorf("err = %v, want an *S3TransferError", err)
	}
}

func TestDeleteS3Files_ARefusedPathIsNotSent(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, successAnswer("1"))
	err := c.DeleteS3Files(t.Context(), 4, []string{"a", "b//c"}, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) || len(server.lines) != 0 {
		t.Errorf("err = %v, sent %q", err, server.lines)
	}
}

func TestRenameS3File(t *testing.T) {
	success := "1"
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	})
	requireNoError(t, c.RenameS3File(t.Context(), 4, "old name.txt", "dir/new.txt", S3FileOptions{}))
	want := `s3ft_renamefile chid=4 chpw= key_old=\/old\sname.txt key_new=\/dir\/new.txt`
	if server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	success = "0"
	err := c.RenameS3File(t.Context(), 4, "a", "b", S3FileOptions{})
	var failed *S3TransferError
	if !errors.As(err, &failed) || err.Error() != "the server did not rename /a to /b" {
		t.Errorf("err = %v, want an *S3TransferError", err)
	}

	n := len(server.lines)
	err = c.RenameS3File(t.Context(), 4, "a", "b/", S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) || len(server.lines) != n {
		t.Errorf("err = %v, sent %q", err, server.lines[n:])
	}
}

func TestRenameS3Files(t *testing.T) {
	success := "1"
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return []map[string]string{{"success": success}}, nil
	})
	renames := []S3FileRename{{OldPath: "a", NewPath: "b c"}, {OldPath: "d", NewPath: "e/f"}}
	requireNoError(t, c.RenameS3Files(t.Context(), 4, renames, S3FileOptions{}))
	want := `s3ft_renamefiles chid=4 chpw=|chid=4 key_old=\/a key_new=\/b\sc|chid=4 key_old=\/d key_new=\/e\/f`
	if server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	success = "0"
	err := c.RenameS3Files(t.Context(), 4, renames, S3FileOptions{})
	var failed *S3TransferError
	wantMsg := "the server reports that the last rename of the batch, /d to /e/f, was not done"
	if !errors.As(err, &failed) || err.Error() != wantMsg {
		t.Errorf("err = %v, want %q", err, wantMsg)
	}

	n := len(server.lines)
	requireNoError(t, c.RenameS3Files(t.Context(), 4, nil, S3FileOptions{}))
	err = c.RenameS3Files(t.Context(), 4, []S3FileRename{{OldPath: "a", NewPath: "../b"}}, S3FileOptions{})
	if !errors.Is(err, teamspeak.ErrInvalidCommand) || len(server.lines) != n {
		t.Errorf("err = %v, sent %q", err, server.lines[n:])
	}
}

func TestS3_RenameAndBatchDeleteRefuseAServerWithoutTheExtension(t *testing.T) {
	c, server := newS3Client(t, []string{"FILETIME"}, noAnswer)
	errs := []error{
		c.DeleteS3Files(t.Context(), 2, []string{"a", "b"}, S3FileOptions{}),
		c.RenameS3File(t.Context(), 2, "a", "b", S3FileOptions{}),
		c.RenameS3Files(t.Context(), 2, nil, S3FileOptions{}),
	}
	for i, err := range errs {
		if _, ok := errors.AsType[*S3UnsupportedError](err); !ok {
			t.Errorf("call %d: err = %v, want *S3UnsupportedError", i, err)
		}
	}
	if len(server.lines) != 0 {
		t.Errorf("sent %q, want nothing", server.lines)
	}
}
