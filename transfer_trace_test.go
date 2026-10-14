package teamspeak_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/honeybbq/teamspeak-go"
)

var errTraceRefused = errors.New("refused")

const traceKey = "secret-transfer-key-123"

// transferRecorder records what a FileTransferTrace reports, and formats every
// info so a test can look for the key in it.
type transferRecorder struct {
	order    []string
	infos    []string
	progress []teamspeak.FileTransferProgressInfo
	done     []teamspeak.FileTransferDoneInfo
	failed   []teamspeak.FileTransferFailedInfo
	dialDone []teamspeak.FileTransferDialDoneInfo
	mu       sync.Mutex
}

func (r *transferRecorder) note(name string, info any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, name)
	r.infos = append(r.infos, fmt.Sprintf("%+v %#v %v", info, info, info))
}

func (r *transferRecorder) trace() *teamspeak.FileTransferTrace {
	return &teamspeak.FileTransferTrace{
		DialStart: func(i teamspeak.FileTransferDialStartInfo) { r.note("DialStart", i) },
		DialDone: func(i teamspeak.FileTransferDialDoneInfo) {
			r.note("DialDone", i)
			r.dialDone = append(r.dialDone, i)
		},
		Progress: func(i teamspeak.FileTransferProgressInfo) {
			r.note("Progress", i)
			r.progress = append(r.progress, i)
		},
		Done: func(i teamspeak.FileTransferDoneInfo) {
			r.note("Done", i)
			r.done = append(r.done, i)
		},
		Failed: func(i teamspeak.FileTransferFailedInfo) {
			r.note("Failed", i)
			r.failed = append(r.failed, i)
		},
	}
}

func (r *transferRecorder) requireKeyAbsent(t *testing.T) {
	t.Helper()
	for _, s := range r.infos {
		if strings.Contains(s, traceKey) {
			t.Errorf("the transfer key is in an info: %s", s)
		}
	}
}

func tracedOptions(
	dialer teamspeak.FileTransferDialer, trace *teamspeak.FileTransferTrace,
) teamspeak.FileTransferOptions {
	return teamspeak.FileTransferOptions{Dialer: dialer, Trace: trace}
}

//nolint:cyclop,funlen,gocyclo // checks every property of one transfer
func TestFileTransferTrace_DownloadOrderAndCoalescedProgress(t *testing.T) {
	dialer, server := pipeDialer(t)
	const size = 300 << 10
	go func() {
		key := make([]byte, len(traceKey))
		_, _ = io.ReadFull(server, key)
		// Small writes, so that coalescing has something to do.
		chunk := make([]byte, 4<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			_, _ = server.Write(chunk)
		}
		_ = server.Close()
	}()
	rec := &transferRecorder{}
	info := &teamspeak.FileDownloadInfo{FileTransferKey: traceKey, Port: 30033, Size: size}

	var got bytes.Buffer
	err := teamspeak.DownloadFileData(t.Context(), "transfer.example", info, &got, tracedOptions(dialer, rec.trace()))

	if err != nil {
		t.Fatalf("DownloadFileData: %v", err)
	}
	if rec.order[0] != "DialStart" || rec.order[1] != "DialDone" || rec.order[len(rec.order)-1] != "Done" {
		t.Fatalf("order = %v", rec.order)
	}
	if rec.count("Failed") != 0 || rec.count("Done") != 1 {
		t.Errorf("order = %v, want exactly one Done and no Failed", rec.order)
	}
	last := rec.progress[len(rec.progress)-1]
	if last.Bytes != size || last.Total != size {
		t.Errorf("final Progress = %+v, want %d of %d", last, size, size)
	}
	if n := len(rec.progress); n > size/(64<<10)+2 || n < 2 {
		t.Errorf("%d Progress calls for %d bytes: not coalesced to one per 64 KiB", n, size)
	}
	for i := 1; i < len(rec.progress); i++ {
		if rec.progress[i].Bytes < rec.progress[i-1].Bytes {
			t.Errorf("Progress went backwards: %v", rec.progress)
		}
		if i < len(rec.progress)-1 && rec.progress[i].Bytes-rec.progress[i-1].Bytes < 64<<10 {
			t.Errorf("Progress calls %d and %d are under 64 KiB apart", i-1, i)
		}
	}
	if rec.done[0].Bytes != size || rec.done[0].Duration <= 0 {
		t.Errorf("Done = %+v", rec.done[0])
	}
	if got.Len() != size {
		t.Errorf("downloaded %d bytes", got.Len())
	}
	if rec.dialDone[0].Addr != "transfer.example:30033" || rec.dialDone[0].LocalAddr == "" {
		t.Errorf("DialDone = %+v", rec.dialDone[0])
	}
	rec.requireKeyAbsent(t)
}

func (r *transferRecorder) count(name string) int {
	n := 0
	for _, o := range r.order {
		if o == name {
			n++
		}
	}

	return n
}

func TestFileTransferTrace_UploadReportsTheFinalCount(t *testing.T) {
	dialer, server := pipeDialer(t)
	const size = 100<<10 + 7
	go func() { _, _ = io.Copy(io.Discard, server) }()
	rec := &transferRecorder{}
	info := &teamspeak.FileUploadInfo{FileTransferKey: traceKey, Port: 30033}

	err := teamspeak.UploadFileData(t.Context(), "transfer.example", info,
		bytes.NewReader(make([]byte, size)), tracedOptions(dialer, rec.trace()))

	if err != nil {
		t.Fatalf("UploadFileData: %v", err)
	}
	last := rec.progress[len(rec.progress)-1]
	if last.Bytes != size || last.Total != 0 {
		t.Errorf("final Progress = %+v, want %d of an unknown total", last, size)
	}
	if rec.count("Done") != 1 || rec.count("Failed") != 0 {
		t.Errorf("order = %v", rec.order)
	}
	rec.requireKeyAbsent(t)
}

func TestFileTransferTrace_EmptyTransferStillReportsTheEnd(t *testing.T) {
	dialer, server := pipeDialer(t)
	go func() {
		key := make([]byte, len(traceKey))
		_, _ = io.ReadFull(server, key)
		_ = server.Close()
	}()
	rec := &transferRecorder{}
	info := &teamspeak.FileDownloadInfo{FileTransferKey: traceKey, Port: 30033}

	err := teamspeak.DownloadFileData(t.Context(), "h", info, io.Discard, tracedOptions(dialer, rec.trace()))

	if err != nil {
		t.Fatal(err)
	}
	if last := rec.progress[len(rec.progress)-1]; last.Bytes != 0 {
		t.Errorf("final Progress = %+v", last)
	}
}

func TestFileTransferTrace_DialFailureIsFailedInTheDialStage(t *testing.T) {
	boom := errTraceRefused
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, boom })
	rec := &transferRecorder{}

	err := teamspeak.UploadFileData(t.Context(), "h", &teamspeak.FileUploadInfo{FileTransferKey: traceKey, Port: 1},
		strings.NewReader("x"), tracedOptions(dialer, rec.trace()))

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	want := []string{"DialStart", "Failed"}
	if fmt.Sprint(rec.order) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", rec.order, want)
	}
	if got := rec.failed[0]; got.Stage != teamspeak.FileTransferStageDial || !errors.Is(got.Err, boom) || got.Bytes != 0 {
		t.Errorf("Failed = %+v", got)
	}
	rec.requireKeyAbsent(t)
}

func TestFileTransferTrace_TransferFailureIsFailedInTheTransferStage(t *testing.T) {
	dialer, server := pipeDialer(t)
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		key := make([]byte, len(traceKey))
		_, _ = io.ReadFull(server, key)
		_, _ = server.Write([]byte("partial"))
		cancel()
	}()
	rec := &transferRecorder{}
	info := &teamspeak.FileDownloadInfo{FileTransferKey: traceKey, Port: 30033, Size: 1 << 20}

	err := teamspeak.DownloadFileData(ctx, "h", info, io.Discard, tracedOptions(dialer, rec.trace()))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if rec.count("Failed") != 1 || rec.count("Done") != 0 {
		t.Fatalf("order = %v, want exactly one Failed and no Done", rec.order)
	}
	if got := rec.failed[0]; got.Stage != teamspeak.FileTransferStageTransfer || got.Bytes != 7 ||
		!errors.Is(got.Err, context.Canceled) {
		t.Errorf("Failed = %+v", got)
	}
	rec.requireKeyAbsent(t)
}

func TestFileTransferTrace_DialFileTransferAlone(t *testing.T) {
	dialer, server := pipeDialer(t)
	go func() { _, _ = io.Copy(io.Discard, server) }()
	rec := &transferRecorder{}

	conn, err := teamspeak.DialFileTransfer(t.Context(), "h", 1, traceKey, tracedOptions(dialer, rec.trace()))

	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if fmt.Sprint(rec.order) != "[DialStart DialDone]" {
		t.Errorf("order = %v", rec.order)
	}

	failing := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrUnexpectedEOF })
	rec = &transferRecorder{}
	_, err = teamspeak.DialFileTransfer(t.Context(), "h", 1, traceKey, tracedOptions(failing, rec.trace()))
	if err == nil || fmt.Sprint(rec.order) != "[DialStart Failed]" ||
		rec.failed[0].Stage != teamspeak.FileTransferStageDial {
		t.Errorf("err = %v, order = %v", err, rec.order)
	}
	rec.requireKeyAbsent(t)
}

// A hook that panics is the caller's panic: it comes out of the transfer
// function, and the connection is closed on the way.
func TestFileTransferTrace_APanicPropagatesAfterTheConnectionIsClosed(t *testing.T) {
	for _, hook := range []string{"DialDone", "Progress", "Done"} {
		t.Run(hook, func(t *testing.T) {
			dialer, server := pipeDialer(t)
			go func() {
				key := make([]byte, len(traceKey))
				_, _ = io.ReadFull(server, key)
				_, _ = server.Write([]byte("data"))
				_ = server.Close()
			}()
			trace := &teamspeak.FileTransferTrace{}
			boom := func() { panic("hook boom") }
			switch hook {
			case "DialDone":
				trace.DialDone = func(teamspeak.FileTransferDialDoneInfo) { boom() }
			case "Progress":
				trace.Progress = func(teamspeak.FileTransferProgressInfo) { boom() }
			default:
				trace.Done = func(teamspeak.FileTransferDoneInfo) { boom() }
			}
			var closed bool
			wrapped := dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
				c, err := dialer.DialContext(ctx, n, a)

				return &closeRecorder{Conn: c, closed: &closed}, err
			})
			info := &teamspeak.FileDownloadInfo{FileTransferKey: traceKey, Port: 1, Size: 4}

			func() {
				defer func() {
					if r := recover(); r != "hook boom" {
						t.Errorf("recovered %v, want the hook's panic", r)
					}
				}()
				_ = teamspeak.DownloadFileData(t.Context(), "h", info, io.Discard, tracedOptions(wrapped, trace))
				t.Error("DownloadFileData returned: the panic was swallowed")
			}()
			if !closed {
				t.Error("the connection was not closed before the panic reached the caller")
			}
		})
	}
}

type closeRecorder struct {
	net.Conn

	closed *bool
}

func (c *closeRecorder) Close() error {
	*c.closed = true

	return c.Conn.Close()
}

func TestFileTransferTrace_NoTraceNoHooks(t *testing.T) {
	dialer, server := pipeDialer(t)
	go func() {
		key := make([]byte, 3)
		_, _ = io.ReadFull(server, key)
		_, _ = server.Write([]byte("x"))
		_ = server.Close()
	}()
	var got bytes.Buffer
	info := &teamspeak.FileDownloadInfo{FileTransferKey: "key", Port: 1, Size: 1}
	err := teamspeak.DownloadFileData(t.Context(), "h", info,
		&got, tracedOptions(dialer, &teamspeak.FileTransferTrace{}))
	if err != nil || got.String() != "x" {
		t.Fatalf("err = %v, got %q", err, got.String())
	}
}
