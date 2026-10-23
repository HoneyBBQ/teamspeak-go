package teamspeak_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

// errMustNotDial is what a dialer that no test expects to be used returns.
var errMustNotDial = errors.New("must not dial")

// serveUpload reads the transfer key, "key", and then up to want bytes, and
// closes the connection once it holds them, as the server does with a whole
// file after delay. It reports the bytes it got, key excluded, when it is done.
func serveUpload(server net.Conn, want int, delay time.Duration) <-chan []byte {
	done := make(chan []byte, 1)
	go func() {
		_, _ = io.ReadFull(server, make([]byte, len("key")))
		got := make([]byte, want)
		n, _ := io.ReadFull(server, got)
		time.Sleep(delay)
		_ = server.Close()
		done <- got[:n]
	}()

	return done
}

func TestUploadFileData_ReturnsOnlyOnceTheServerHasClosed(t *testing.T) {
	dialer, server := pipeDialer(t)
	done := serveUpload(server, 5, 150*time.Millisecond)

	start := time.Now()
	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 5}
	err := teamspeak.UploadFileData(t.Context(), "h", info, strings.NewReader("hello"), viaDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	// Without the wait the call would be done as soon as the bytes had left.
	if elapsed := time.Since(start); elapsed < 120*time.Millisecond {
		t.Errorf("returned after %v, before the server closed", elapsed)
	}
	if got := <-done; string(got) != "hello" {
		t.Errorf("the server got %q", got)
	}
}

func TestUploadFileData_FailsWhenTheServerNeverCloses(t *testing.T) {
	dialer, server := pipeDialer(t)
	go func() { _, _ = io.Copy(io.Discard, server) }()

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 5}
	err := teamspeak.UploadFileData(t.Context(), "h", info, strings.NewReader("hello"), idleOptions(dialer))
	requireIdleError(t, err)
}

func TestUploadFileData_FailsWhenTheServerClosesBeforeTheLastByte(t *testing.T) {
	dialer, server := pipeDialer(t)
	go func() {
		_, _ = io.ReadFull(server, make([]byte, len("key")+10))
		_ = server.Close()
	}()

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 1 << 20}
	err := teamspeak.UploadFileData(t.Context(), "h", info, bytes.NewReader(make([]byte, 1<<20)), viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Fatalf("err = %v, want ErrFileTransfer", err)
	}
}

func TestUploadFileData_FailsOnAShortReader(t *testing.T) {
	dialer, server := pipeDialer(t)
	done := serveUpload(server, 10, 0)

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 10}
	err := teamspeak.UploadFileData(t.Context(), "h", info, strings.NewReader("hello"), viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want ErrFileTransfer wrapping io.ErrUnexpectedEOF", err)
	}
	// The connection is closed, which ends the transfer on the server.
	if got := <-done; string(got) != "hello" {
		t.Errorf("the server got %q", got)
	}
}

func TestUploadFileData_FailsOnALongReaderAndSendsNoneOfTheExcess(t *testing.T) {
	dialer, server := pipeDialer(t)
	done := serveUpload(server, 100, 0)

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 5}
	err := teamspeak.UploadFileData(t.Context(), "h", info, strings.NewReader("hello-and-more"), viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) || !strings.Contains(err.Error(), "longer than the declared size") {
		t.Fatalf("err = %v, want a failure for the excess", err)
	}
	if got := <-done; string(got) != "hello" {
		t.Errorf("the server got %q, want only the declared bytes", got)
	}
}

func TestUploadFileData_SendsFromTheSeekPosition(t *testing.T) {
	dialer, server := pipeDialer(t)
	done := serveUpload(server, 3, 0)

	info := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 10, SeekPosition: 7}
	err := teamspeak.UploadFileData(t.Context(), "h", info, strings.NewReader("789"), viaDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	if got := <-done; string(got) != "789" {
		t.Errorf("the server got %q", got)
	}
}

func TestFileTransfer_RefusesASeekPastTheEndWithoutDialling(t *testing.T) {
	dialled := false
	dialer := dialerFunc(func(_ context.Context, _, _ string) (net.Conn, error) {
		dialled = true

		return nil, errMustNotDial
	})
	up := &teamspeak.FileUploadInfo{FileTransferKey: "key", Port: 1, Size: 10, SeekPosition: 11}
	err := teamspeak.UploadFileData(t.Context(), "h", up, strings.NewReader(""), viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("upload: err = %v, want ErrFileTransfer", err)
	}
	down := &teamspeak.FileDownloadInfo{FileTransferKey: "key", Port: 1, Size: 10, SeekPosition: 11}
	err = teamspeak.DownloadFileData(t.Context(), "h", down, io.Discard, viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) {
		t.Errorf("download: err = %v, want ErrFileTransfer", err)
	}
	if dialled {
		t.Error("dialled for a transfer that cannot happen")
	}
}

func TestFileTransfer_RefusesPortZeroWithoutDialling(t *testing.T) {
	dialled := false
	dialer := dialerFunc(func(_ context.Context, _, _ string) (net.Conn, error) {
		dialled = true

		return nil, errMustNotDial
	})
	_, err := teamspeak.DialFileTransfer(t.Context(), "h", 0, "key", viaDialer(dialer))
	if !errors.Is(err, teamspeak.ErrFileTransfer) || dialled {
		t.Errorf("err = %v, dialled %v, want ErrFileTransfer and no dial", err, dialled)
	}
}

// Measured on both servers: a seekpos of 40000 on a 100000-byte file is
// answered with the whole size and then 60000 bytes.
func TestDownloadFileData_ExpectsTheBytesFromTheSeekPositionOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		send    string
		wantErr string
	}{
		{"exact", "456789", ""},
		{"short", "4567", "unexpected EOF"},
		{"long", "4567890", "more data than the announced size"},
	} {
		dialer, server := pipeDialer(t)
		go func() {
			_, _ = io.ReadFull(server, make([]byte, len("key")))
			_, _ = server.Write([]byte(tc.send))
			_ = server.Close()
		}()

		var got bytes.Buffer
		info := &teamspeak.FileDownloadInfo{FileTransferKey: "key", Port: 1, Size: 10, SeekPosition: 4}
		err := teamspeak.DownloadFileData(t.Context(), "h", info, &got, viaDialer(dialer))
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
		if tc.name == "exact" && got.String() != "456789" {
			t.Errorf("got %q", got.String())
		}
	}
}

func TestUploadFile_ResumeSendsOnlyWhatTheServerDoesNotHold(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitupload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "seekpos": "3",
	}}
	srv.rows["ftgetfileinfo"] = []map[string]string{{"name": "a", "size": "5", "datetime": "0", "type": "1"}}
	var got []byte
	srv.serve = func(conn net.Conn) {
		got = make([]byte, 2)
		_, _ = io.ReadFull(conn, got)
	}

	err := teamspeak.NewCommands(srv).UploadFile(t.Context(), "h", 5, "/a", []byte("hello"),
		teamspeak.UploadFileOptions{Resume: true, Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil || string(got) != "lo" {
		t.Errorf("err = %v, the server got %q, want lo", err, got)
	}
}

func TestDownloadFile_SeekPositionBringsTheRestOfTheFile(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitdownload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "size": "10",
	}}
	srv.serve = func(conn net.Conn) { _, _ = conn.Write([]byte("456789")) }

	got, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/a",
		teamspeak.DownloadFileOptions{SeekPosition: 4, Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil || string(got) != "456789" {
		t.Errorf("got %q, %v, want 456789", got, err)
	}
	// MaxSize limits the bytes held, which a seek makes fewer than the file.
	srv.dialed = nil
	got, err = teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/a",
		teamspeak.DownloadFileOptions{SeekPosition: 4, MaxSize: 6, Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil || string(got) != "456789" {
		t.Errorf("under MaxSize: got %q, %v", got, err)
	}
}

// Over ServerQuery a refusal arrives in the answer's row, with error id=0.
func TestUploadAndDownloadFile_ARefusalInTheRowIsTheServersError(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitdownload"] = []map[string]string{{"clientftfid": "1", "status": "2051", "msg": "file not found"}}
	srv.rows["ftinitupload"] = []map[string]string{{"clientftfid": "2", "status": "2050", "msg": "file already exists"}}

	_, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/a", teamspeak.DownloadFileOptions{})
	if !errors.Is(err, errcode.FileNotFound) {
		t.Errorf("download: err = %v, want FileNotFound", err)
	}
	err = teamspeak.NewCommands(srv).UploadFile(t.Context(), "h", 5, "/a", []byte("x"), teamspeak.UploadFileOptions{})
	if !errors.Is(err, errcode.FileAlreadyExists) {
		t.Errorf("upload: err = %v, want FileAlreadyExists", err)
	}
	if len(srv.dialed) != 0 {
		t.Errorf("dialled %v after a refusal", srv.dialed)
	}
}
