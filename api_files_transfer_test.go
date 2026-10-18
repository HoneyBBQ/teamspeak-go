package teamspeak_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

const testKey = "itRNdsIOvcBiBg/Xj4Ge51ZSrsShHuid"

// transferServer answers the negotiation commands and stands in for the file
// transfer port: each dial gets one end of a pipe, whose other end is served by
// serve with the key already read.
type transferServer struct {
	t      *testing.T
	dialed []string
	sent   []string
	serve  func(conn net.Conn)
	rows   map[string][]map[string]string
	errs   map[string]error
}

func (s *transferServer) Send(_ context.Context, req teamspeak.Request) ([]map[string]string, error) {
	s.sent = append(s.sent, req.Command())

	return s.rows[req.Command()], s.errs[req.Command()]
}

func (s *transferServer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	s.dialed = append(s.dialed, network+" "+addr)
	server, client := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		key := make([]byte, len(testKey))
		_, err := io.ReadFull(server, key)
		if err != nil || string(key) != testKey {
			s.t.Errorf("the transfer key was %q, %v", key, err)

			return
		}
		s.serve(server)
	}()

	return client, nil
}

func newTransferServer(t *testing.T) *transferServer {
	t.Helper()

	return &transferServer{t: t, rows: map[string][]map[string]string{}, errs: map[string]error{}}
}

func TestUploadFile_NegotiatesAndSends(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitupload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "seekpos": "0", "proto": "0",
	}}
	var got []byte
	done := make(chan struct{})
	srv.serve = func(conn net.Conn) {
		got, _ = io.ReadAll(conn)
		close(done)
	}

	err := teamspeak.NewCommands(srv).UploadFile(t.Context(), "ts.example", 5, "docs/a.txt", []byte("hello"),
		teamspeak.UploadFileOptions{Overwrite: true, Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if string(got) != "hello" {
		t.Errorf("the server received %q, want hello", got)
	}
	if len(srv.dialed) != 1 || srv.dialed[0] != "tcp ts.example:30033" {
		t.Errorf("dialed %v, want tcp ts.example:30033", srv.dialed)
	}
}

// The address the server names is the one dialled.
func TestUploadFile_DialsTheAddressTheServerNames(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitupload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "ip": "10.0.0.7",
	}}
	srv.serve = func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) }

	err := teamspeak.NewCommands(srv).UploadFile(t.Context(), "ts.example", 5, "/a", []byte("x"),
		teamspeak.UploadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.dialed) != 1 || srv.dialed[0] != "tcp 10.0.0.7:30033" {
		t.Errorf("dialed %v, want the named address", srv.dialed)
	}
}

func TestUploadFile_ARefusalIsTheServersAndNothingIsDialled(t *testing.T) {
	srv := newTransferServer(t)
	srv.errs["ftinitupload"] = &teamspeak.ServerError{Code: errcode.PermissionsClientInsufficient}

	err := teamspeak.NewCommands(srv).UploadFile(t.Context(), "h", 5, "/a", []byte("x"),
		teamspeak.UploadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if !errors.Is(err, errcode.PermissionsClientInsufficient) || len(srv.dialed) != 0 {
		t.Errorf("err = %v, dialed %v, want the refusal and no dial", err, srv.dialed)
	}
}

func TestDownloadFile_NegotiatesAndReturnsTheBytes(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitdownload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "size": "5",
	}}
	srv.serve = func(conn net.Conn) { _, _ = conn.Write([]byte("hello")) }

	got, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "ts.example", 5, "/a.txt",
		teamspeak.DownloadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Errorf("got %q, %v, want hello", got, err)
	}
	if len(srv.dialed) != 1 || srv.dialed[0] != "tcp ts.example:30033" {
		t.Errorf("dialed %v", srv.dialed)
	}
}

// A file over the limit is refused before a byte is fetched.
func TestDownloadFile_RefusesAFileOverTheLimitBeforeDialling(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitdownload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "size": "100",
	}}

	got, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/big",
		teamspeak.DownloadFileOptions{MaxSize: 99, Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if !errors.Is(err, teamspeak.ErrFileTransfer) || got != nil || len(srv.dialed) != 0 {
		t.Errorf("got %q, %v, dialed %v, want ErrFileTransfer and no dial", got, err, srv.dialed)
	}
	// The transfer the server prepared is stopped, not left listed as active.
	if want := []string{"ftinitdownload", "ftstop"}; !slices.Equal(srv.sent, want) {
		t.Errorf("commands = %v, want %v", srv.sent, want)
	}
}

// A download that ends short of the announced size is an error, not a short file.
func TestDownloadFile_ShortFileIsAnError(t *testing.T) {
	srv := newTransferServer(t)
	srv.rows["ftinitdownload"] = []map[string]string{{
		"clientftfid": "1", "serverftfid": "2", "ftkey": testKey, "port": "30033", "size": "5",
	}}
	srv.serve = func(conn net.Conn) { _, _ = conn.Write([]byte("hel")) }

	got, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/a",
		teamspeak.DownloadFileOptions{Transfer: teamspeak.FileTransferOptions{Dialer: srv}})
	if !errors.Is(err, io.ErrUnexpectedEOF) || got != nil {
		t.Errorf("got %q, %v, want io.ErrUnexpectedEOF", got, err)
	}
}

func TestDownloadFile_ARefusalIsTheServers(t *testing.T) {
	srv := newTransferServer(t)
	srv.errs["ftinitdownload"] = &teamspeak.ServerError{Code: errcode.FileNotFound}

	_, err := teamspeak.NewCommands(srv).DownloadFile(t.Context(), "h", 5, "/a", teamspeak.DownloadFileOptions{})
	if !errors.Is(err, errcode.FileNotFound) {
		t.Errorf("err = %v, want FileNotFound", err)
	}
}
