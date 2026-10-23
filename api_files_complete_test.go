package teamspeak

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/ftdial"
)

// fileScript answers each command from the table, and counts the commands.
type fileScript struct {
	rows map[string][]map[string]string
	errs map[string]error
	sent []string
}

func (s *fileScript) Send(_ context.Context, req Request) ([]map[string]string, error) {
	s.sent = append(s.sent, req.Command())

	return s.rows[req.Command()], s.errs[req.Command()]
}

func negotiatedRows(command string) map[string][]map[string]string {
	return map[string][]map[string]string{command: {{
		"clientftfid": "1", "serverftfid": "7", "ftkey": "key", "port": "30033", "seekpos": "0", "size": "5",
	}}}
}

func heldRows(size string) []map[string]string {
	return []map[string]string{{"name": "a", "size": size, "datetime": "0", "type": "1"}}
}

// echoDialer opens a pipe whose far end reads the key and what follows, then
// closes, as the server does with a whole file.
type echoDialer struct{ want int }

func (d echoDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	server, client := net.Pipe()
	go func() {
		_, _ = io.ReadFull(server, make([]byte, len("key")+d.want))
		_ = server.Close()
	}()

	return client, nil
}

var errRefused = errors.New("connection refused")

// refusingDialer is a TCP connect that is refused.
type refusingDialer struct{ calls int }

func (d *refusingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++

	return nil, errRefused
}

// openThenDropDialer opens the connection, takes the key and drops it.
type openThenDropDialer struct{}

func (openThenDropDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	server, client := net.Pipe()
	go func() {
		_, _ = io.ReadFull(server, make([]byte, len("key")))
		_ = server.Close()
	}()

	return client, nil
}

func TestUploadFile_FailsWhenTheServerHoldsAnotherSize(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []map[string]string
		err  error
		want string
	}{
		{name: "fewer bytes", rows: heldRows("2"), want: "holds 2 of the 5 bytes"},
		{name: "no file on TeamSpeak 6", err: &ServerError{Code: errcode.FileNotFound}, want: "has no file"},
		{name: "no file on TeamSpeak 3", err: &ServerError{Code: errcode.FileIOError}, want: "has no file"},
	} {
		s := &fileScript{rows: negotiatedRows("ftinitupload"), errs: map[string]error{"ftgetfileinfo": tc.err}}
		s.rows["ftgetfileinfo"] = tc.rows
		err := NewCommands(s).UploadFile(t.Context(), "h", 1, "/a", []byte("hello"),
			UploadFileOptions{Transfer: FileTransferOptions{Dialer: echoDialer{want: 5}}})
		if !errors.Is(err, ErrFileTransfer) || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want ErrFileTransfer with %q", tc.name, err, tc.want)
		}
		if !slices.Equal(s.sent, []string{"ftinitupload", "ftgetfileinfo"}) {
			t.Errorf("%s: commands = %v", tc.name, s.sent)
		}
	}
}

func TestUploadFile_CountsOnTheCloseWhenTheClientMayNotLook(t *testing.T) {
	s := &fileScript{rows: negotiatedRows("ftinitupload"), errs: map[string]error{
		"ftgetfileinfo": &ServerError{Code: errcode.PermissionsClientInsufficient},
	}}
	err := NewCommands(s).UploadFile(t.Context(), "h", 1, "/a", []byte("hello"),
		UploadFileOptions{Transfer: FileTransferOptions{Dialer: echoDialer{want: 5}}})
	if err != nil {
		t.Errorf("err = %v, want success on 2568", err)
	}

	flooding := errcode.ClientIsFlooding
	s = &fileScript{rows: negotiatedRows("ftinitupload"), errs: map[string]error{
		"ftgetfileinfo": &ServerError{Code: flooding},
	}}
	err = NewCommands(s).UploadFile(t.Context(), "h", 1, "/a", []byte("hello"),
		UploadFileOptions{Transfer: FileTransferOptions{Dialer: echoDialer{want: 5}}})
	if !errors.Is(err, flooding) {
		t.Errorf("err = %v, want the command's own failure", err)
	}
}

func TestFileCalls_StopTheTransferWhenTheDialIsRefused(t *testing.T) {
	for name, run := range map[string]func(c *Commands, d FileTransferDialer) error{
		"upload": func(c *Commands, d FileTransferDialer) error {
			return c.UploadFile(t.Context(), "h", 1, "/a", []byte("hello"),
				UploadFileOptions{Transfer: FileTransferOptions{Dialer: d}})
		},
		"download": func(c *Commands, d FileTransferDialer) error {
			_, err := c.DownloadFile(t.Context(), "h", 1, "/a", DownloadFileOptions{Transfer: FileTransferOptions{Dialer: d}})

			return err
		},
	} {
		command := "ftinitupload"
		if name == "download" {
			command = "ftinitdownload"
		}
		// The stop fails too: the dial's error is still the one returned.
		s := &fileScript{rows: negotiatedRows(command), errs: map[string]error{"ftstop": ErrNotConnected}}
		dialer := &refusingDialer{}
		err := run(NewCommands(s), dialer)
		if !errors.Is(err, ErrFileTransfer) || errors.Is(err, ErrNotConnected) || !errors.Is(err, errRefused) {
			t.Errorf("%s: err = %v, want the refused dial", name, err)
		}
		if !slices.Equal(s.sent, []string{command, "ftstop"}) {
			t.Errorf("%s: commands = %v, want the negotiation and ftstop", name, s.sent)
		}
	}
}

func TestFileCalls_DoNotStopAfterTheConnectionOpened(t *testing.T) {
	s := &fileScript{rows: negotiatedRows("ftinitdownload")}
	_, err := NewCommands(s).DownloadFile(t.Context(), "h", 1, "/a",
		DownloadFileOptions{Transfer: FileTransferOptions{Dialer: openThenDropDialer{}}})
	if !errors.Is(err, ErrFileTransfer) {
		t.Fatalf("err = %v, want a failed download", err)
	}
	if !slices.Equal(s.sent, []string{"ftinitdownload"}) {
		t.Errorf("commands = %v, want no ftstop once the connection opened", s.sent)
	}
}

func TestFileCalls_DoNotStopWhenTheCallersContextEndedTheDial(t *testing.T) {
	s := &fileScript{rows: negotiatedRows("ftinitdownload")}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := NewCommands(s).DownloadFile(ctx, "h", 1, "/a",
		DownloadFileOptions{Transfer: FileTransferOptions{Dialer: &refusingDialer{}}})
	if err == nil {
		t.Fatal("want an error")
	}
	// The negotiation itself ran: s ignores the context. Nothing followed it.
	if !slices.Equal(s.sent, []string{"ftinitdownload"}) {
		t.Errorf("commands = %v, want no ftstop", s.sent)
	}
}

// ftstop of a transfer the server has already dropped crashes TeamSpeak 6, and
// it drops one nobody dialled after about 10 seconds.
func TestFileCalls_DoNotStopATransferTheServerProbablyDropped(t *testing.T) {
	old := ftdial.StopWithin
	ftdial.StopWithin = 0
	t.Cleanup(func() { ftdial.StopWithin = old })

	s := &fileScript{rows: negotiatedRows("ftinitdownload")}
	_, err := NewCommands(s).DownloadFile(t.Context(), "h", 1, "/a",
		DownloadFileOptions{Transfer: FileTransferOptions{Dialer: &refusingDialer{}}})
	if !errors.Is(err, ErrFileTransfer) || !slices.Equal(s.sent, []string{"ftinitdownload"}) {
		t.Errorf("err = %v, commands = %v, want no ftstop past the window", err, s.sent)
	}
}
