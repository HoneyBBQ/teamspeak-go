package teamspeak

import (
	"errors"
	"strings"
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
)

const negotiationKey = "itRNdsIOvcBiBg/Xj4Ge51ZSrsShHuid"

// Measured on both servers, over ServerQuery and the voice protocol: the
// answers carry no ip, so the port is dialled on the connection's host; an ip
// that did arrive would not be read.
func TestInitFileTransfer_ReadsSizeAndSeekPosition(t *testing.T) {
	up := &script{replies: []reply{{rows: []map[string]string{{
		"clientftfid": "5", "ftkey": negotiationKey, "port": "20033", "proto": "0",
		"seekpos": "40", "serverftfid": "1", "ip": "10.0.0.7",
	}}}}}
	upInfo, err := NewCommands(up).InitFileUpload(t.Context(), 2, "/ctw.bin", 100, FileUploadOptions{Resume: true})
	if err != nil || upInfo.Port != 20033 || upInfo.Size != 100 || upInfo.SeekPosition != 40 {
		t.Errorf("upload = %+v, %v, want port 20033, size 100 and seek 40", upInfo, err)
	}
	if !strings.Contains(up.sent[0], "resume=1") {
		t.Errorf("sent %q, want resume=1", up.sent[0])
	}

	down := &script{replies: []reply{{rows: []map[string]string{{
		"clientftfid": "6", "ftkey": negotiationKey, "port": "20033", "proto": "0",
		"serverftfid": "2", "size": "100",
	}}}}}
	downInfo, err := NewCommands(down).InitFileDownload(t.Context(), 2, "/ctw.bin", FileDownloadOptions{SeekPosition: 40})
	if err != nil || downInfo.Size != 100 || downInfo.SeekPosition != 40 {
		t.Errorf("download = %+v, %v, want the whole size and the seek asked for", downInfo, err)
	}
	if !strings.Contains(down.sent[0], "seekpos=40") {
		t.Errorf("sent %q, want seekpos=40", down.sent[0])
	}
}

// Over ServerQuery a refusal is in the row, with error id=0.
func TestInitFileTransfer_ARefusalInTheRowIsTheServersError(t *testing.T) {
	row := func(status, msg string) []reply {
		return []reply{{rows: []map[string]string{{"clientftfid": "3", "status": status, "msg": msg}}}}
	}
	for _, tc := range []struct {
		run  func(c *Commands) error
		want errcode.Code
		msg  string
	}{
		{func(c *Commands) error {
			_, err := c.InitFileDownload(t.Context(), 1, "/nope", FileDownloadOptions{})

			return err
		}, errcode.FileNotFound, "file not found"},
		{func(c *Commands) error {
			_, err := c.InitFileUpload(t.Context(), 1, "/there", 3, FileUploadOptions{})

			return err
		}, errcode.FileAlreadyExists, "file already exists"},
	} {
		status := map[errcode.Code]string{errcode.FileNotFound: "2051", errcode.FileAlreadyExists: "2050"}[tc.want]
		err := tc.run(NewCommands(&script{replies: row(status, tc.msg)}))
		var serverErr *ServerError
		if !errors.Is(err, tc.want) || !errors.As(err, &serverErr) || serverErr.Message != tc.msg {
			t.Errorf("err = %v, want a *ServerError of %v saying %q", err, tc.want, tc.msg)
		}
		if errors.Is(err, ErrNoData) {
			t.Errorf("err = %v, must not read as no data", err)
		}
	}
	// A row with no key and no status is still no data.
	_, err := NewCommands(&script{replies: []reply{{rows: []map[string]string{{"clientftfid": "3"}}}}}).
		InitFileDownload(t.Context(), 1, "/x", FileDownloadOptions{})
	if !errors.Is(err, ErrNoData) {
		t.Errorf("err = %v, want ErrNoData", err)
	}
}

func TestInitFileTransfer_RefusesAPortThatIsNoPort(t *testing.T) {
	for _, port := range []string{"0", "", "65536", "70000", "x"} {
		row := map[string]string{"clientftfid": "1", "serverftfid": "2", "ftkey": negotiationKey, "port": port, "size": "3"}
		_, err := NewCommands(&script{replies: []reply{{rows: []map[string]string{row}}}}).
			InitFileUpload(t.Context(), 1, "/a", 3, FileUploadOptions{})
		if !errors.Is(err, ErrFileTransfer) {
			t.Errorf("upload with port %q: err = %v, want ErrFileTransfer", port, err)
		}
		_, err = NewCommands(&script{replies: []reply{{rows: []map[string]string{row}}}}).
			InitFileDownload(t.Context(), 1, "/a", FileDownloadOptions{})
		if !errors.Is(err, ErrFileTransfer) {
			t.Errorf("download with port %q: err = %v, want ErrFileTransfer", port, err)
		}
	}
	row := map[string]string{"clientftfid": "1", "serverftfid": "2", "ftkey": negotiationKey, "port": "65535"}
	info, err := NewCommands(&script{replies: []reply{{rows: []map[string]string{row}}}}).
		InitFileUpload(t.Context(), 1, "/a", 3, FileUploadOptions{})
	if err != nil || info.Port != 65535 {
		t.Errorf("port 65535: %+v, %v", info, err)
	}
}
