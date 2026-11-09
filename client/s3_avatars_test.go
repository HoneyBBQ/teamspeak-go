package client

import (
	"crypto/md5" //nolint:gosec // the avatar's flag on the wire is its MD5
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
)

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// avatarServer signs every URL for s and says every other command succeeded.
func avatarServer(t *testing.T, s *s3Storage) (*Client, *fakeS3Server) {
	t.Helper()

	return newS3Client(t, []string{"s3"}, func(line teamspeak.CommandLine) ([]map[string]string, error) {
		if strings.HasPrefix(line.Text, "s3ft_getpresignedurl") {
			return []map[string]string{{"url": s.URL + "/bucket/k?sig=secret", "key": "/k"}}, nil
		}

		return []map[string]string{{"success": "1"}}, nil
	})
}

func TestUploadS3Avatar_UploadsUnderTheOwnNameThenSetsTheFlag(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	c, server := avatarServer(t, s)
	data := []byte("pixels")
	sum := md5.Sum(data) //nolint:gosec // see the import
	want := hex.EncodeToString(sum[:])

	got, err := c.UploadS3Avatar(t.Context(), data, s.transfer())
	requireNoError(t, err)
	if got != want {
		t.Errorf("md5 = %q, want %q", got, want)
	}
	name, err := teamspeak.AvatarFileName(c.UID())
	requireNoError(t, err)
	if len(server.lines) != 3 ||
		!strings.HasPrefix(server.lines[0], "s3ft_getpresignedurl chid=0 chpw=|key=\\/"+name+" verb=PUT length=6") ||
		server.lines[1] != "s3ft_upload_done_notification chid=0 chpw=" ||
		server.lines[2] != "clientupdate client_flag_avatar="+want {
		t.Errorf("sent %q", server.lines)
	}
	if string(s.bodies[0]) != "pixels" {
		t.Errorf("stored %q", s.bodies[0])
	}
}

func TestUploadS3Avatar_ARefusedSigningChangesNothing(t *testing.T) {
	s := newS3Storage(t, func(http.ResponseWriter, *http.Request) {})
	refusal := &teamspeak.ServerError{Code: errcode.FileInvalidPermissions}
	c, server := newS3Client(t, []string{"s3"}, func(teamspeak.CommandLine) ([]map[string]string, error) {
		return nil, refusal
	})
	_, err := c.UploadS3Avatar(t.Context(), []byte("x"), s.transfer())
	if !errors.Is(err, refusal) || len(server.lines) != 1 || len(s.requests) != 0 {
		t.Errorf("err = %v, sent %q, storage saw %d", err, server.lines, len(s.requests))
	}
}

func TestUploadS3Avatar_ARefusedFlagIsReturnedWithTheFileStored(t *testing.T) {
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	refusal := &teamspeak.ServerError{Code: errcode.PermissionsClientInsufficient}
	c, server := newS3Client(t, []string{"s3"}, func(line teamspeak.CommandLine) ([]map[string]string, error) {
		switch {
		case strings.HasPrefix(line.Text, "s3ft_getpresignedurl"):
			return []map[string]string{{"url": s.URL + "/bucket/k?sig=secret", "key": "/k"}}, nil
		case strings.HasPrefix(line.Text, "clientupdate"):
			return nil, refusal
		default:
			return []map[string]string{{"success": "1"}}, nil
		}
	})
	_, err := c.UploadS3Avatar(t.Context(), []byte("pixels"), s.transfer())
	if !errors.Is(err, refusal) || len(server.lines) != 3 || len(s.bodies) != 1 {
		t.Errorf("err = %v, sent %q, storage stored %d", err, server.lines, len(s.bodies))
	}
}

func TestDownloadS3Avatar(t *testing.T) {
	status := http.StatusOK
	s := newS3Storage(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte("pixels"))
		}
	})
	c, server := avatarServer(t, s)
	uid := c.UID()
	name, err := teamspeak.AvatarFileName(uid)
	requireNoError(t, err)

	got, ok, err := c.DownloadS3Avatar(t.Context(), uid, s.transfer())
	if err != nil || !ok || string(got) != "pixels" {
		t.Fatalf("got %q, %v, %v", got, ok, err)
	}
	if want := "s3ft_getpresignedurl chid=0 chpw=|key=\\/" + name + " verb=GET length=0"; server.lines[0] != want {
		t.Errorf("sent %q, want %q", server.lines[0], want)
	}

	status = http.StatusNotFound
	got, ok, err = c.DownloadS3Avatar(t.Context(), uid, s.transfer())
	if err != nil || ok || got != nil {
		t.Errorf("missing: got %q, %v, %v, want nil, false, nil", got, ok, err)
	}

	status = http.StatusForbidden
	_, _, err = c.DownloadS3Avatar(t.Context(), uid, s.transfer())
	var failed *S3TransferError
	if !errors.As(err, &failed) || failed.Status != http.StatusForbidden {
		t.Errorf("forbidden: err = %v, want an *S3TransferError", err)
	}

	_, _, err = c.DownloadS3Avatar(t.Context(), teamspeak.UID("not base64!"), s.transfer())
	if !errors.Is(err, teamspeak.ErrInvalidUID) {
		t.Errorf("err = %v, want ErrInvalidUID", err)
	}
}

func TestRemoveS3Avatar_DeletesTheFileThenEmptiesTheFlag(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, successAnswer("1"))
	requireNoError(t, c.RemoveS3Avatar(t.Context()))
	name, err := teamspeak.AvatarFileName(c.UID())
	requireNoError(t, err)
	if len(server.lines) != 2 ||
		server.lines[0] != "s3ft_deletefile chid=0 chpw= key=\\/"+name ||
		server.lines[1] != "clientupdate client_flag_avatar=" {
		t.Errorf("sent %q", server.lines)
	}
}

func TestRemoveS3Avatar_AFailedDeleteLeavesTheFlag(t *testing.T) {
	c, server := newS3Client(t, []string{"s3"}, successAnswer("0"))
	err := c.RemoveS3Avatar(t.Context())
	var failed *S3TransferError
	if !errors.As(err, &failed) || len(server.lines) != 1 {
		t.Errorf("err = %v, sent %q", err, server.lines)
	}
}

func TestS3Icons(t *testing.T) {
	status := http.StatusOK
	s := newS3Storage(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if r.Method == http.MethodGet && status == http.StatusOK {
			_, _ = w.Write([]byte("icon"))
		}
	})
	c, server := avatarServer(t, s)
	data := []byte("icon")
	id := teamspeak.IconIDOf(data)
	file := `\/icon_` + strconv.FormatUint(uint64(id), 10)

	got, err := c.UploadS3Icon(t.Context(), data, s.transfer())
	if err != nil || got != id {
		t.Fatalf("UploadS3Icon = %d, %v, want %d", got, err, id)
	}
	if len(server.lines) != 2 ||
		!strings.HasPrefix(server.lines[0], "s3ft_getpresignedurl chid=0 chpw=|key="+file+" verb=PUT length=4") ||
		server.lines[1] != "s3ft_upload_done_notification chid=0 chpw=" {
		t.Errorf("sent %q", server.lines)
	}

	bytes, ok, err := c.DownloadS3Icon(t.Context(), id, s.transfer())
	if err != nil || !ok || string(bytes) != "icon" {
		t.Errorf("download = %q, %v, %v", bytes, ok, err)
	}
	status = http.StatusNotFound
	bytes, ok, err = c.DownloadS3Icon(t.Context(), id, s.transfer())
	if err != nil || ok || bytes != nil {
		t.Errorf("missing = %q, %v, %v, want nil, false, nil", bytes, ok, err)
	}

	n := len(server.lines)
	requireNoError(t, c.DeleteS3Icon(t.Context(), id))
	if server.lines[n] != "s3ft_deletefile chid=0 chpw= key="+file {
		t.Errorf("sent %q", server.lines[n])
	}
}
