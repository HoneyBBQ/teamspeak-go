package teamspeak

import (
	"errors"
	"strings"
	"testing"
)

var errCaptured = errors.New("captured")

// captureCommand runs fn on a client whose command chain records the outgoing
// command and stops it before it reaches the wire.
func captureCommand(t *testing.T, fn func(*Client) error) string {
	t.Helper()
	c := newTestClient(t)
	var sent string
	c.UseCommandMiddleware(func(_ func(string) error) func(string) error {
		return func(cmd string) error {
			sent = cmd

			return errCaptured
		}
	})
	err := fn(c)
	if !errors.Is(err, errCaptured) {
		t.Fatalf("expected the captured sentinel, got %v", err)
	}

	return sent
}

func TestClientMove_HashesChannelPassword(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error { return c.MoveClient(t.Context(), 5, 7, "hunter2") })

	// base64(sha1("hunter2")), escaped for the wire ("/" -> "\/").
	want := "cpw=" + strings.ReplaceAll(prepareClientPassword("hunter2"), "/", `\/`)
	if !strings.Contains(sent, want) {
		t.Errorf("clientmove = %q, want it to contain %q", sent, want)
	}
	if strings.Contains(sent, "cpw=hunter2") {
		t.Errorf("clientmove sent the plain password: %q", sent)
	}
}

func TestClientMove_OmitsEmptyPassword(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error { return c.MoveClient(t.Context(), 5, 7, "") })
	if strings.Contains(sent, "cpw") {
		t.Errorf("clientmove = %q, want no cpw", sent)
	}
}

func TestFileTransfer_HashesChannelPassword(t *testing.T) {
	// ftinitupload and ftinitdownload reject a plain channel password with
	// error 781, exactly like clientmove.
	want := "cpw=" + strings.ReplaceAll(prepareClientPassword("hunter2"), "/", `\/`)

	upload := captureCommand(t, func(c *Client) error {
		_, err := c.InitFileUpload(t.Context(), 7, "/a.txt", 4, "hunter2", true)

		return err
	})
	download := captureCommand(t, func(c *Client) error {
		_, err := c.InitFileDownload(t.Context(), 7, "/a.txt", "hunter2", 0)

		return err
	})
	for name, sent := range map[string]string{"ftinitupload": upload, "ftinitdownload": download} {
		if !strings.Contains(sent, want) {
			t.Errorf("%s = %q, want it to contain %q", name, sent, want)
		}
	}
}
