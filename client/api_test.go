package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/identity"
)

var errCaptured = errors.New("captured")

// captureCommand runs fn on a client whose command chain records the outgoing
// command and stops it before it reaches the wire.
func captureCommand(t *testing.T, fn func(*Client) error) string {
	t.Helper()
	var sent string
	c := newTestClient(t)
	c.wireHook = func(line string) error {
		sent = line

		return errCaptured
	}
	err := fn(c)
	if !errors.Is(err, errCaptured) {
		t.Fatalf("expected the captured sentinel, got %v", err)
	}

	return sent
}

func TestClientMove_HashesChannelPassword(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		return c.MoveClient(t.Context(), 5, 7, teamspeak.ClientMoveOptions{Password: "hunter2"})
	})

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
	sent := captureCommand(t, func(c *Client) error {
		return c.MoveClient(t.Context(), 5, 7, teamspeak.ClientMoveOptions{})
	})
	if strings.Contains(sent, "cpw") {
		t.Errorf("clientmove = %q, want no cpw", sent)
	}
}

func TestFileTransfer_HashesChannelPassword(t *testing.T) {
	// ftinitupload and ftinitdownload reject a plain channel password with
	// error 781, exactly like clientmove.
	want := "cpw=" + strings.ReplaceAll(prepareClientPassword("hunter2"), "/", `\/`)

	upload := captureCommand(t, func(c *Client) error {
		opts := teamspeak.FileUploadOptions{Password: "hunter2", Overwrite: true}
		_, err := c.InitFileUpload(t.Context(), 7, "/a.txt", 4, opts)

		return err
	})
	download := captureCommand(t, func(c *Client) error {
		_, err := c.InitFileDownload(t.Context(), 7, "/a.txt", teamspeak.FileDownloadOptions{Password: "hunter2"})

		return err
	})
	for name, sent := range map[string]string{"ftinitupload": upload, "ftinitdownload": download} {
		if !strings.Contains(sent, want) {
			t.Errorf("%s = %q, want it to contain %q", name, sent, want)
		}
	}
}

// Sending before Connect, or after Disconnect, fails cleanly.
func TestSendsWithoutAConnectionReturnErrNotConnected(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := mustNew(t, id, "idle")

	err = c.SendVoice([]byte{1}, teamspeak.CodecOpusVoice)
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("SendVoice = %v, want ErrNotConnected", err)
	}
	err = c.SendWhisper([]byte{1}, []teamspeak.ClientID{1}, teamspeak.CodecOpusVoice)
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("SendWhisper = %v, want ErrNotConnected", err)
	}
	err = c.ExecNoWait(t.Context(), "clientupdate")
	if !errors.Is(err, teamspeak.ErrNotConnected) {
		t.Errorf("ExecNoWait = %v, want ErrNotConnected", err)
	}
}

func TestClientFormattingHidesPasswords(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := mustNew(t, id, "bot", WithServerPassword("server-s3cret"), WithDefaultChannelPassword("chan-s3cret"))
	secrets := []string{"server-s3cret", "chan-s3cret", prepareClientPassword("server-s3cret"),
		prepareClientPassword("chan-s3cret"), id.Export()}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		for _, v := range []any{c, c.clientInitOptions, *c.clientInitOptions} {
			out := fmt.Sprintf(verb, v)
			for _, secret := range secrets {
				if strings.Contains(out, secret) {
					t.Errorf("%T with %s leaks %q", v, verb, secret)
				}
			}
		}
	}
	wantHash := commands.Escape(prepareClientPassword("server-s3cret"))
	if !strings.Contains(c.buildClientInitCommand(c.handler.TsCrypt), wantHash) {
		t.Error("clientinit no longer carries the server password hash")
	}
}

// Mid-handshake, with the transport open and even the shared secret set, no
// command, raw line, voice or whisper goes out: only a connected session sends.
func TestSendsWhileConnectingReturnErrNotConnected(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)
	var sent []string
	c.wireHook = func(line string) error {
		sent = append(sent, line)

		return nil
	}

	checks := map[string]error{
		"SendVoice":   c.SendVoice([]byte{1}, teamspeak.CodecOpusVoice),
		"SendWhisper": c.SendWhisper([]byte{1}, []teamspeak.ClientID{1}, teamspeak.CodecOpusVoice),
		"ExecNoWait":  c.ExecNoWait(t.Context(), "clientupdate"),
	}
	_, checks["Exec"] = c.Exec(t.Context(), "whoami")
	_, checks["ListChannels"] = c.ListChannels(t.Context())
	for name, err := range checks {
		if !errors.Is(err, teamspeak.ErrNotConnected) {
			t.Errorf("%s = %v, want ErrNotConnected", name, err)
		}
	}
	if len(sent) != 0 {
		t.Errorf("sent %q while connecting", sent)
	}
}

// The voice-only commands are typed requests too, so command middleware sees
// them as it sees the shared ones.
func TestVoiceOnlyCommandsPassThroughCommandMiddleware(t *testing.T) {
	var seen []string
	c := newTestClient(t, WithCommandMiddleware(func(teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(_ context.Context, req teamspeak.Request) ([]map[string]string, error) {
			seen = append(seen, req.Command())

			return []map[string]string{{"channel_description": "hello"}}, nil
		})
	}))

	desc, err := c.GetChannelDescription(t.Context(), 7)
	if err != nil || desc != "hello" {
		t.Fatalf("GetChannelDescription = %q, %v", desc, err)
	}
	for _, call := range []func(context.Context) error{
		func(ctx context.Context) error { return c.SubscribeChannel(ctx, 7) },
		func(ctx context.Context) error { return c.UnsubscribeChannel(ctx, 7) },
		c.SubscribeAllChannels,
		c.UnsubscribeAllChannels,
	} {
		err = call(t.Context())
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"channelgetdescription", "channelsubscribe", "channelunsubscribe",
		"channelsubscribeall", "channelunsubscribeall"}
	if !slices.Equal(seen, want) {
		t.Errorf("middleware saw %q, want %q", seen, want)
	}
}
