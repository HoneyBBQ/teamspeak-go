package client

import (
	"errors"
	"fmt"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// selfEnterLine is a notifycliententerview for client id under nickname.
func selfEnterLine(id int, nickname string) string {
	return fmt.Sprintf("notifycliententerview clid=%d client_nickname=%s ctid=1 client_type=0"+
		" client_servergroups= client_unique_identifier=x", id, nickname)
}

// initNickname is the nickname the client's next clientinit carries.
func initNickname(c *Client) string {
	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))

	return cmd.Params["client_nickname"]
}

// answerWith makes the client's commands come back as the server's answer line,
// with the command's return_code.
func answerWith(c *Client, answer string) {
	c.wireHook = func(line string) error {
		rc := wire.ParseCommand(line).Params["return_code"]
		c.handleCommand(c.handler, answer+" return_code="+rc)

		return nil
	}
}

func TestNickname_ReconnectAsksForTheRequestedName(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 5
	c.mu.Unlock()

	// The requested name was taken, so the server calls us TestBot1.
	c.handleClientEnterView(c.handler, wire.ParseCommand(selfEnterLine(5, "TestBot1")))

	if got := ownNickname(c); got != "TestBot1" {
		t.Errorf("current nickname = %q, want TestBot1", got)
	}
	if got := initNickname(c); got != "TestBot" {
		t.Errorf("clientinit nickname = %q, want the requested TestBot", got)
	}
}

func TestNickname_WelcomeEnterIsRecognisedByTheRequestedName(t *testing.T) {
	c := newTestClient(t)
	c.handleClientEnterView(c.handler, wire.ParseCommand(selfEnterLine(7, "TestBot3")))
	// A second welcome enter leaves the first match in place.
	c.handleClientEnterView(c.handler, wire.ParseCommand(selfEnterLine(8, "TestBot")))

	c.mu.Lock()
	clid := c.clid
	c.mu.Unlock()
	if clid != 7 {
		t.Errorf("clid = %d, want 7", clid)
	}
	if got := initNickname(c); got != "TestBot" {
		t.Errorf("clientinit nickname = %q, want TestBot", got)
	}
}

func TestNickname_AdminRenameDoesNotStick(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 5
	c.mu.Unlock()

	c.handleCommandLines(c.handler,
		"notifyclientupdated clid=5 client_nickname=Renamed invokerid=9 invokername=admin invokeruid=x")

	if got := ownNickname(c); got != "Renamed" {
		t.Errorf("current nickname = %q, want Renamed", got)
	}
	if got := initNickname(c); got != "TestBot" {
		t.Errorf("clientinit nickname = %q, want the requested TestBot", got)
	}
}

func TestNickname_OwnAcceptedRenameIsWhatReconnectAsksFor(t *testing.T) {
	c := newTestClient(t)
	c.mu.Lock()
	c.clid = 5
	c.mu.Unlock()
	answerWith(c, "error id=0 msg=ok")

	err := c.UpdateClient(ctxWithin(t, time.Second), teamspeak.ClientUpdateOptions{Nickname: new("bob")})
	if err != nil {
		t.Fatal(err)
	}
	c.handleCommandLines(c.handler, "notifyclientupdated clid=5 client_nickname=bob")

	if got := ownNickname(c); got != "bob" {
		t.Errorf("current nickname = %q, want bob", got)
	}
	if got := initNickname(c); got != "bob" {
		t.Errorf("clientinit nickname = %q, want bob", got)
	}
}

func TestNickname_RefusedRenameChangesNothing(t *testing.T) {
	c := newTestClient(t)
	answerWith(c, "error id=513 msg=nickname\\sis\\sinuse")

	err := c.UpdateClient(ctxWithin(t, time.Second), teamspeak.ClientUpdateOptions{Nickname: new("bob")})
	if !errors.Is(err, teamspeak.ErrServer) {
		t.Fatalf("err = %v, want a server refusal", err)
	}
	if got := initNickname(c); got != "TestBot" {
		t.Errorf("clientinit nickname = %q, want TestBot", got)
	}
}

func TestUpdateClient_SendsTheNickname(t *testing.T) {
	sent := captureCommand(t, func(c *Client) error {
		return c.UpdateClient(t.Context(), teamspeak.ClientUpdateOptions{Nickname: new("bob")})
	})
	if cmd := wire.ParseCommand(sent); cmd.Params["client_nickname"] != "bob" {
		t.Errorf("clientupdate = %q, want client_nickname=bob", sent)
	}
}
