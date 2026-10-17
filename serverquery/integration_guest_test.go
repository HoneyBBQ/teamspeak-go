//go:build integration

package serverquery_test

// Guest ServerQuery access against a live TeamSpeak 6 (beta13 or later) with
// guest access on, which is the server's default. The fixture's endpoints are
// reused, and TEAMSPEAK_QUERY_GUEST=1 says the server has guest access: a
// TeamSpeak 3 server has none, so the tests skip without it rather than fail.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/livetest"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// envGuest says the server under test serves guest ServerQuery access.
const envGuest = "TEAMSPEAK_QUERY_GUEST"

// The codes a guest is refused with that the typed errcode table has no name
// for: WebQuery's "out of scope".
const codeOutOfScope = 5120

func guestEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv(envGuest) != "1" {
		t.Skipf("%s is not 1 - skipping the guest ServerQuery test (TeamSpeak 6 beta13+ only)", envGuest)
	}
}

func guestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	return ctx
}

func TestQueryGuest_OverSSH(t *testing.T) {
	guestEnabled(t)
	addr, _, _ := sshVars(t)
	waitForOtherSuites()

	// The host key is verified exactly as for an account login.
	check, err := serverquery.KnownHosts(livetest.KnownHostsFor(t, addr))
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	c, err := serverquery.New(serverquery.SSHGuestWith(addr, serverquery.SSHOptions{HostKeyCheck: check}),
		serverquery.WithServer(1), serverquery.WithoutEvents())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)
	ctx := guestCtx(t)

	version, err := c.GetVersion(ctx)
	if err != nil || version.Version == "" {
		t.Fatalf("GetVersion as a guest = %+v, %v", version, err)
	}
	who, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI as a guest: %v", err)
	}
	if who.ClientID == 0 {
		t.Errorf("WhoAmI described no connection: %+v", who)
	}

	// Administration is refused for lack of permission. The instance's own
	// settings are used: what a guest may read of one virtual server is the
	// Guest ServerQuery group's to grant, and the fixture's administrator may
	// have widened it.
	_, err = c.GetInstanceInfo(ctx)
	if !errors.Is(err, errcode.PermissionsClientInsufficient) {
		t.Errorf("instanceinfo as a guest = %v, want insufficient client permissions (2568)", err)
	}
}

func TestQueryGuest_OverWebQuery(t *testing.T) {
	guestEnabled(t)
	base, _ := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.WebGuest(base), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	open(t, c)
	ctx := guestCtx(t)

	version, err := c.GetVersion(ctx)
	if err != nil || version.Version == "" {
		t.Fatalf("GetVersion as a guest = %+v, %v", version, err)
	}
	_, err = c.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI as a guest: %v", err)
	}

	// Outside the guest scope: the server refuses the command itself.
	_, err = c.GetServerInfo(ctx)
	if got := serverCode(err); got != codeOutOfScope {
		t.Errorf("serverinfo as a guest = %v, want code %d (out of scope)", err, codeOutOfScope)
	}
	_, err = c.ListAPIKeys(ctx, teamspeak.APIKeyListOptions{})
	if got := serverCode(err); got != codeOutOfScope {
		t.Errorf("apikeylist as a guest = %v, want code %d (out of scope)", err, codeOutOfScope)
	}
}

// A wrong key is not a guest: the server refuses it, so a mistyped key never
// downgrades quietly.
func TestQueryGuest_WrongAPIKeyIsNotAGuest(t *testing.T) {
	guestEnabled(t)
	base, _ := webVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.Web(base, "not-a-key"), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(guestCtx(t))
	if err == nil {
		_ = c.Disconnect(guestCtx(t))
		t.Fatal("a wrong api key connected")
	}
}
