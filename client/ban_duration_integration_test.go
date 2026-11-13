//go:build integration

package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

func listBansForCleanup(ctx context.Context, t *testing.T, admin *serverquery.Client) []teamspeak.BanEntry {
	t.Helper()
	bans, err := admin.ListBans(ctx, teamspeak.BanListOptions{})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		t.Fatalf("ListBans: %v", err)
	}

	return bans
}

func deleteCreatedBans(
	ctx context.Context,
	admin *serverquery.Client,
	ids []teamspeak.BanID,
	before []teamspeak.BanEntry,
) error {
	seen := make(map[teamspeak.BanID]bool, len(before))
	for _, b := range before {
		seen[b.ID] = true
	}
	var firstErr error
	for _, id := range ids {
		err := admin.DeleteBan(ctx, id)
		if err != nil && !errors.Is(err, errcode.BanInvalidID) && firstErr == nil {
			firstErr = err
		}
	}
	bans, err := admin.ListBans(ctx, teamspeak.BanListOptions{})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		if firstErr == nil {
			firstErr = err
		}

		return firstErr
	}
	for _, b := range bans {
		if seen[b.ID] {
			continue
		}
		delErr := admin.DeleteBan(ctx, b.ID)
		if delErr != nil && !errors.Is(delErr, errcode.BanInvalidID) && firstErr == nil {
			firstErr = delErr
		}
	}

	return firstErr
}

func waitObserverKnows(t *testing.T, observer, victim *client.Client) {
	t.Helper()
	deadline := time.Now().Add(liveEventWait)
	for {
		if _, ok := observer.KnownClientForTest(victim.ClientID()); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("observer did not see victim (clid %d) within %s", victim.ClientID(), liveEventWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func assertConnectRefusedAsBanned(t *testing.T, addr, wantExtraPrefix string) {
	t.Helper()
	id, err := identity.Generate(t.Context(), 8)
	requireNoErr(t, err)
	probe := newClient(t, id, addr, uniqueName("ban-probe"), integrationClientOptions(nil)...)
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		_ = probe.Disconnect(ctx)
	})

	requireNoErr(t, paceConnect(t.Context()))
	attemptCtx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	err = probe.Connect(attemptCtx)
	cancel()

	if err == nil {
		t.Fatalf("probe Connect succeeded while banned, want 3329 (%q)", wantExtraPrefix)
	}
	if !errors.Is(err, errcode.ConnectFailedBanned) {
		t.Fatalf("probe Connect = %v, want errcode.ConnectFailedBanned (3329)", err)
	}
	serverErr, ok := errors.AsType[*teamspeak.ServerError](err)
	if !ok {
		t.Fatalf("probe Connect = %T, want *teamspeak.ServerError", err)
	}
	if !strings.HasPrefix(serverErr.ExtraMessage, wantExtraPrefix) {
		t.Errorf("ServerError.ExtraMessage = %q, want prefix %q", serverErr.ExtraMessage, wantExtraPrefix)
	}
}

func assertBanDurationPtr(t *testing.T, what string, got, want *time.Duration) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s BanDuration = %v, want nil", what, *got)
		}

		return
	}
	if got == nil {
		t.Errorf("%s BanDuration = nil, want %v", what, *want)

		return
	}
	if *got != *want {
		t.Errorf("%s BanDuration = %v, want %v", what, *got, *want)
	}
}

func assertVoiceKickDuration(t *testing.T, admin *serverquery.Client, observer *client.Client) {
	t.Helper()
	victim := liveClient(t, uniqueName("kick-v"))
	waitObserverKnows(t, observer, victim)

	vKicked := listen(t, victim.OnKicked)
	vDisc := listen(t, victim.OnDisconnected)
	obsLeave := listen(t, observer.OnClientLeave)

	requireNoErr(t, admin.KickClient(t.Context(), victim.ClientID(), teamspeak.ReasonKickServer,
		teamspeak.ClientKickOptions{ReasonMessage: "kick-test"}))

	kicked := await(t, vKicked, "victim OnKicked", func(e client.KickedEvent) bool {
		return e.Reason == teamspeak.ReasonKickServer
	})
	assertBanDurationPtr(t, "victim KickedEvent", kicked.BanDuration, nil)

	disc := await(t, vDisc, "victim OnDisconnected", func(client.DisconnectedEvent) bool { return true })
	removed, ok := errors.AsType[*client.RemovedError](disc.Err)
	if !ok || removed.Reason != teamspeak.ReasonKickServer {
		t.Fatalf("victim DisconnectedEvent.Err = %v, want *RemovedError for kick", disc.Err)
	}
	assertBanDurationPtr(t, "victim RemovedError", removed.BanDuration, nil)

	leave := await(t, obsLeave, "observer OnClientLeave", func(e client.ClientLeaveEvent) bool {
		return e.ClientID == victim.ClientID()
	})
	if leave.Reason != teamspeak.ReasonKickServer {
		t.Errorf("observer ClientLeaveEvent.Reason = %v, want ReasonKickServer", leave.Reason)
	}
	assertBanDurationPtr(t, "observer ClientLeaveEvent", leave.BanDuration, nil)
}

func assertVoiceBanDuration(
	t *testing.T,
	addr string,
	admin *serverquery.Client,
	observer *client.Client,
	duration time.Duration,
	wantPrefix string,
) {
	t.Helper()
	victim := liveClient(t, uniqueName("ban-v"))
	waitObserverKnows(t, observer, victim)

	vKicked := listen(t, victim.OnKicked)
	vDisc := listen(t, victim.OnDisconnected)
	obsLeave := listen(t, observer.OnClientLeave)

	before := listBansForCleanup(t.Context(), t, admin)
	var createdIDs []teamspeak.BanID
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		delErr := deleteCreatedBans(ctx, admin, createdIDs, before)
		if delErr != nil {
			t.Errorf("cleanup bans: %v", delErr)
		}
	})

	ids, err := admin.BanClient(t.Context(), victim.ClientID(), teamspeak.BanClientOptions{
		Duration: duration,
		Reason:   "ban-duration-it",
	})
	requireNoErr(t, err)
	createdIDs = ids

	wantDur := duration
	kicked := await(t, vKicked, "victim OnKicked", func(e client.KickedEvent) bool {
		return e.Reason == teamspeak.ReasonKickServerBan
	})
	assertBanDurationPtr(t, "victim KickedEvent", kicked.BanDuration, &wantDur)

	disc := await(t, vDisc, "victim OnDisconnected", func(client.DisconnectedEvent) bool { return true })
	removed, ok := errors.AsType[*client.RemovedError](disc.Err)
	if !ok || removed.Reason != teamspeak.ReasonKickServerBan {
		t.Fatalf("victim DisconnectedEvent.Err = %v, want *RemovedError for ban", disc.Err)
	}
	assertBanDurationPtr(t, "victim RemovedError", removed.BanDuration, &wantDur)

	leave := await(t, obsLeave, "observer OnClientLeave", func(e client.ClientLeaveEvent) bool {
		return e.ClientID == victim.ClientID()
	})
	if leave.Reason != teamspeak.ReasonKickServerBan {
		t.Errorf("observer ClientLeaveEvent.Reason = %v, want ReasonKickServerBan", leave.Reason)
	}
	assertBanDurationPtr(t, "observer ClientLeaveEvent", leave.BanDuration, &wantDur)

	assertConnectRefusedAsBanned(t, addr, wantPrefix)

	requireNoErr(t, deleteCreatedBans(t.Context(), admin, createdIDs, before))
}

func TestIntegration_BanDurationOnKickAndBans(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	admin := requireAdmin(t)
	observer := liveClient(t, uniqueName("ban-obs"))

	t.Run("kick has nil duration", func(t *testing.T) {
		assertVoiceKickDuration(t, admin, observer)
	})

	for name, tc := range map[string]struct {
		wantPrefix string
		duration   time.Duration
	}{
		"temporary ban": {duration: 5 * time.Second, wantPrefix: "You are banned temporarily"},
		"permanent ban": {duration: 0, wantPrefix: "You are banned permanently"},
	} {
		t.Run(name, func(t *testing.T) {
			assertVoiceBanDuration(t, addr, admin, observer, tc.duration, tc.wantPrefix)
		})
	}
}
