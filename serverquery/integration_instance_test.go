//go:build integration

package serverquery_test

// Integration tests for the instance commands that cannot be undone: stopping
// and deleting virtual servers, restoring a snapshot over one, and stopping
// the process. They run against a throwaway server only, so each is off until
// the environment says it may be:
//
//	TEAMSPEAK_QUERY_DESTRUCTIVE=1       the lifecycle and the snapshot round trip
//	TEAMSPEAK_QUERY_STOP_INSTANCE=1     StopInstance, which ends the server
//	                                    process and every test after it; run it
//	                                    alone, with -run TestInstanceStop
//
// A server's license limits how many virtual servers run at once, and the
// free one allows a single one, so the lifecycle stops the server the fixture
// provisioned to make room for a second, and starts it again at the end.

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// allowDestructive skips a test unless the environment has switched on name,
// and says which switch it wants.
func allowDestructive(t *testing.T, name string) {
	t.Helper()
	if os.Getenv(name) != "1" {
		t.Skipf("%s is not 1: this test stops or deletes virtual servers, so it runs against a throwaway server only", name)
	}
}

// serverStatus reads the status of one server from the instance's list.
func serverStatus(ctx context.Context, t *testing.T, c *serverquery.Client, id teamspeak.ServerID) string {
	t.Helper()
	servers, err := c.ListServers(ctx, teamspeak.ServerListOptions{Short: true})
	if err != nil && !errors.Is(err, errcode.DatabaseEmptyResult) {
		t.Fatalf("ListServers: %v", err)
	}
	i := slices.IndexFunc(servers, func(s teamspeak.VirtualServer) bool { return s.ID == id })
	if i < 0 {
		return "absent"
	}

	return servers[i].Status
}

// A second virtual server is created, stopped, started and deleted, beside the
// one the fixture provisioned.
func TestInstanceLifecycle_SecondServer(t *testing.T) {
	allowDestructive(t, "TEAMSPEAK_QUERY_DESTRUCTIVE")
	forEachTransport(t, 0, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, _ string) {
		ctx := adminCtx(t)
		servers, err := c.ListServers(ctx, teamspeak.ServerListOptions{Short: true})
		if err != nil || len(servers) == 0 {
			t.Fatalf("ListServers = %+v, %v", servers, err)
		}
		base := servers[0]
		cleanup(t, "the first server's status", func(ctx context.Context) error {
			if serverStatus(ctx, t, c, base.ID) == "online" {
				return nil
			}

			return c.StartServer(ctx, base.ID)
		})

		// Room first: a license of one server counts the running ones.
		err = c.StopServer(ctx, base.ID, teamspeak.ServerStopOptions{ReasonMessage: "making room for the lifecycle test"})
		if err != nil {
			t.Fatalf("StopServer %d: %v", base.ID, err)
		}
		if got := serverStatus(ctx, t, c, base.ID); got != "offline" {
			t.Errorf("server %d is %q after StopServer, want offline", base.ID, got)
		}
		if code := serverCode(c.StopServer(ctx, base.ID, teamspeak.ServerStopOptions{})); code != 1033 {
			t.Errorf("stopping a stopped server: code %d, want 1033", code)
		}

		created := createSecondServer(t, c, base)
		assertDeleteNeedsAStoppedServer(ctx, t, c, created.ID)

		err = c.StartServer(ctx, base.ID)
		if err != nil {
			t.Fatalf("StartServer %d: %v", base.ID, err)
		}
		if got := serverStatus(ctx, t, c, base.ID); got != "online" {
			t.Errorf("server %d is %q after StartServer, want online", base.ID, got)
		}

		err = c.DeleteServer(ctx, created.ID, teamspeak.ServerDeleteOptions{NoEvent: true})
		if err != nil {
			t.Fatalf("DeleteServer %d: %v", created.ID, err)
		}
		if got := serverStatus(ctx, t, c, created.ID); got != "absent" {
			t.Errorf("the deleted server is %q, want absent", got)
		}
		if code := serverCode(c.DeleteServer(ctx, created.ID, teamspeak.ServerDeleteOptions{})); code != 1024 {
			t.Errorf("deleting a deleted server: code %d, want 1024", code)
		}
	})
}

// createSecondServer makes the server beside base, one port up, and removes it
// at the end of the test if the test has not.
func createSecondServer(t *testing.T, c *serverquery.Client, base teamspeak.VirtualServer) teamspeak.ServerCreated {
	t.Helper()
	ctx := adminCtx(t)
	created, err := c.CreateServer(ctx, "ts-go lifecycle test", teamspeak.Properties{
		"virtualserver_port": strconv.Itoa(int(base.Port) + 1), "virtualserver_maxclients": "4",
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	cleanup(t, "the second server", func(ctx context.Context) error {
		if serverStatus(ctx, t, c, created.ID) == "absent" {
			return nil
		}
		_ = c.StopServer(ctx, created.ID, teamspeak.ServerStopOptions{})

		return c.DeleteServer(ctx, created.ID, teamspeak.ServerDeleteOptions{})
	})
	if created.ID == 0 || created.ID == base.ID || created.Port != base.Port+1 || created.Token == "" {
		t.Errorf("the new server = %v, want a new id on port %d with a token", created, base.Port+1)
	}
	if got := serverStatus(ctx, t, c, created.ID); got != "online" {
		t.Errorf("the new server is %q, want online", got)
	}

	return created
}

// assertDeleteNeedsAStoppedServer deletes a running server, which the server
// refuses, then stops it and finds it in the offline list.
func assertDeleteNeedsAStoppedServer(ctx context.Context, t *testing.T, c *serverquery.Client, id teamspeak.ServerID) {
	t.Helper()
	if code := serverCode(c.DeleteServer(ctx, id, teamspeak.ServerDeleteOptions{})); code != 1035 {
		t.Errorf("deleting a running server: code %d, want 1035", code)
	}
	err := c.StopServer(ctx, id, teamspeak.ServerStopOptions{})
	if err != nil {
		t.Fatalf("StopServer %d: %v", id, err)
	}
	offline, err := c.ListServers(ctx, teamspeak.ServerListOptions{OnlyOffline: true, Short: true})
	if err != nil || !slices.ContainsFunc(offline, func(s teamspeak.VirtualServer) bool { return s.ID == id }) {
		t.Errorf("the offline list = %+v, %v, want the stopped server in it", offline, err)
	}
}

// A snapshot of a server is restored over it: a channel made after the
// snapshot is gone again, one deleted after it is back, and the mapping says
// which channel each one became.
func TestInstanceSnapshot_RoundTrip(t *testing.T) {
	allowDestructive(t, "TEAMSPEAK_QUERY_DESTRUCTIVE")
	forEachTransport(t, 1, func(t *testing.T, c *serverquery.Client, _ teamspeak.ServerFamily, transport string) {
		ctx := adminCtx(t)
		stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
		kept := "ts-go-snap-kept-" + stamp
		extra := "ts-go-snap-extra-" + stamp

		keptID, err := c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: kept, IsPermanent: new(true)})
		if err != nil {
			t.Fatalf("CreateChannel: %v", err)
		}
		cleanup(t, "the snapshot's channels", func(ctx context.Context) error {
			return deleteChannelsNamed(ctx, c, kept, extra)
		})

		snapshot, err := c.CreateServerSnapshot(ctx, teamspeak.SnapshotCreateOptions{Password: "ts-go-it"})
		skipUnlessAllowed(t, err, "CreateServerSnapshot")
		if err != nil {
			t.Fatalf("CreateServerSnapshot: %v", err)
		}

		// After the snapshot: one channel more, one less.
		_, err = c.CreateChannel(ctx, teamspeak.ChannelCreateOptions{Name: extra, IsPermanent: new(true)})
		if err != nil {
			t.Fatalf("CreateChannel: %v", err)
		}
		err = c.DeleteChannel(ctx, keptID, teamspeak.ChannelDeleteOptions{Force: true})
		if err != nil {
			t.Fatalf("DeleteChannel: %v", err)
		}

		assertWrongPasswordChangesNothing(ctx, t, c, snapshot, kept, extra)

		mapping, err := c.DeployServerSnapshot(ctx, snapshot, teamspeak.SnapshotDeployOptions{
			Password: "ts-go-it", Mapping: true, KeepFiles: true,
		})
		if err != nil {
			t.Fatalf("DeployServerSnapshot: %v", err)
		}
		t.Logf("the mapping: %+v", mapping)
		// The deploy drops this connection's selection of the server, where the
		// connection has a session to hold one: WebQuery does not.
		_, err = c.ListChannels(ctx, teamspeak.ChannelListOptions{})
		if code := serverCode(err); transport != "web" && code != 1024 {
			t.Errorf("a command right after the deploy: %v, want 1024", err)
		}
		err = c.Use(ctx, serverquery.ByID(1), serverquery.UseOptions{})
		if err != nil {
			t.Fatalf("Use after the deploy: %v", err)
		}
		names := channelNames(ctx, t, c)
		if names[extra] || !names[kept] {
			t.Errorf("after the deploy the channels are %v, want %q back and %q gone", names, kept, extra)
		}
		if len(mapping) == 0 {
			t.Error("the deploy returned no channel mapping though -mapping was asked for")
		}
		for _, m := range mapping {
			if m.Old == 0 || m.New == 0 {
				t.Errorf("a mapping with a zero id: %+v", m)
			}
		}
	})
}

// assertWrongPasswordChangesNothing deploys the snapshot under a password that
// is not its own, which the server refuses without touching the channels.
func assertWrongPasswordChangesNothing(
	ctx context.Context, t *testing.T, c *serverquery.Client, snapshot teamspeak.ServerSnapshot, kept, extra string,
) {
	t.Helper()
	_, err := c.DeployServerSnapshot(ctx, snapshot, teamspeak.SnapshotDeployOptions{Password: "wrong"})
	if err == nil {
		t.Fatal("a snapshot deployed with the wrong password")
	}
	t.Logf("the wrong password: %v", err)
	names := channelNames(ctx, t, c)
	if !names[extra] || names[kept] {
		t.Fatalf("a refused deploy changed the channels: %v", names)
	}
}

func channelNames(ctx context.Context, t *testing.T, c *serverquery.Client) map[string]bool {
	t.Helper()
	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	names := make(map[string]bool, len(channels))
	for _, ch := range channels {
		names[ch.Name] = true
	}

	return names
}

func deleteChannelsNamed(ctx context.Context, c *serverquery.Client, names ...string) error {
	channels, err := c.ListChannels(ctx, teamspeak.ChannelListOptions{})
	if err != nil {
		return err
	}
	for _, ch := range channels {
		if slices.Contains(names, ch.Name) {
			err = c.DeleteChannel(ctx, ch.ID, teamspeak.ChannelDeleteOptions{Force: true})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// firstDialer is the first query transport the environment provides, raw TCP
// before SSH before WebQuery: the process stops once, so one is enough.
func firstDialer(t *testing.T) (serverquery.Dialer, []serverquery.Option, string) {
	t.Helper()
	switch {
	case os.Getenv(envHost) != "":
		d, opts, _ := tcpDialer(t)

		return d, opts, "tcp"
	case os.Getenv(envSSHHost) != "":
		d, opts, _ := sshDialer(t)

		return d, opts, "ssh"
	default:
		d, opts, _ := webDialer(t)

		return d, opts, "web"
	}
}

// The process stops, and the connection that asked for it finds out. Last in
// the file because nothing answers afterwards; run it alone.
func TestInstanceStop_EndsTheProcess(t *testing.T) {
	allowDestructive(t, "TEAMSPEAK_QUERY_STOP_INSTANCE")
	d, opts, transport := firstDialer(t)
	waitForOtherSuites()
	c, err := serverquery.New(d, append(opts, serverquery.WithoutEvents())...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := adminCtx(t)
	err = c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	err = c.StopInstance(ctx, teamspeak.InstanceStopOptions{ReasonMessage: "ts-go integration test"})
	t.Logf("StopInstance over %s answered: %v", transport, err)

	// The process is going: a connection with a session ends, and a new one is
	// refused.
	if transport != "web" {
		deadline := time.Now().Add(20 * time.Second)
		for c.Status() == teamspeak.StatusConnected && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
		}
		if got := c.Status(); got == teamspeak.StatusConnected {
			t.Errorf("Status = %v after StopInstance, want the connection ended", got)
		}
	}
	time.Sleep(2 * time.Second)
	// The same dialer, built before the process went: an SSH one reads the
	// host key from the running server.
	again, err := serverquery.New(d, append(opts, serverquery.WithoutEvents())...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = again.Connect(connectCtx)
	if err == nil {
		_ = again.Disconnect(context.Background())
		t.Error("a new connection was accepted after StopInstance")
	}
}
