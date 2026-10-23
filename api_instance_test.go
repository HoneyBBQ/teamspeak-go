package teamspeak

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// Measured on TeamSpeak 3.13.8, with -uid.
func TestListServers(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"virtualserver_autostart": "1", "virtualserver_clientsonline": "0", "virtualserver_id": "2",
		"virtualserver_machine_id": "", "virtualserver_maxclients": "8", "virtualserver_name": "ctw new",
		"virtualserver_port": "9987", "virtualserver_queryclientsonline": "1", "virtualserver_status": "online",
		"virtualserver_unique_identifier": "6SM/NYHQYWb74oLekyndKNO415Q=", "virtualserver_uptime": "44",
	}}}}}
	got, err := NewCommands(s).ListServers(t.Context(), ServerListOptions{UID: true, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := "serverlist -uid -all"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := VirtualServer{
		ID: 2, Port: 9987, Status: "online", Name: "ctw new", UID: "6SM/NYHQYWb74oLekyndKNO415Q=",
		Uptime: 44 * time.Second, ClientsOnline: 0, QueryClientsOnline: 1, MaxClients: 8, Autostart: true,
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("servers = %+v, want %+v", got, want)
	}
}

// -short answers the id, port and status only, and TeamSpeak 6 adds fields
// VirtualServer has no home for.
func TestListServers_Short(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"virtualserver_id": "1", "virtualserver_port": "9987", "virtualserver_status": "offline"},
	}}}}
	got, err := NewCommands(s).ListServers(t.Context(), ServerListOptions{Short: true, OnlyOffline: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := "serverlist -short -onlyoffline"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if want := (VirtualServer{ID: 1, Port: 9987, Status: "offline"}); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("servers = %+v, want %+v", got, want)
	}

	// An instance with no server answers 1281.
	none := &script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}
	got, err = NewCommands(none).ListServers(t.Context(), ServerListOptions{})
	if err != nil || len(got) != 0 {
		t.Errorf("empty = %v, %v", got, err)
	}
}

func TestServerListLine(t *testing.T) {
	line := encoded(t, func(c *Commands) error {
		_, err := c.ListServers(t.Context(), ServerListOptions{})

		return err
	})
	if line != "serverlist" {
		t.Errorf("line = %q", line)
	}
}

// Measured on both servers: sid, the port, and the first administrator's key.
func TestCreateServer(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"sid": "2", "token": "KCij56c8enW+gBTU+oDT16HFWjEiouOctgj81OaC", "virtualserver_port": "9988",
	}}}}}
	got, err := NewCommands(s).CreateServer(t.Context(), "ctw new", Properties{
		"virtualserver_port": "9988", "virtualserver_maxclients": "8",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `servercreate virtualserver_name=ctw\snew virtualserver_maxclients=8 virtualserver_port=9988`
	if s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	if want := (ServerCreated{ID: 2, Port: 9988, Token: "KCij56c8enW+gBTU+oDT16HFWjEiouOctgj81OaC"}); got != want {
		t.Errorf("created = %+v, want %+v", got, want)
	}
}

func TestCreateServer_Refusals(t *testing.T) {
	refused(t, func(c *Commands) error {
		_, err := c.CreateServer(t.Context(), "a", Properties{"virtualserver_name": "b"})

		return err
	})
	_, err := NewCommands(&script{}).CreateServer(t.Context(), "a", nil)
	if !errors.Is(err, ErrNoData) {
		t.Errorf("an answer with no sid: err = %v, want ErrNoData", err)
	}
}

func TestServerLifecycleLines(t *testing.T) {
	for _, tc := range []struct {
		run  func(c *Commands) error
		want string
	}{
		{func(c *Commands) error { return c.StartServer(t.Context(), 2) }, "serverstart sid=2"},
		{func(c *Commands) error { return c.StopServer(t.Context(), 2, ServerStopOptions{}) }, "serverstop sid=2"},
		{
			func(c *Commands) error {
				return c.StopServer(t.Context(), 2, ServerStopOptions{ReasonMessage: "maintenance break"})
			},
			`serverstop sid=2 reasonmsg=maintenance\sbreak`,
		},
		{func(c *Commands) error { return c.DeleteServer(t.Context(), 2, ServerDeleteOptions{}) }, "serverdelete sid=2"},
		{
			func(c *Commands) error { return c.DeleteServer(t.Context(), 2, ServerDeleteOptions{NoEvent: true}) },
			"serverdelete -noevent sid=2",
		},
		{func(c *Commands) error { return c.StopInstance(t.Context(), InstanceStopOptions{}) }, "serverprocessstop"},
		{
			func(c *Commands) error {
				return c.StopInstance(t.Context(), InstanceStopOptions{ReasonMessage: "5 minute"})
			},
			`serverprocessstop reasonmsg=5\sminute`,
		},
		{func(c *Commands) error { return c.SendGlobalMessage(t.Context(), "Hello World!") }, `gm msg=Hello\sWorld!`},
	} {
		if got := encoded(t, tc.run); got != tc.want {
			t.Errorf("line = %q, want %q", got, tc.want)
		}
	}
}

// The data is the whole snapshot, and the salt only comes with a password.
func TestCreateServerSnapshot(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"data": "2lb++pw7J/YsheVYIIpGaqlHbCquusl0", "salt": "jsjcAwSFAXukc3X2FLnj1ofPqiyXBSACjHQ0x8X+9aQ=", "version": "3",
	}}}}}
	got, err := NewCommands(s).CreateServerSnapshot(t.Context(), SnapshotCreateOptions{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "serversnapshotcreate password=test"; s.sent[0] != want {
		t.Errorf("sent %q, want %q", s.sent[0], want)
	}
	want := ServerSnapshot{
		Version: 3, Data: "2lb++pw7J/YsheVYIIpGaqlHbCquusl0", Salt: "jsjcAwSFAXukc3X2FLnj1ofPqiyXBSACjHQ0x8X+9aQ=",
	}
	if got != want {
		t.Errorf("snapshot = %+v, want %+v", got, want)
	}

	plain := &script{replies: []reply{{rows: []map[string]string{{"data": "KLUv/WT1", "version": "3"}}}}}
	got, err = NewCommands(plain).CreateServerSnapshot(t.Context(), SnapshotCreateOptions{})
	if err != nil || plain.sent[0] != "serversnapshotcreate" || got.Salt != "" || got.Data != "KLUv/WT1" {
		t.Errorf("plain snapshot = %+v, %v, sent %q", got, err, plain.sent)
	}
}

func TestDeployServerSnapshot(t *testing.T) {
	snap := ServerSnapshot{Version: 3, Salt: "jsjc+9aQ=", Data: "2lb++pw7J/Yshe"}
	line := encoded(t, func(c *Commands) error {
		_, err := c.DeployServerSnapshot(t.Context(), snap, SnapshotDeployOptions{
			Password: "test", KeepFiles: true, Mapping: true,
		})

		return err
	})
	want := `serversnapshotdeploy -mapping -keepfiles password=test version=3 salt=jsjc+9aQ= data=2lb++pw7J\/Yshe`
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}

	line = encoded(t, func(c *Commands) error {
		_, err := c.DeployServerSnapshot(t.Context(), ServerSnapshot{Version: 3, Data: "KLUv"}, SnapshotDeployOptions{})

		return err
	})
	if line != "serversnapshotdeploy version=3 data=KLUv" {
		t.Errorf("line = %q", line)
	}

	refused(t, func(c *Commands) error {
		_, err := c.DeployServerSnapshot(t.Context(), ServerSnapshot{Version: 3}, SnapshotDeployOptions{})

		return err
	})
}

// With -mapping the server answers one ocid/ncid row per channel; without it,
// nothing.
func TestDeployServerSnapshot_ReadsTheMapping(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{
		{"ocid": "36", "ncid": "40"}, {"ocid": "37", "ncid": "41"},
	}}, {}}}
	snap := ServerSnapshot{Version: 3, Data: "KLUv"}
	got, err := NewCommands(s).DeployServerSnapshot(t.Context(), snap, SnapshotDeployOptions{Mapping: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []ChannelMapping{{Old: 36, New: 40}, {Old: 37, New: 41}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mapping = %+v, want %+v", got, want)
	}

	got, err = NewCommands(s).DeployServerSnapshot(t.Context(), snap, SnapshotDeployOptions{})
	if err != nil || got != nil {
		t.Errorf("without -mapping: %v, %v, want nil", got, err)
	}
}

// A settings key is a protocol identifier: one that would add a parameter or a
// command to the line is refused before anything is sent.
func TestSettingsKeysAreProtocolIdentifiers(t *testing.T) {
	for _, key := range []string{
		"virtualserver_name x=1", "a\nlogout", "a|b", "a=b", "", "a b", "-", "a\\sb", "näme", "a\rb",
	} {
		s := &script{}
		c := NewCommands(s)
		for name, err := range map[string]error{
			"EditServer":   c.EditServer(t.Context(), Properties{key: "v"}),
			"EditInstance": c.EditInstance(t.Context(), Properties{key: "v"}),
			"CreateServer": createServerErr(c, key),
		} {
			if !errors.Is(err, ErrInvalidCommand) {
				t.Errorf("%s with key %q: err = %v, want ErrInvalidCommand", name, key, err)
			}
		}
		if len(s.sent) != 0 {
			t.Errorf("key %q: sent %q, want nothing", key, s.sent)
		}
	}
	s := &script{}
	err := NewCommands(s).EditServer(t.Context(),
		Properties{"virtualserver_name": "x", "virtualserver_hostbanner_gfx_interval": "1"})
	if err != nil || len(s.sent) != 1 {
		t.Errorf("valid keys: err = %v, sent %q", err, s.sent)
	}
}

func createServerErr(c *Commands, key string) error {
	_, err := c.CreateServer(context.Background(), "n", Properties{key: "v"})

	return err
}
