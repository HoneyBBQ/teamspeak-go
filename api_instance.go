package teamspeak

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"
)

// Virtual servers and the instance that hosts them: listing, creating,
// starting, stopping and deleting servers, stopping the whole process, and
// server snapshots.
//
// These are instance commands, and almost none of them is reachable from a
// voice client: even a Server Admin is refused with 2568, "insufficient client
// permissions", for b_virtualserver_create, b_virtualserver_delete,
// b_serverinstance_textmessage_send and the snapshot permissions. They are for
// a ServerQuery connection, which is where the permissions live.
//
// An instance holds as many virtual servers as its license allows; the free
// one allows a single one, and servercreate past that is 2816, "virtualserver
// limit reached".

// VirtualServer is a virtual server as serverlist reports one.
type VirtualServer struct {
	// Name is the server's name (virtualserver_name); empty with
	// ServerListOptions.Short.
	Name string
	// Status is the server's state (virtualserver_status), such as "online",
	// "offline", "booting up", "shutting down" or "virtual online".
	Status string
	// UID is the server's unique identifier (virtualserver_unique_identifier);
	// empty unless ServerListOptions.UID.
	UID string
	// MachineID is the machine id of the instance the server belongs to
	// (virtualserver_machine_id), empty when the instance has none; empty with
	// ServerListOptions.Short.
	MachineID string
	// Uptime is how long the server has been running (virtualserver_uptime, in
	// seconds); 0 for a stopped server or with ServerListOptions.Short.
	Uptime time.Duration
	// ID is the server's id (virtualserver_id).
	ID ServerID
	// ClientsOnline is how many voice clients are connected
	// (virtualserver_clientsonline); 0 with ServerListOptions.Short.
	ClientsOnline int32
	// QueryClientsOnline is how many ServerQuery clients are connected
	// (virtualserver_queryclientsonline); 0 with ServerListOptions.Short.
	QueryClientsOnline int32
	// MaxClients is how many clients the server accepts
	// (virtualserver_maxclients); 0 with ServerListOptions.Short.
	MaxClients int32
	// Port is the server's voice port (virtualserver_port).
	Port uint16
	// Autostart reports a server that starts with the instance
	// (virtualserver_autostart); false with ServerListOptions.Short.
	Autostart bool
}

func parseVirtualServer(row map[string]string) VirtualServer {
	return VirtualServer{
		ID:                 ServerID(fieldUint(row, "virtualserver_id")),
		Port:               fieldUint16(row, "virtualserver_port"),
		Status:             fieldStr(row, "virtualserver_status"),
		Name:               fieldStr(row, "virtualserver_name"),
		UID:                fieldStr(row, "virtualserver_unique_identifier"),
		MachineID:          fieldStr(row, "virtualserver_machine_id"),
		Uptime:             fieldDuration(row, "virtualserver_uptime", time.Second),
		ClientsOnline:      fieldInt32(row, "virtualserver_clientsonline"),
		QueryClientsOnline: fieldInt32(row, "virtualserver_queryclientsonline"),
		MaxClients:         fieldInt32(row, "virtualserver_maxclients"),
		Autostart:          fieldBool(row, "virtualserver_autostart"),
	}
}

// ServerListOptions are ListServers' optional parameters.
type ServerListOptions struct {
	// UID adds each server's unique identifier (-uid).
	UID bool
	// Short leaves out the counts, the uptime, the name, the autostart flag and
	// the machine id, which cost the server a lookup each (-short).
	Short bool
	// All lists the servers of every instance sharing the database, whatever
	// their machine id (-all).
	All bool
	// OnlyOffline lists only the servers whose status is offline
	// (-onlyoffline).
	OnlyOffline bool
}

// ListServers returns the instance's virtual servers, none when it has none.
// It sends serverlist.
//
// Needs b_serverinstance_virtualserver_list. TeamSpeak 6 reports further
// fields, such as virtualserver_uuid, that VirtualServer has no field for. A
// voice client is answered too, with the one server it is on. Measured on
// TeamSpeak 3 and 6.
func (c *Commands) ListServers(ctx context.Context, opts ServerListOptions) ([]VirtualServer, error) {
	rows, err := c.list(ctx, "serverlist", []param{
		boolArg("-uid", opts.UID),
		boolArg("-short", opts.Short),
		boolArg("-all", opts.All),
		boolArg("-onlyoffline", opts.OnlyOffline),
	})
	if err != nil {
		return nil, err
	}

	out := make([]VirtualServer, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseVirtualServer(row))
	}

	return out, nil
}

// ServerCreated is a virtual server CreateServer just made.
//
// Token is a secret, shown once: redeeming it makes a client the server's
// administrator, and the server does not show it again, so keep it where it is
// needed and do not log it. String, GoString and LogValue leave it out, so the
// value can reach fmt and log/slog safely. encoding/json does not: the token is
// the caller's own data, which they may need to store, so json.Marshal
// includes it.
type ServerCreated struct {
	// Token is the privilege key of the new server's first administrator
	// (token): redeeming it with UsePrivilegeKey makes the client a Server
	// Admin.
	Token string
	// ID is the new server's id (sid).
	ID ServerID
	// Port is the voice port it listens on (virtualserver_port).
	Port uint16
}

// String describes the server without its token.
func (s ServerCreated) String() string {
	return fmt.Sprintf("{ID:%d Port:%d Token:redacted}", s.ID, s.Port)
}

// GoString is String, so %#v redacts too.
func (s ServerCreated) GoString() string { return s.String() }

// LogValue describes the server to log/slog without its token.
func (s ServerCreated) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("id", uint64(s.ID)),
		slog.Uint64("port", uint64(s.Port)),
		slog.String("token", "redacted"),
	)
}

// CreateServer makes a virtual server named name, starts it, and returns its
// id, port and first administrator's privilege key. It sends servercreate.
//
// settings are further virtualserver_* properties, passed through as given as
// EditServer does — virtualserver_port, virtualserver_maxclients,
// virtualserver_password and so on; nil sends none. Without a
// virtualserver_port the server takes the first unused one. The name is not
// also a setting: a settings map that holds virtualserver_name is refused with
// ErrInvalidCommand.
//
// Needs b_virtualserver_create. A server with no license runs one virtual
// server, and a second is refused with 2816, "virtualserver limit reached",
// while the first is running: StopServer it first. Both TeamSpeak 3 and 6 serve
// it over ServerQuery.
func (c *Commands) CreateServer(ctx context.Context, name string, settings Properties) (ServerCreated, error) {
	params := []param{strArg("virtualserver_name", name)}
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		if key == "virtualserver_name" {
			params = append(params, invalidArg("virtualserver_name is the name argument, not a setting"))

			continue
		}
		params = append(params, strArg(key, settings[key]))
	}

	row, err := c.queryRow(ctx, "servercreate", "sid", params)
	if err != nil {
		return ServerCreated{}, err
	}

	return ServerCreated{
		ID:    ServerID(fieldUint(row, "sid")),
		Port:  fieldUint16(row, "virtualserver_port"),
		Token: fieldStr(row, "token"),
	}, nil
}

// StartServer starts a stopped virtual server. It sends serverstart.
//
// Needs b_virtualserver_start_any, or b_virtualserver_start for the server the
// connection's own client administers. Starting a server that is already
// running is refused with 2816, "virtualserver limit reached", on a license of
// one server: the server counts it a second time. An id that names no server
// is refused the same way. Both TeamSpeak 3 and 6 serve it over ServerQuery.
func (c *Commands) StartServer(ctx context.Context, id ServerID) error {
	return c.exec(ctx, "serverstart", []param{idArg("sid", id)})
}

// ServerStopOptions are StopServer's optional parameters.
type ServerStopOptions struct {
	// ReasonMessage is the text the connected clients are sent before they are
	// disconnected (reasonmsg); "" sends none.
	ReasonMessage string
}

// StopServer stops a running virtual server, disconnecting its clients. It
// sends serverstop.
//
// Needs b_virtualserver_stop_any, or b_virtualserver_stop for the server the
// connection's own client administers. A server that is not running is 1033,
// "server is not running". A ServerQuery connection that had selected the
// server loses it. Both TeamSpeak 3 and 6 serve it over ServerQuery.
func (c *Commands) StopServer(ctx context.Context, id ServerID, opts ServerStopOptions) error {
	return c.exec(ctx, "serverstop", []param{
		idArg("sid", id),
		optStrArg("reasonmsg", opts.ReasonMessage),
	})
}

// ServerDeleteOptions are DeleteServer's optional parameters.
type ServerDeleteOptions struct {
	// NoEvent leaves out the event that tells the other connections the server
	// is gone (-noevent). TeamSpeak 6 has it; TeamSpeak 3 takes the flag too.
	NoEvent bool
}

// DeleteServer deletes a stopped virtual server, with everything in it:
// channels, groups, client records, files. It sends serverdelete.
//
// Destructive and not undoable. Needs b_virtualserver_delete. A server that is
// still running is refused with 1035, "server got an invalid status for this
// operation": StopServer it first. So is a stopped one that a ServerQuery
// client has selected virtually, with `use -virtual`, which lists as "online
// virtual" until that client selects another server or leaves; stopping a
// server drops the ordinary selections of the clients on it. A server that does
// not exist is 1024, "invalid serverID". Both TeamSpeak 3 and 6 serve it over
// ServerQuery.
func (c *Commands) DeleteServer(ctx context.Context, id ServerID, opts ServerDeleteOptions) error {
	return c.exec(ctx, "serverdelete", []param{
		boolArg("-noevent", opts.NoEvent),
		idArg("sid", id),
	})
}

// InstanceStopOptions are StopInstance's optional parameters.
type InstanceStopOptions struct {
	// ReasonMessage is the text the connected clients are sent before they are
	// disconnected (reasonmsg); "" sends none.
	ReasonMessage string
}

// StopInstance shuts the whole server process down, every virtual server in it
// with it. It sends serverprocessstop.
//
// Destructive: nothing answers afterwards, and starting the process again is
// not something this connection can do. Needs b_serverinstance_stop. A
// ServerQuery connection is dropped as the process exits, so its next command
// fails with a connection error; the answer to this one may be that error
// rather than success. Both TeamSpeak 3 and 6 serve it over ServerQuery.
func (c *Commands) StopInstance(ctx context.Context, opts InstanceStopOptions) error {
	return c.exec(ctx, "serverprocessstop", []param{optStrArg("reasonmsg", opts.ReasonMessage)})
}

// SendGlobalMessage sends a text message to every client on every virtual
// server of the instance. It sends gm.
//
// Needs b_serverinstance_textmessage_send, which a voice Server Admin lacks:
// error 2568. Both TeamSpeak 3 and 6 serve it over ServerQuery.
func (c *Commands) SendGlobalMessage(ctx context.Context, message string) error {
	return c.exec(ctx, "gm", []param{strArg("msg", message)})
}

// ---- Snapshots --------------------------------------------------------------

// ServerSnapshot is a virtual server's settings, groups, permissions and known
// client identities, as serversnapshotcreate reports them and
// serversnapshotdeploy takes them back.
//
// The data holds every client's identity and the server's permissions, so
// String, GoString and LogValue show none of it. encoding/json does not
// redact: the snapshot is the caller's own data, to store, so json.Marshal
// includes all of it.
type ServerSnapshot struct {
	// Salt is the salt the data was encrypted with (salt); "" for a snapshot
	// made without a password.
	Salt string
	// Data is the snapshot itself (data), compressed, and encrypted when a
	// password was given.
	Data string
	// Version is the snapshot format's version (version); the servers measured
	// write 3.
	Version uint32
}

// String describes the snapshot without its data.
func (s ServerSnapshot) String() string {
	return fmt.Sprintf("{Version:%d Salted:%t Data:redacted(%d bytes)}", s.Version, s.Salt != "", len(s.Data))
}

// GoString is String, so %#v redacts too.
func (s ServerSnapshot) GoString() string { return s.String() }

// LogValue describes the snapshot to log/slog without its data.
func (s ServerSnapshot) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("version", uint64(s.Version)),
		slog.Bool("salted", s.Salt != ""),
		slog.Int("data_bytes", len(s.Data)),
		slog.String("data", "redacted"),
	)
}

// SnapshotCreateOptions are CreateServerSnapshot's optional parameters.
type SnapshotCreateOptions struct {
	// Password encrypts the snapshot's data (password), and DeployServerSnapshot
	// needs it to read it back; "" makes an unencrypted snapshot. It is sent as
	// it is, on both servers and over every transport.
	Password string
}

// CreateServerSnapshot returns a snapshot of the selected virtual server. It
// sends serversnapshotcreate.
//
// Needs b_virtualserver_snapshot_create, which a voice Server Admin lacks:
// error 2568. Both TeamSpeak 3 and 6 serve it over ServerQuery. The server
// writes the snapshot as one line, which the connection must read whole: a
// snapshot of a busy server is large.
func (c *Commands) CreateServerSnapshot(ctx context.Context, opts SnapshotCreateOptions) (ServerSnapshot, error) {
	row, err := c.queryRow(ctx, "serversnapshotcreate", "data", []param{optStrArg("password", opts.Password)})
	if err != nil {
		return ServerSnapshot{}, err
	}

	return ServerSnapshot{
		Version: fieldUint32(row, "version"),
		Salt:    fieldStr(row, "salt"),
		Data:    fieldStr(row, "data"),
	}, nil
}

// SnapshotDeployOptions are DeployServerSnapshot's optional parameters.
type SnapshotDeployOptions struct {
	// Password decrypts the snapshot's data (password); it must be the one the
	// snapshot was made with. "" for an unencrypted snapshot.
	Password string
	// KeepFiles keeps the files of the channels that exist both on the server
	// and in the snapshot, rather than discarding them (-keepfiles).
	KeepFiles bool
	// Mapping asks for which channel each of the snapshot's channels became
	// (-mapping), returned as the deploy's result.
	Mapping bool
}

// ChannelMapping says which channel a snapshot's channel became when the
// snapshot was deployed.
type ChannelMapping struct {
	// Old is the channel's id in the snapshot (ocid).
	Old ChannelID
	// New is the channel's id on the server now (ncid).
	New ChannelID
}

// DeployServerSnapshot restores the selected virtual server from a snapshot,
// replacing its settings, channels, groups and permissions. It sends
// serversnapshotdeploy, and returns the channel mapping when opts asks for it,
// nil otherwise.
//
// Destructive: what the server holds that the snapshot does not is gone, and
// the server does not check the permissions of what it restores, so a snapshot
// can grant rights the connection lacks. Needs b_virtualserver_snapshot_deploy.
// A wrong password for an encrypted snapshot is refused with 1538, "invalid
// parameter", and changes nothing. The snapshot must have a Data: an empty one
// is refused with ErrInvalidCommand.
//
// The server drops the selection of the ServerQuery connection that deployed
// it, over raw TCP and SSH: the next command answers 1024, "invalid serverID",
// until the connection selects the server again, with serverquery's Use.
// WebQuery has no session to drop, and carries on.
func (c *Commands) DeployServerSnapshot(
	ctx context.Context, snapshot ServerSnapshot, opts SnapshotDeployOptions,
) ([]ChannelMapping, error) {
	data := optStrArg("data", snapshot.Data)
	if snapshot.Data == "" {
		data = invalidArg("a snapshot to deploy needs its data")
	}

	rows, err := c.list(ctx, "serversnapshotdeploy", []param{
		boolArg("-mapping", opts.Mapping),
		boolArg("-keepfiles", opts.KeepFiles),
		optStrArg("password", opts.Password),
		uintArg("version", uint64(snapshot.Version)),
		optStrArg("salt", snapshot.Salt),
		data,
	})
	if err != nil {
		return nil, err
	}

	var out []ChannelMapping
	for _, row := range rows {
		if row["ocid"] == "" && row["ncid"] == "" {
			continue
		}
		out = append(out, ChannelMapping{
			Old: ChannelID(fieldUint(row, "ocid")),
			New: ChannelID(fieldUint(row, "ncid")),
		})
	}

	return out, nil
}
