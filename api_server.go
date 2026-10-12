package teamspeak

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Server and instance commands.
//
// "Server" here means the virtual server a client is connected to; "instance"
// means the process hosting it. The distinction matters because the setting
// names differ (virtualserver_* versus serverinstance_*) and the two are easy
// to mix up.

// ServerGroup is a server group as servergrouplist reports it.
type ServerGroup struct {
	Name              string
	ID                ServerGroupID
	IconID            IconID
	SortID            int32
	Type              GroupType
	NameMode          GroupNameMode
	ModifyPower       int32
	MemberAddPower    int32
	MemberRemovePower int32
	SavedInDatabase   bool
}

func parseServerGroup(row map[string]string) ServerGroup {
	return ServerGroup{
		ID:                ServerGroupID(fieldUint(row, "sgid")),
		Name:              fieldStr(row, "name"),
		Type:              GroupType(fieldInt(row, "type")),
		IconID:            fieldIconID(row, "iconid"),
		SavedInDatabase:   fieldBool(row, "savedb"),
		SortID:            fieldInt32(row, "sortid"),
		NameMode:          GroupNameMode(fieldInt(row, "namemode")),
		ModifyPower:       fieldInt32(row, "n_modifyp"),
		MemberAddPower:    fieldInt32(row, "n_member_addp"),
		MemberRemovePower: fieldInt32(row, "n_member_removep"),
	}
}

// ListServerGroups returns every server group.
func (c *Commands) ListServerGroups(ctx context.Context) ([]ServerGroup, error) {
	rows, err := c.query(ctx, "servergrouplist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseServerGroup(row))
	}

	return out, nil
}

// GetServerInfo returns the server's own settings, unfiltered.
//
// Properties rather than a struct: serverinfo carries well over a hundred
// fields and which appear depends on permissions, so anything narrower would
// drop data.
func (c *Commands) GetServerInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "serverinfo")
}

// EditServer changes the virtual server's settings.
//
// Settings are passed through as given — virtualserver_name, virtualserver_
// maxclients and so on — rather than enumerated: there are well over a hundred,
// they are version-dependent, and a value read out of GetServerInfo should be
// writable straight back.
func (c *Commands) EditServer(ctx context.Context, settings Properties) error {
	return c.exec(ctx, "serveredit", stringParams(settings))
}

// GetHostInfo returns the host process's settings.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetHostInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "hostinfo")
}

// GetInstanceInfo returns the server instance's settings.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetInstanceInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "instanceinfo")
}

// EditInstance changes the server instance's settings.
func (c *Commands) EditInstance(ctx context.Context, settings Properties) error {
	return c.exec(ctx, "instanceedit", stringParams(settings))
}

// firstRow runs a command and returns its single row, or empty Properties.
func (c *Commands) firstRow(ctx context.Context, command string) (Properties, error) {
	rows, err := c.query(ctx, command, nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return Properties{}, nil
	}

	return rows[0], nil
}

// stringParams turns a settings map into params.
//
// Map iteration order is not stable, but serveredit parameters are named on the
// wire, so order does not matter here.
func stringParams(settings Properties) []param {
	out := make([]param, 0, len(settings))
	for key, value := range settings {
		out = append(out, strArg(key, value))
	}

	return out
}

// Binding is one active IP binding.
type Binding struct {
	Subsystem string
	IP        string
	Port      uint16
}

// BindingListOptions are ListBindings' optional parameters.
type BindingListOptions struct {
	// Subsystem is "voice", "query" or "filetransfer"; "" is the server's
	// default.
	Subsystem string
}

// ListBindings returns the instance's active IP bindings, when it is
// multi-homed.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) ListBindings(ctx context.Context, opts BindingListOptions) ([]Binding, error) {
	rows, err := c.query(ctx, "bindinglist", []param{optStrArg("subsystem", opts.Subsystem)})
	if err != nil {
		return nil, err
	}

	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		out = append(out, Binding{
			Subsystem: fieldStr(row, "subsystem"),
			IP:        fieldStr(row, "ip"),
			Port:      fieldUint16(row, "port"),
		})
	}

	return out, nil
}

// BuildVersion is the server's build information.
type BuildVersion struct {
	Version  string
	Platform string
	Build    uint64
}

// GetVersion returns the server's build version.
func (c *Commands) GetVersion(ctx context.Context) (BuildVersion, error) {
	rows, err := c.query(ctx, "version", nil)
	if err != nil {
		return BuildVersion{}, err
	}

	if len(rows) == 0 {
		return BuildVersion{}, ErrNoData
	}

	row := rows[0]

	return BuildVersion{
		Version:  fieldStr(row, "version"),
		Build:    fieldUint(row, "build"),
		Platform: fieldStr(row, "platform"),
	}, nil
}

// WhoAmI is which server and client a connection is, as the server sees it.
type WhoAmI struct {
	// ServerStatus is the virtual server's state, such as "online"
	// (virtualserver_status).
	ServerStatus string
	// ServerUID is the virtual server's unique identifier
	// (virtualserver_unique_identifier).
	ServerUID string
	// Nickname is this connection's nickname (client_nickname).
	Nickname string
	// LoginName is the ServerQuery login name, "" for a voice client
	// (client_login_name).
	LoginName string
	// UID is this connection's unique identifier (client_unique_identifier).
	// The voice protocol sends it empty; the voice client's UID method has it.
	UID UID
	// ServerID is the virtual server's id, 0 when none is selected
	// (virtualserver_id).
	ServerID ServerID
	// ChannelID is the channel this connection is in (client_channel_id).
	ChannelID ChannelID
	// DatabaseID is this connection's database id (client_database_id).
	DatabaseID ClientDBID
	// ServerPort is the virtual server's voice port (virtualserver_port).
	ServerPort uint16
	// ClientID is this connection's client id (client_id).
	ClientID ClientID
}

// WhoAmI returns which server and client this connection is, as the server sees
// it.
func (c *Commands) WhoAmI(ctx context.Context) (WhoAmI, error) {
	row, err := c.firstRow(ctx, "whoami")
	if err != nil {
		return WhoAmI{}, err
	}

	return WhoAmI{
		ServerStatus: fieldStr(row, "virtualserver_status"),
		ServerID:     ServerID(fieldUint(row, "virtualserver_id")),
		ServerUID:    fieldStr(row, "virtualserver_unique_identifier"),
		ServerPort:   fieldUint16(row, "virtualserver_port"),
		ClientID:     ClientID(fieldUint16(row, "client_id")),
		ChannelID:    ChannelID(fieldUint(row, "client_channel_id")),
		Nickname:     fieldStr(row, "client_nickname"),
		DatabaseID:   ClientDBID(fieldUint(row, "client_database_id")),
		LoginName:    fieldStr(row, "client_login_name"),
		UID:          UID(fieldStr(row, "client_unique_identifier")),
	}, nil
}

// ServerConnectionInfo is the virtual server's traffic statistics, as
// serverrequestconnectioninfo reports them. Rates are in bytes per second.
type ServerConnectionInfo struct {
	// FileTransferBandwidthSent and FileTransferBandwidthReceived are the
	// file transfer bandwidth (connection_filetransfer_bandwidth_*).
	FileTransferBandwidthSent     uint64
	FileTransferBandwidthReceived uint64
	// FileTransferBytesSent and FileTransferBytesReceived are the file
	// transfer totals (connection_filetransfer_bytes_*_total).
	FileTransferBytesSent     uint64
	FileTransferBytesReceived uint64
	// PacketsSent, BytesSent, PacketsReceived and BytesReceived are the
	// totals (connection_*_total).
	PacketsSent     uint64
	BytesSent       uint64
	PacketsReceived uint64
	BytesReceived   uint64
	// The bandwidth over the last second and minute
	// (connection_bandwidth_*_last_*_total).
	BandwidthSentLastSecond     uint64
	BandwidthSentLastMinute     uint64
	BandwidthReceivedLastSecond uint64
	BandwidthReceivedLastMinute uint64
	// ConnectedTime is how long the virtual server has been running
	// (connection_connected_time, in seconds here).
	ConnectedTime time.Duration
	// Ping is the average ping (connection_ping, in milliseconds).
	Ping time.Duration
	// PacketLoss is the share of packets lost, 0 to 1
	// (connection_packetloss_total).
	PacketLoss float32
}

// GetConnectionInfo returns the virtual server's traffic statistics — not
// this connection's, as the command's name suggests.
func (c *Commands) GetConnectionInfo(ctx context.Context) (ServerConnectionInfo, error) {
	row, err := c.firstRow(ctx, "serverrequestconnectioninfo")
	if err != nil {
		return ServerConnectionInfo{}, err
	}

	return ServerConnectionInfo{
		FileTransferBandwidthSent:     fieldUint(row, "connection_filetransfer_bandwidth_sent"),
		FileTransferBandwidthReceived: fieldUint(row, "connection_filetransfer_bandwidth_received"),
		FileTransferBytesSent:         fieldUint(row, "connection_filetransfer_bytes_sent_total"),
		FileTransferBytesReceived:     fieldUint(row, "connection_filetransfer_bytes_received_total"),
		PacketsSent:                   fieldUint(row, "connection_packets_sent_total"),
		BytesSent:                     fieldUint(row, "connection_bytes_sent_total"),
		PacketsReceived:               fieldUint(row, "connection_packets_received_total"),
		BytesReceived:                 fieldUint(row, "connection_bytes_received_total"),
		BandwidthSentLastSecond:       fieldUint(row, "connection_bandwidth_sent_last_second_total"),
		BandwidthSentLastMinute:       fieldUint(row, "connection_bandwidth_sent_last_minute_total"),
		BandwidthReceivedLastSecond:   fieldUint(row, "connection_bandwidth_received_last_second_total"),
		BandwidthReceivedLastMinute:   fieldUint(row, "connection_bandwidth_received_last_minute_total"),
		ConnectedTime:                 fieldDuration(row, "connection_connected_time", time.Second),
		Ping:                          time.Duration(fieldFloat32(row, "connection_ping") * float32(time.Millisecond)),
		PacketLoss:                    fieldFloat32(row, "connection_packetloss_total"),
	}, nil
}

// GetServerIDByPort returns the numeric id of the virtual server listening on
// port.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetServerIDByPort(ctx context.Context, port uint16) (ServerID, error) {
	rows, err := c.query(ctx, "serveridgetbyport", []param{uintArg("virtualserver_port", uint64(port))})
	if err != nil {
		return 0, err
	}

	return ServerID(firstOrEmpty(rows, "server_id")), nil
}

// CreateServerGroup creates a server group and returns its id.
//
// groupType is always sent, for the reason CreateChannelGroup gives: the
// server's default is GroupRegular, but the zero GroupType is GroupTemplate.
func (c *Commands) CreateServerGroup(ctx context.Context, name string, groupType GroupType) (ServerGroupID, error) {
	rows, err := c.query(ctx, "servergroupadd", []param{
		strArg("name", name),
		intArg("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	return createdGroupID[ServerGroupID](rows, "sgid", name)
}

// DeleteServerGroup deletes a server group.
func (c *Commands) DeleteServerGroup(ctx context.Context, serverGroupID ServerGroupID, opts GroupDeleteOptions) error {
	return c.exec(ctx, "servergroupdel", []param{
		idArg("sgid", serverGroupID),
		boolArg("force", opts.Force),
	})
}

// RenameServerGroup renames a server group.
func (c *Commands) RenameServerGroup(ctx context.Context, serverGroupID ServerGroupID, name string) error {
	return c.exec(ctx, "servergrouprename", []param{
		idArg("sgid", serverGroupID),
		strArg("name", name),
	})
}

// CopyServerGroup copies a server group.
//
// A targetGroupID of 0 makes the server allocate a new id.
func (c *Commands) CopyServerGroup(
	ctx context.Context, sourceGroupID, targetGroupID ServerGroupID, name string, groupType GroupType,
) (ServerGroupID, error) {
	rows, err := c.query(ctx, "servergroupcopy", []param{
		idArg("ssgid", sourceGroupID),
		idArg("tsgid", targetGroupID),
		strArg("name", name),
		intArg("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	// Copying onto an existing group keeps that group's id.
	if targetGroupID != 0 {
		return targetGroupID, nil
	}

	return createdGroupID[ServerGroupID](rows, "sgid", name)
}

// AddClientToServerGroup adds a client to a server group.
func (c *Commands) AddClientToServerGroup(
	ctx context.Context, serverGroupID ServerGroupID, clientDBID ClientDBID,
) error {
	return c.exec(ctx, "servergroupaddclient", []param{
		idArg("sgid", serverGroupID),
		idArg("cldbid", clientDBID),
	})
}

// RemoveClientFromServerGroup removes a client from a server group.
func (c *Commands) RemoveClientFromServerGroup(
	ctx context.Context, serverGroupID ServerGroupID, clientDBID ClientDBID,
) error {
	return c.exec(ctx, "servergroupdelclient", []param{
		idArg("sgid", serverGroupID),
		idArg("cldbid", clientDBID),
	})
}

// ServerGroupClient is one member of a server group.
type ServerGroupClient struct {
	Nickname   string
	UID        UID
	DatabaseID ClientDBID
}

// ServerGroupClientListOptions select ListServerGroupClients' optional
// fields. Each costs the server a lookup per member, so both are off unless
// asked for.
type ServerGroupClientListOptions struct {
	// Names includes each member's nickname.
	Names bool
	// UIDs includes each member's unique identifier.
	UIDs bool
}

// ListServerGroupClients returns the members of a server group.
func (c *Commands) ListServerGroupClients(
	ctx context.Context, serverGroupID ServerGroupID, opts ServerGroupClientListOptions,
) ([]ServerGroupClient, error) {
	params := []param{idArg("sgid", serverGroupID)}
	if opts.Names {
		params = append(params, boolArg("-names", true))
	}
	if opts.UIDs {
		params = append(params, boolArg("-uid", true))
	}

	rows, err := c.list(ctx, "servergroupclientlist", params)
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroupClient, 0, len(rows))
	for _, row := range rows {
		out = append(out, ServerGroupClient{
			DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
			Nickname:   fieldStr(row, "client_nickname"),
			UID:        UID(fieldStr(row, "client_unique_identifier")),
		})
	}

	return out, nil
}

// ServerGroupRef is a group a client belongs to.
type ServerGroupRef struct {
	Name string
	ID   ServerGroupID
}

// GetServerGroupsByClient returns the server groups a client belongs to.
func (c *Commands) GetServerGroupsByClient(ctx context.Context, clientDBID ClientDBID) ([]ServerGroupRef, error) {
	rows, err := c.query(ctx, "servergroupsbyclientid", []param{idArg("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroupRef, 0, len(rows))
	for _, row := range rows {
		out = append(out, ServerGroupRef{
			ID:   ServerGroupID(fieldUint(row, "sgid")),
			Name: fieldStr(row, "name"),
		})
	}

	return out, nil
}

// ListServerGroupPermissions returns the permissions set on a server group.
func (c *Commands) ListServerGroupPermissions(
	ctx context.Context, serverGroupID ServerGroupID,
) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "servergrouppermlist", []param{idArg("sgid", serverGroupID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// ServerGroupPermission is one permission to set on a server group.
type ServerGroupPermission struct {
	Permission Permission
	Value      int32
	Negated    bool
	Skip       bool
}

// AddServerGroupPermission sets a permission on a server group.
func (c *Commands) AddServerGroupPermission(
	ctx context.Context, serverGroupID ServerGroupID, perm ServerGroupPermission,
) error {
	return c.exec(ctx, "servergroupaddperm", []param{
		idArg("sgid", serverGroupID),
		permArg(perm.Permission),
		intArg("permvalue", int64(perm.Value)),
		boolArg("permnegated", perm.Negated),
		boolArg("permskip", perm.Skip),
	})
}

// DeleteServerGroupPermission removes a permission from a server group.
func (c *Commands) DeleteServerGroupPermission(
	ctx context.Context, serverGroupID ServerGroupID, perm Permission,
) error {
	return c.exec(ctx, "servergroupdelperm", []param{
		idArg("sgid", serverGroupID),
		permArg(perm),
	})
}

// TempPassword is a temporary server password.
//
// String, GoString and LogValue redact the password, so the value can reach fmt
// and log/slog safely. encoding/json does not: the password is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type TempPassword struct {
	// Start and End are when the password is valid from and until.
	Start       time.Time
	End         time.Time
	Password    string
	Description string
	// TargetChannelID is the channel a client joining with the password lands
	// in, or 0 for the default channel.
	TargetChannelID ChannelID
}

// String describes the password without the password itself.
func (p TempPassword) String() string {
	return fmt.Sprintf("{Description:%q TargetChannelID:%d Start:%v End:%v Password:redacted}",
		p.Description, p.TargetChannelID, p.Start, p.End)
}

// GoString is String, so %#v redacts too.
func (p TempPassword) GoString() string { return p.String() }

// LogValue describes the password to log/slog without the password itself.
func (p TempPassword) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("description", p.Description),
		slog.Uint64("target_channel_id", uint64(p.TargetChannelID)),
		slog.Time("start", p.Start),
		slog.Time("end", p.End),
		slog.String("password", "redacted"),
	)
}

// ListTempPasswords returns the server's temporary passwords.
func (c *Commands) ListTempPasswords(ctx context.Context) ([]TempPassword, error) {
	rows, err := c.list(ctx, "servertemppasswordlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]TempPassword, 0, len(rows))
	for _, row := range rows {
		out = append(out, TempPassword{
			Password:        fieldStr(row, "pw_clear"),
			Description:     fieldStr(row, "desc"),
			Start:           fieldTime(row, "start"),
			End:             fieldTime(row, "end"),
			TargetChannelID: ChannelID(fieldUint(row, "tcid")),
		})
	}

	return out, nil
}

// TempPasswordOptions describe a temporary password to create.
type TempPasswordOptions struct {
	// Password is the password itself. The caller chooses it; the server does
	// not generate one, and an empty one is refused.
	Password    string
	Description string
	// TargetChannelPassword is the target channel's password, "" for none.
	TargetChannelPassword string
	// Duration is how long the password stays valid, sent in whole seconds.
	// A positive duration under a second is sent as one second.
	Duration time.Duration
	// TargetChannelID is the channel a client joining with the password lands
	// in; 0 is the default channel.
	TargetChannelID ChannelID
}

// AddTempPassword creates a temporary server password. The caller chooses the
// password; the server does not generate one, and an empty one is refused
// with ErrInvalidCommand.
func (c *Commands) AddTempPassword(ctx context.Context, opts TempPasswordOptions) error {
	if opts.Password == "" {
		return fmt.Errorf("%w: a temporary password needs a password", ErrInvalidCommand)
	}

	return c.exec(ctx, "servertemppasswordadd", []param{
		strArg("pw", opts.Password),
		strArg("desc", opts.Description),
		durationArg("duration", opts.Duration, time.Second),
		idArg("tcid", opts.TargetChannelID),
		strArg("tcpw", opts.TargetChannelPassword),
	}, "tcpw")
}

// DeleteTempPassword removes a temporary password.
func (c *Commands) DeleteTempPassword(ctx context.Context, password string) error {
	return c.exec(ctx, "servertemppassworddel", []param{strArg("pw", password)})
}
