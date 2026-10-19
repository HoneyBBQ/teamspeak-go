package teamspeak

import (
	"cmp"
	"context"
	"errors"
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
	// Name is the group's name (name).
	Name string
	// ID is the group's id (sgid).
	ID ServerGroupID
	// IconID is the group's icon, or 0 for none (iconid).
	IconID IconID
	// SortID orders the group among the others (sortid).
	SortID int32
	// Type is whether the group is a template, a regular group or a query group
	// (type).
	Type GroupType
	// NameMode is where the client shows the group's name beside a member's
	// (namemode).
	NameMode GroupNameMode
	// ModifyPower is the power needed to change the group (n_modifyp).
	ModifyPower int32
	// MemberAddPower is the power needed to add a member (n_member_addp).
	MemberAddPower int32
	// MemberRemovePower is the power needed to remove a member
	// (n_member_removep).
	MemberRemovePower int32
	// SavedInDatabase reports a permanent group, one the server keeps across
	// restarts (savedb).
	SavedInDatabase bool
}

func parseServerGroup(row map[string]string) ServerGroup {
	return ServerGroup{
		ID:                ServerGroupID(fieldUint(row, "sgid")),
		Name:              fieldStr(row, "name"),
		Type:              GroupType(fieldEnum(row, "type")),
		IconID:            fieldIconID(row, "iconid"),
		SavedInDatabase:   fieldBool(row, "savedb"),
		SortID:            fieldInt32(row, "sortid"),
		NameMode:          GroupNameMode(fieldEnum(row, "namemode")),
		ModifyPower:       fieldInt32(row, "n_modifyp"),
		MemberAddPower:    fieldInt32(row, "n_member_addp"),
		MemberRemovePower: fieldInt32(row, "n_member_removep"),
	}
}

// ServerGroupListOptions are ListServerGroups' optional parameters. It has no
// fields yet: it is reserved for the parameters of servergrouplist.
type ServerGroupListOptions struct{}

// ListServerGroups returns every server group.
func (c *Commands) ListServerGroups(ctx context.Context, _ ServerGroupListOptions) ([]ServerGroup, error) {
	rows, err := c.list(ctx, "servergrouplist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseServerGroup(row))
	}

	return out, nil
}

// GetServerInfo returns the server's own settings, unfiltered; the prop
// package names the keys.
//
// Properties rather than a struct: serverinfo carries well over a hundred
// fields and which appear depends on permissions, so anything narrower would
// drop data.
func (c *Commands) GetServerInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "serverinfo")
}

// EditServer changes the virtual server's settings; the prop package marks
// the editable keys.
//
// Settings are passed through as given — virtualserver_name, virtualserver_
// maxclients and so on — rather than enumerated: there are well over a hundred,
// they are version-dependent, and a value read out of GetServerInfo should be
// writable straight back.
func (c *Commands) EditServer(ctx context.Context, settings Properties) error {
	return c.exec(ctx, "serveredit", stringParams(settings))
}

// GetHostInfo returns the host process's settings; the prop package names the
// keys.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetHostInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "hostinfo")
}

// GetInstanceInfo returns the server instance's settings; the prop package
// names the keys.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetInstanceInfo(ctx context.Context) (Properties, error) {
	return c.firstRow(ctx, "instanceinfo")
}

// EditInstance changes the server instance's settings; the prop package marks
// the editable keys.
func (c *Commands) EditInstance(ctx context.Context, settings Properties) error {
	return c.exec(ctx, "instanceedit", stringParams(settings))
}

// firstRow runs a command defined to answer with one row and returns it, or an
// error wrapping ErrNoData.
func (c *Commands) firstRow(ctx context.Context, command string) (Properties, error) {
	return c.queryRow(ctx, command, "", nil)
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
	// Subsystem is what the binding serves: "voice", "query" or "filetransfer".
	// The server does not name it in each row, so it is the subsystem asked
	// for, or "voice" when none was.
	Subsystem string
	// IP is the address bound (ip).
	IP string
	// Port is the port bound (port); nil when the server does not report it.
	Port *uint16
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
	rows, err := c.list(ctx, "bindinglist", []param{optStrArg("subsystem", opts.Subsystem)})
	if err != nil {
		return nil, err
	}

	subsystem := opts.Subsystem
	if subsystem == "" {
		subsystem = "voice"
	}

	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		out = append(out, Binding{
			Subsystem: cmp.Or(fieldStr(row, "subsystem"), subsystem),
			IP:        fieldStr(row, "ip"),
			Port:      fieldOptUint16(row, "port"),
		})
	}

	return out, nil
}

// ServerVersion is the server's build information.
type ServerVersion struct {
	// Version is the server's version (version).
	Version string
	// Platform is the operating system the server runs on (platform).
	Platform string
	// Build is the server's build number (build).
	Build uint64
}

// GetVersion returns the server's build version.
func (c *Commands) GetVersion(ctx context.Context) (ServerVersion, error) {
	row, err := c.queryRow(ctx, "version", "", nil)
	if err != nil {
		return ServerVersion{}, err
	}

	return ServerVersion{
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
	// ServerUUID is the virtual server's uuid (virtualserver_uuid); empty when
	// the server sends none: TeamSpeak 6 does, TeamSpeak 3 does not.
	ServerUUID string
	// OriginServerID is the id of the server this connection's account
	// originates from (client_origin_server_id); 0 for a connection that is not
	// from another server, which is what both TeamSpeak 3.13.8 and 6.0.0-beta13.1
	// sent.
	OriginServerID ServerID
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

		ServerUUID:     fieldStr(row, "virtualserver_uuid"),
		OriginServerID: ServerID(fieldUint(row, "client_origin_server_id")),
	}, nil
}

// ServerConnectionInfo is the virtual server's traffic statistics, as
// serverrequestconnectioninfo reports them. Rates are in bytes per second.
type ServerConnectionInfo struct {
	// FileTransferBandwidthSent and FileTransferBandwidthReceived are the
	// file transfer bandwidth (connection_filetransfer_bandwidth_*).
	FileTransferBandwidthSent uint64
	// FileTransferBandwidthReceived is the inbound file transfer bandwidth.
	FileTransferBandwidthReceived uint64
	// FileTransferBytesSent and FileTransferBytesReceived are the file
	// transfer totals (connection_filetransfer_bytes_*_total).
	FileTransferBytesSent uint64
	// FileTransferBytesReceived is the inbound file transfer total.
	FileTransferBytesReceived uint64
	// PacketsSent, BytesSent, PacketsReceived and BytesReceived are the
	// totals (connection_*_total).
	PacketsSent uint64
	// BytesSent is the total of bytes sent.
	BytesSent uint64
	// PacketsReceived is the total of packets received.
	PacketsReceived uint64
	// BytesReceived is the total of bytes received.
	BytesReceived uint64
	// The bandwidth over the last second and minute
	// (connection_bandwidth_*_last_*_total).
	BandwidthSentLastSecond uint64
	// BandwidthSentLastMinute is the outbound bandwidth over the last minute.
	BandwidthSentLastMinute uint64
	// BandwidthReceivedLastSecond is the inbound bandwidth over the last second.
	BandwidthReceivedLastSecond uint64
	// BandwidthReceivedLastMinute is the inbound bandwidth over the last minute.
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
	row, err := c.queryRow(ctx, "serveridgetbyport", "server_id", []param{uintArg("virtualserver_port", uint64(port))})
	if err != nil {
		return 0, err
	}

	return ServerID(fieldUint(row, "server_id")), nil
}

// CreateServerGroup creates a server group and returns its id.
//
// groupType is always sent, for the reason CreateChannelGroup gives: the
// server's default is GroupRegular, but the zero GroupType is GroupTemplate.
//
// TeamSpeak 6 6.0.0-beta13.1 over WebQuery answers a create without its id, in a
// share of the creates, while a Server Admin voice client is connected: the
// server writes the id after its status, so the HTTP answer has no body. The
// group exists then. When the answer names no group, it is looked up in the
// group list by its exact name and type, which is exact because the server
// keeps a group's name and type unique. The one gap is another client renaming
// or deleting the group between the create and the lookup. The error wraps
// ErrNoData only when nothing matches, and then the group may still have been
// created. See the "Server behaviour the SDK works around" section of the
// serverquery package documentation.
func (c *Commands) CreateServerGroup(ctx context.Context, name string, groupType GroupType) (ServerGroupID, error) {
	rows, err := c.query(ctx, "servergroupadd", []param{
		strArg("name", name),
		intArg("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	return c.createdServerGroup(ctx, rows, name, groupType)
}

// createdServerGroup returns the id of the server group a create or copy just
// made. When the answer names none — TeamSpeak 6's WebQuery does so while a
// Server Admin voice client is connected — the group is looked up in the group
// list by its exact name and type, which is unambiguous because a server
// refuses a second group of the same name and type. The error wraps ErrNoData only when nothing
// matches.
func (c *Commands) createdServerGroup(
	ctx context.Context, rows []map[string]string, name string, groupType GroupType,
) (ServerGroupID, error) {
	id, err := createdGroupID[ServerGroupID](rows, "sgid", name)
	if !errors.Is(err, ErrNoData) {
		return id, err
	}
	groups, listErr := c.ListServerGroups(ctx, ServerGroupListOptions{})
	if listErr != nil {
		return 0, listErr
	}
	for _, g := range groups {
		if g.Name == name && g.Type == groupType {
			return g.ID, nil
		}
	}

	return 0, fmt.Errorf("%w: the server did not report the new group %q", ErrNoData, name)
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
// A targetGroupID of 0 makes the server allocate a new id, and the new group is
// then found as CreateServerGroup finds its own, by name and groupType.
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

	return c.createdServerGroup(ctx, rows, name, groupType)
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

// ServerGroupMembersOptions are the optional parameters of
// AddClientsToServerGroup and RemoveClientsFromServerGroup.
type ServerGroupMembersOptions struct {
	// ContinueOnError sends -continueonerror, so a client that cannot be added
	// or removed does not stop the ones after it. See AddClientsToServerGroup.
	ContinueOnError bool
}

// AddClientsToServerGroup adds several clients to a server group in one
// command (servergroupaddclient, one cldbid row each). Adding none sends
// nothing.
//
// The server answers one status for the whole command and never one per
// client, so the result is an error and nothing more. Measured on TeamSpeak 3
// 3.13.8 and 6 beta13.1, over raw ServerQuery, SSH, WebQuery and the voice
// protocol alike: the clients are added in order. Without ContinueOnError the
// first failure ends the command and is its answer: 512 for an unknown
// database id, 2561 for a client already in the group. The clients before it
// were added, the ones after it were not. With ContinueOnError every client that
// can be added is, and the answer is the last error among the failures, or
// success when none failed: with a duplicate before an unknown id the answer is
// 512, with the unknown id first it is 2561. Which clients failed is not
// reported; list the group's members.
func (c *Commands) AddClientsToServerGroup(
	ctx context.Context, serverGroupID ServerGroupID, clientDBIDs []ClientDBID, opts ServerGroupMembersOptions,
) error {
	if len(clientDBIDs) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupaddclient", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("sgid", serverGroupID),
		idRowsArg("cldbid", clientDBIDs),
	})
}

// RemoveClientsFromServerGroup removes several clients from a server group in
// one command (servergroupdelclient, one cldbid row each). Removing none sends
// nothing.
//
// It answers as AddClientsToServerGroup does, measured the same way: without
// ContinueOnError the first failure ends the command and the clients before it
// were removed; with it every client that can be removed is, and the answer is
// the last error among the failures. A client that is not in the group, and an
// unknown database id, are both refused with 2563, "empty result set".
func (c *Commands) RemoveClientsFromServerGroup(
	ctx context.Context, serverGroupID ServerGroupID, clientDBIDs []ClientDBID, opts ServerGroupMembersOptions,
) error {
	if len(clientDBIDs) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupdelclient", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("sgid", serverGroupID),
		idRowsArg("cldbid", clientDBIDs),
	})
}

// ServerGroupMember is one member of a server group.
type ServerGroupMember struct {
	// Nickname is the member's nickname (client_nickname); "" unless the list
	// asked for Names.
	Nickname string
	// UID is the member's identity (client_unique_identifier); "" unless the
	// list asked for Names.
	UID UID
	// DatabaseID is the member's database id (cldbid).
	DatabaseID ClientDBID
}

// ServerGroupClientListOptions select ListServerGroupClients' optional
// fields. They cost the server a lookup per member, so they are off unless
// asked for.
type ServerGroupClientListOptions struct {
	// Names includes each member's nickname and unique identifier.
	Names bool
}

// ListServerGroupClients returns the members of a server group.
func (c *Commands) ListServerGroupClients(
	ctx context.Context, serverGroupID ServerGroupID, opts ServerGroupClientListOptions,
) ([]ServerGroupMember, error) {
	params := []param{idArg("sgid", serverGroupID)}
	if opts.Names {
		params = append(params, boolArg("-names", true))
	}

	rows, err := c.list(ctx, "servergroupclientlist", params)
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroupMember, 0, len(rows))
	for _, row := range rows {
		out = append(out, ServerGroupMember{
			DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
			Nickname:   fieldStr(row, "client_nickname"),
			UID:        UID(fieldStr(row, "client_unique_identifier")),
		})
	}

	return out, nil
}

// ServerGroupRef is a group a client belongs to.
type ServerGroupRef struct {
	// Name is the group's name (name).
	Name string
	// ID is the group's id (sgid).
	ID ServerGroupID
}

// GetServerGroupsByClient returns the server groups a client belongs to.
func (c *Commands) GetServerGroupsByClient(ctx context.Context, clientDBID ClientDBID) ([]ServerGroupRef, error) {
	rows, err := c.list(ctx, "servergroupsbyclientid", []param{idArg("cldbid", clientDBID)})
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
	rows, err := c.list(ctx, "servergrouppermlist", []param{idArg("sgid", serverGroupID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// ServerGroupPermissionOptions are AddServerGroupPermission's optional
// parameters. Both are always sent, false unless set.
type ServerGroupPermissionOptions struct {
	// Negated makes the lowest value among the client's groups win instead of
	// the highest (permnegated).
	Negated bool
	// Skip makes the value override the client's channel and channel group
	// permissions (permskip).
	Skip bool
}

// AddServerGroupPermission sets a permission on a server group.
func (c *Commands) AddServerGroupPermission(
	ctx context.Context, serverGroupID ServerGroupID, perm Permission, value int32, opts ServerGroupPermissionOptions,
) error {
	return c.exec(ctx, "servergroupaddperm", []param{
		idArg("sgid", serverGroupID),
		permArg(perm),
		intArg("permvalue", int64(value)),
		boolArg("permnegated", opts.Negated),
		boolArg("permskip", opts.Skip),
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

// GroupAutoUpdateType names the regular server groups a permission is added to
// or removed from across every virtual server, by their
// i_group_auto_update_type permission (sgtype). Each is the kind of group the
// server's default templates make; the server accepts any other number without
// effect.
type GroupAutoUpdateType int

const (
	// GroupAutoUpdateChannelGuest is the Channel Guest groups.
	GroupAutoUpdateChannelGuest GroupAutoUpdateType = 10
	// GroupAutoUpdateServerGuest is the Server Guest groups.
	GroupAutoUpdateServerGuest GroupAutoUpdateType = 15
	// GroupAutoUpdateQueryGuest is the Query Guest groups.
	GroupAutoUpdateQueryGuest GroupAutoUpdateType = 20
	// GroupAutoUpdateChannelVoice is the Channel Voice groups.
	GroupAutoUpdateChannelVoice GroupAutoUpdateType = 25
	// GroupAutoUpdateServerNormal is the Server Normal groups.
	GroupAutoUpdateServerNormal GroupAutoUpdateType = 30
	// GroupAutoUpdateChannelOperator is the Channel Operator groups.
	GroupAutoUpdateChannelOperator GroupAutoUpdateType = 35
	// GroupAutoUpdateChannelAdmin is the Channel Admin groups.
	GroupAutoUpdateChannelAdmin GroupAutoUpdateType = 40
	// GroupAutoUpdateServerAdmin is the Server Admin groups.
	GroupAutoUpdateServerAdmin GroupAutoUpdateType = 45
	// GroupAutoUpdateQueryAdmin is the Query Admin groups.
	GroupAutoUpdateQueryAdmin GroupAutoUpdateType = 50
)

var groupAutoUpdateTypeNames = [...]string{
	GroupAutoUpdateChannelGuest:    "channel guest",
	GroupAutoUpdateServerGuest:     "server guest",
	GroupAutoUpdateQueryGuest:      "query guest",
	GroupAutoUpdateChannelVoice:    "channel voice",
	GroupAutoUpdateServerNormal:    "server normal",
	GroupAutoUpdateChannelOperator: "channel operator",
	GroupAutoUpdateChannelAdmin:    "channel admin",
	GroupAutoUpdateServerAdmin:     "server admin",
	GroupAutoUpdateQueryAdmin:      "query admin",
}

// String returns the group kind's name, or "group auto update type N" for a
// value this version does not know.
func (t GroupAutoUpdateType) String() string {
	return enumName(t, groupAutoUpdateTypeNames[:], "group auto update type")
}

// AddServerGroupPermissionByType sets a permission on every regular server
// group of one kind, on every virtual server of the instance. It sends
// servergroupautoaddperm with the group kind as sgtype.
//
// It changes groups on virtual servers the connection is not on, and
// overwrites the permission where a group already has it. Needs
// b_permission_modify_power_ignore, an instance permission that not even a
// voice Server Admin holds: error 2568. A permission the server does not
// know is refused with 2562. Both TeamSpeak 3 and 6 serve it over
// ServerQuery. Negated and Skip are always sent: the server answers 1539,
// "parameter not found", without them.
func (c *Commands) AddServerGroupPermissionByType(
	ctx context.Context, groups GroupAutoUpdateType, perm Permission, value int32, opts ServerGroupPermissionOptions,
) error {
	return c.exec(ctx, "servergroupautoaddperm", []param{
		intArg("sgtype", int64(groups)),
		permArg(perm),
		intArg("permvalue", int64(value)),
		boolArg("permnegated", opts.Negated),
		boolArg("permskip", opts.Skip),
	})
}

// DeleteServerGroupPermissionByType removes a permission from every regular
// server group of one kind, on every virtual server of the instance. It sends
// servergroupautodelperm.
//
// Needs b_permission_modify_power_ignore; see AddServerGroupPermissionByType.
// A group that does not hold the permission is not an error.
func (c *Commands) DeleteServerGroupPermissionByType(
	ctx context.Context, groups GroupAutoUpdateType, perm Permission,
) error {
	return c.exec(ctx, "servergroupautodelperm", []param{
		intArg("sgtype", int64(groups)),
		permArg(perm),
	})
}

// TempPassword is a temporary server password.
//
// String, GoString and LogValue redact the password and the target channel's
// password, so the value can reach fmt and log/slog safely. encoding/json does
// not: they are the caller's own data, which they may need to store, so
// json.Marshal includes them.
type TempPassword struct {
	// Starts is when the password becomes valid.
	Starts time.Time
	// Ends is when the password stops being valid.
	Ends time.Time
	// Password is the password itself (pw_clear).
	Password string
	// Description is the password's description (desc).
	Description string
	// TargetChannelPassword is the password of the target channel (tcpw), in
	// cleartext as the list gives it, "" for none. Like Password it is a secret:
	// String, GoString and LogValue leave it out, and encoding/json does not.
	TargetChannelPassword string
	// TargetChannelID is the channel a client joining with the password lands
	// in, or 0 for the default channel.
	TargetChannelID ChannelID
	// CreatorNickname is the nickname of the client that made the password
	// (nickname).
	CreatorNickname string
	// CreatorUID is the identity of the client that made the password
	// (uid).
	CreatorUID UID
}

// String describes the password without the password itself.
func (p TempPassword) String() string {
	return fmt.Sprintf("{Description:%q TargetChannelID:%d Start:%v End:%v Password:redacted}",
		p.Description, p.TargetChannelID, p.Starts, p.Ends)
}

// GoString is String, so %#v redacts too.
func (p TempPassword) GoString() string { return p.String() }

// LogValue describes the password to log/slog without the password itself.
func (p TempPassword) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("description", p.Description),
		slog.Uint64("target_channel_id", uint64(p.TargetChannelID)),
		slog.Time("start", p.Starts),
		slog.Time("end", p.Ends),
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
			Starts:          fieldTime(row, "start"),
			Ends:            fieldTime(row, "end"),
			CreatorNickname: fieldStr(row, "nickname"),
			CreatorUID:      UID(fieldStr(row, "uid")),

			TargetChannelPassword: fieldStr(row, "tcpw"),
			TargetChannelID:       ChannelID(fieldUint(row, "tcid")),
		})
	}

	return out, nil
}

// TempPasswordOptions describe a temporary password to create.
type TempPasswordOptions struct {
	// Password is the password itself. The caller chooses it; the server does
	// not generate one, and an empty one is refused.
	Password string
	// Description is shown in the password list (desc).
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
