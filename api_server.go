package teamspeak

import "context"

// Server and instance commands.
//
// "Server" here means the virtual server a client is connected to; "instance"
// means the process hosting it. The distinction matters because the setting
// names differ (virtualserver_* versus serverinstance_*) and the two are easy
// to mix up.

// ServerGroup is a server group as servergrouplist reports it.
type ServerGroup struct {
	Name              string
	ID                uint64
	IconID            uint64
	SortID            uint64
	Type              int
	NameMode          int
	ModifyPower       int32
	MemberAddPower    int32
	MemberRemovePower int32
	SavedInDatabase   bool
}

func parseServerGroup(row map[string]string) ServerGroup {
	return ServerGroup{
		ID:                fieldUint(row, "sgid"),
		Name:              fieldStr(row, "name"),
		Type:              int(fieldInt(row, "type")),
		IconID:            fieldUint(row, "iconid"),
		SavedInDatabase:   fieldBool(row, "savedb"),
		SortID:            fieldUint(row, "sortid"),
		NameMode:          int(fieldInt(row, "namemode")),
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
// A map rather than a struct: serverinfo carries well over a hundred fields and
// which appear depends on permissions, so anything narrower would drop data.
func (c *Commands) GetServerInfo(ctx context.Context) (map[string]string, error) {
	rows, err := c.query(ctx, "serverinfo", nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return map[string]string{}, nil
	}

	return rows[0], nil
}

// EditServer changes the virtual server's settings.
//
// Settings are passed through as given — virtualserver_name, virtualserver_
// maxclients and so on — rather than enumerated: there are well over a hundred,
// they are version-dependent, and a value read out of GetServerInfo should be
// writable straight back.
func (c *Commands) EditServer(ctx context.Context, settings map[string]string) error {
	return c.exec(ctx, "serveredit", stringParams(settings))
}

// GetHostInfo returns the host process's settings.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetHostInfo(ctx context.Context) (map[string]string, error) {
	return c.firstRow(ctx, "hostinfo")
}

// GetInstanceInfo returns the server instance's settings.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetInstanceInfo(ctx context.Context) (map[string]string, error) {
	return c.firstRow(ctx, "instanceinfo")
}

// EditInstance changes the server instance's settings.
func (c *Commands) EditInstance(ctx context.Context, settings map[string]string) error {
	return c.exec(ctx, "instanceedit", stringParams(settings))
}

// firstRow runs a command and returns its single row, or an empty map.
func (c *Commands) firstRow(ctx context.Context, command string) (map[string]string, error) {
	rows, err := c.query(ctx, command, nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return map[string]string{}, nil
	}

	return rows[0], nil
}

// stringParams turns a settings map into params.
//
// Map iteration order is not stable, but serveredit parameters are named on the
// wire, so order does not matter here.
func stringParams(settings map[string]string) []param {
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
	Port      int
}

// ListBindings returns active IP bindings, when the instance is multi-homed.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) ListBindings(ctx context.Context, subsystem *string) ([]Binding, error) {
	rows, err := c.query(ctx, "bindinglist", []param{strPtrArg("subsystem", subsystem)})
	if err != nil {
		return nil, err
	}

	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		out = append(out, Binding{
			Subsystem: fieldStr(row, "subsystem"),
			IP:        fieldStr(row, "ip"),
			Port:      int(fieldInt(row, "port")),
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
		return BuildVersion{}, errNoDataReturned
	}

	row := rows[0]

	return BuildVersion{
		Version:  fieldStr(row, "version"),
		Build:    fieldUint(row, "build"),
		Platform: fieldStr(row, "platform"),
	}, nil
}

// WhoAmI returns which server and client this connection is, as the server sees
// it.
func (c *Commands) WhoAmI(ctx context.Context) (map[string]string, error) {
	return c.firstRow(ctx, "whoami")
}

// GetConnectionInfo returns connection statistics for our own session.
func (c *Commands) GetConnectionInfo(ctx context.Context) (map[string]string, error) {
	return c.firstRow(ctx, "serverrequestconnectioninfo")
}

// GetServerIDByPort returns the numeric id of the virtual server listening on
// port.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetServerIDByPort(ctx context.Context, port uint16) (uint64, error) {
	rows, err := c.query(ctx, "serveridgetbyport", []param{uintArg("virtualserver_port", uint64(port))})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "server_id"), nil
}

// CreateServerGroup creates a server group and returns its id.
func (c *Commands) CreateServerGroup(ctx context.Context, name string, groupType *int) (uint64, error) {
	params := []param{strArg("name", name)}
	if groupType != nil {
		params = append(params, intArg("type", int64(*groupType)))
	}

	rows, err := c.query(ctx, "servergroupadd", params)
	if err != nil {
		return 0, err
	}

	return createdGroupID(rows, "sgid", name)
}

// DeleteServerGroup deletes a server group.
func (c *Commands) DeleteServerGroup(ctx context.Context, serverGroupID uint64, force bool) error {
	return c.exec(ctx, "servergroupdel", []param{
		uintArg("sgid", serverGroupID),
		boolArg("force", force),
	})
}

// RenameServerGroup renames a server group.
func (c *Commands) RenameServerGroup(ctx context.Context, serverGroupID uint64, name string) error {
	return c.exec(ctx, "servergrouprename", []param{
		uintArg("sgid", serverGroupID),
		strArg("name", name),
	})
}

// CopyServerGroup copies a server group.
//
// A targetGroupID of 0 makes the server allocate a new id.
func (c *Commands) CopyServerGroup(
	ctx context.Context, sourceGroupID, targetGroupID uint64, name string, groupType int,
) (uint64, error) {
	rows, err := c.query(ctx, "servergroupcopy", []param{
		uintArg("ssgid", sourceGroupID),
		uintArg("tsgid", targetGroupID),
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

	return createdGroupID(rows, "sgid", name)
}

// AddClientToServerGroup adds a client to a server group.
func (c *Commands) AddClientToServerGroup(ctx context.Context, serverGroupID, clientDBID uint64) error {
	return c.exec(ctx, "servergroupaddclient", []param{
		uintArg("sgid", serverGroupID),
		uintArg("cldbid", clientDBID),
	})
}

// RemoveClientFromServerGroup removes a client from a server group.
func (c *Commands) RemoveClientFromServerGroup(ctx context.Context, serverGroupID, clientDBID uint64) error {
	return c.exec(ctx, "servergroupdelclient", []param{
		uintArg("sgid", serverGroupID),
		uintArg("cldbid", clientDBID),
	})
}

// ServerGroupClient is one member of a server group.
type ServerGroupClient struct {
	Nickname   string
	UID        string
	DatabaseID uint64
}

// ListServerGroupClients returns the members of a server group.
//
// Names and uids are omitted unless asked for, because each adds a lookup the
// server has to do per member.
func (c *Commands) ListServerGroupClients(
	ctx context.Context, serverGroupID uint64, names, uids bool,
) ([]ServerGroupClient, error) {
	params := []param{uintArg("sgid", serverGroupID)}
	if names {
		params = append(params, boolArg("-names", true))
	}
	if uids {
		params = append(params, boolArg("-uid", true))
	}

	rows, err := c.query(ctx, "servergroupclientlist", params)
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroupClient, 0, len(rows))
	for _, row := range rows {
		out = append(out, ServerGroupClient{
			DatabaseID: fieldUint(row, "cldbid"),
			Nickname:   fieldStr(row, "client_nickname"),
			UID:        fieldStr(row, "client_unique_identifier"),
		})
	}

	return out, nil
}

// ServerGroupRef is a group a client belongs to.
type ServerGroupRef struct {
	Name string
	ID   uint64
}

// GetServerGroupsByClient returns the server groups a client belongs to.
func (c *Commands) GetServerGroupsByClient(ctx context.Context, clientDBID uint64) ([]ServerGroupRef, error) {
	rows, err := c.query(ctx, "servergroupsbyclientid", []param{uintArg("cldbid", clientDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]ServerGroupRef, 0, len(rows))
	for _, row := range rows {
		out = append(out, ServerGroupRef{
			ID:   fieldUint(row, "sgid"),
			Name: fieldStr(row, "name"),
		})
	}

	return out, nil
}

// ListServerGroupPermissions returns the permissions set on a server group.
func (c *Commands) ListServerGroupPermissions(ctx context.Context, serverGroupID uint64) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "servergrouppermlist", []param{uintArg("sgid", serverGroupID)})
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
	PermID  *uint64
	PermSID *string
	Value   int32
	Negated bool
	Skip    bool
}

// AddServerGroupPermission grants a permission to a server group.
func (c *Commands) AddServerGroupPermission(
	ctx context.Context, serverGroupID uint64, perm ServerGroupPermission,
) error {
	return c.exec(ctx, "servergroupaddperm", []param{
		uintArg("sgid", serverGroupID),
		intArg("permvalue", int64(perm.Value)),
		boolArg("permnegated", perm.Negated),
		boolArg("permskip", perm.Skip),
		uintPtrArg("permid", perm.PermID),
		strPtrArg("permsid", perm.PermSID),
	})
}

// DeleteServerGroupPermission removes a permission from a server group.
func (c *Commands) DeleteServerGroupPermission(
	ctx context.Context, serverGroupID uint64, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "servergroupdelperm", []param{
		uintArg("sgid", serverGroupID),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// TempPassword is a temporary server password.
type TempPassword struct {
	Password        string
	Description     string
	TargetChannelID uint64
	Start           uint64
	End             uint64
}

// ListTempPasswords returns the server's temporary passwords.
func (c *Commands) ListTempPasswords(ctx context.Context) ([]TempPassword, error) {
	rows, err := c.query(ctx, "servertemppasswordlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]TempPassword, 0, len(rows))
	for _, row := range rows {
		out = append(out, TempPassword{
			Password:        fieldStr(row, "pw_clear"),
			Description:     fieldStr(row, "desc"),
			Start:           fieldUint(row, "start"),
			End:             fieldUint(row, "end"),
			TargetChannelID: fieldUint(row, "tcid"),
		})
	}

	return out, nil
}

// AddTempPassword creates a temporary password and returns it as the server
// generated it.
//
// The password itself is not supplied: the server generates it, which is why no
// password parameter is sent even though the schema names one.
func (c *Commands) AddTempPassword(
	ctx context.Context, description string, duration, targetChannelID uint64, targetChannelPassword *string,
) (string, error) {
	rows, err := c.query(ctx, "servertemppasswordadd", []param{
		strArg("pw", ""),
		strArg("desc", description),
		uintArg("duration", duration),
		uintArg("tcid", targetChannelID),
		strPtrArg("tcpw", targetChannelPassword),
	}, "tcpw")
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "pw_clear"), nil
}

// DeleteTempPassword removes a temporary password.
func (c *Commands) DeleteTempPassword(ctx context.Context, password string) error {
	return c.exec(ctx, "servertemppassworddel", []param{strArg("pw", password)})
}
