package teamspeak

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
//
// Returns no rows over the voice protocol even as Server Admin — the server
// answers ok with no data. This is a server behaviour rather than a permission
// problem; see docs/voice-protocol-empty-responses.md in the JS repository.
func (c *Client) ListServerGroups() ([]ServerGroup, error) {
	rows, err := c.query("servergrouplist", nil)
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
func (c *Client) GetServerInfo() (map[string]string, error) {
	rows, err := c.query("serverinfo", nil)
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
func (c *Client) EditServer(settings map[string]string) error {
	return c.exec("serveredit", stringParams(settings))
}

// GetHostInfo returns the host process's settings.
func (c *Client) GetHostInfo() (map[string]string, error) {
	return c.firstRow("hostinfo")
}

// GetInstanceInfo returns the server instance's settings.
func (c *Client) GetInstanceInfo() (map[string]string, error) {
	return c.firstRow("instanceinfo")
}

// EditInstance changes the server instance's settings.
func (c *Client) EditInstance(settings map[string]string) error {
	return c.exec("instanceedit", stringParams(settings))
}

// firstRow runs a command and returns its single row, or an empty map.
func (c *Client) firstRow(command string) (map[string]string, error) {
	rows, err := c.query(command, nil)
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
		out = append(out, Str(key, value))
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
func (c *Client) ListBindings(subsystem *string) ([]Binding, error) {
	rows, err := c.query("bindinglist", []param{StrPtr("subsystem", subsystem)})
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
func (c *Client) GetVersion() (BuildVersion, error) {
	rows, err := c.query("version", nil)
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
func (c *Client) WhoAmI() (map[string]string, error) {
	return c.firstRow("whoami")
}

// GetConnectionInfo returns connection statistics for our own session.
func (c *Client) GetConnectionInfo() (map[string]string, error) {
	return c.firstRow("serverrequestconnectioninfo")
}

// GetServerIDByPort returns the numeric id of the virtual server listening on
// port.
func (c *Client) GetServerIDByPort(port uint16) (uint64, error) {
	rows, err := c.query("serveridgetbyport", []param{Uint("virtualserver_port", uint64(port))})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "server_id"), nil
}

// CreateServerGroup creates a server group and returns its id.
func (c *Client) CreateServerGroup(name string, groupType *int) (uint64, error) {
	params := []param{Str("name", name)}
	if groupType != nil {
		params = append(params, Int("type", int64(*groupType)))
	}

	rows, err := c.query("servergroupadd", params)
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "sgid"), nil
}

// DeleteServerGroup deletes a server group.
func (c *Client) DeleteServerGroup(serverGroupID uint64, force bool) error {
	return c.exec("servergroupdel", []param{
		Uint("sgid", serverGroupID),
		Bool("force", force),
	})
}

// RenameServerGroup renames a server group.
func (c *Client) RenameServerGroup(serverGroupID uint64, name string) error {
	return c.exec("servergrouprename", []param{
		Uint("sgid", serverGroupID),
		Str("name", name),
	})
}

// CopyServerGroup copies a server group.
//
// A targetGroupID of 0 makes the server allocate a new id.
func (c *Client) CopyServerGroup(sourceGroupID, targetGroupID uint64, name string, groupType int) (uint64, error) {
	rows, err := c.query("servergroupcopy", []param{
		Uint("ssgid", sourceGroupID),
		Uint("tsgid", targetGroupID),
		Str("name", name),
		Int("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "sgid"), nil
}

// AddClientToServerGroup adds a client to a server group.
func (c *Client) AddClientToServerGroup(serverGroupID, clientDBID uint64) error {
	return c.exec("servergroupaddclient", []param{
		Uint("sgid", serverGroupID),
		Uint("cldbid", clientDBID),
	})
}

// RemoveClientFromServerGroup removes a client from a server group.
func (c *Client) RemoveClientFromServerGroup(serverGroupID, clientDBID uint64) error {
	return c.exec("servergroupdelclient", []param{
		Uint("sgid", serverGroupID),
		Uint("cldbid", clientDBID),
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
func (c *Client) ListServerGroupClients(serverGroupID uint64, names, uids bool) ([]ServerGroupClient, error) {
	params := []param{Uint("sgid", serverGroupID)}
	if names {
		params = append(params, Bool("-names", true))
	}
	if uids {
		params = append(params, Bool("-uid", true))
	}

	rows, err := c.query("servergroupclientlist", params)
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
func (c *Client) GetServerGroupsByClient(clientDBID uint64) ([]ServerGroupRef, error) {
	rows, err := c.query("servergroupsbyclientid", []param{Uint("cldbid", clientDBID)})
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
//
// Empty over the voice protocol, like the other group permission lists.
func (c *Client) ListServerGroupPermissions(serverGroupID uint64) ([]PermissionEntry, error) {
	rows, err := c.query("servergrouppermlist", []param{Uint("sgid", serverGroupID)})
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
func (c *Client) AddServerGroupPermission(serverGroupID uint64, perm ServerGroupPermission) error {
	return c.exec("servergroupaddperm", []param{
		Uint("sgid", serverGroupID),
		Int("permvalue", int64(perm.Value)),
		Bool("permnegated", perm.Negated),
		Bool("permskip", perm.Skip),
		UintPtr("permid", perm.PermID),
		StrPtr("permsid", perm.PermSID),
	})
}

// DeleteServerGroupPermission removes a permission from a server group.
func (c *Client) DeleteServerGroupPermission(serverGroupID uint64, permID *uint64, permSID *string) error {
	return c.exec("servergroupdelperm", []param{
		Uint("sgid", serverGroupID),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
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
func (c *Client) ListTempPasswords() ([]TempPassword, error) {
	rows, err := c.query("servertemppasswordlist", nil)
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
func (c *Client) AddTempPassword(
	description string, duration, targetChannelID uint64, targetChannelPassword *string,
) (string, error) {
	rows, err := c.query("servertemppasswordadd", []param{
		Str("pw", ""),
		Str("desc", description),
		Uint("duration", duration),
		Uint("tcid", targetChannelID),
		StrPtr("tcpw", targetChannelPassword),
	}, PlainPassword("tcpw"))
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "pw_clear"), nil
}

// DeleteTempPassword removes a temporary password.
func (c *Client) DeleteTempPassword(password string) error {
	return c.exec("servertemppassworddel", []param{Str("pw", password)})
}
