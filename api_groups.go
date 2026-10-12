package teamspeak

// Channel groups, permissions, and the tokens used to join groups.

// ChannelGroup is a channel group as channelgrouplist reports it.
type ChannelGroup struct {
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

func parseChannelGroup(row map[string]string) ChannelGroup {
	return ChannelGroup{
		ID:                fieldUint(row, "cgid"),
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

// ListChannelGroups returns every channel group.
func (c *Client) ListChannelGroups() ([]ChannelGroup, error) {
	rows, err := c.query("channelgrouplist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]ChannelGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseChannelGroup(row))
	}

	return out, nil
}

// CreateChannelGroup creates a channel group and returns its id.
func (c *Client) CreateChannelGroup(name string, groupType *int) (uint64, error) {
	params := []param{Str("name", name)}
	if groupType != nil {
		params = append(params, Int("type", int64(*groupType)))
	}

	rows, err := c.query("channelgroupadd", params)
	if err != nil {
		return 0, err
	}

	return createdGroupID(rows, "cgid", name)
}

// DeleteChannelGroup deletes a channel group.
func (c *Client) DeleteChannelGroup(channelGroupID uint64, force bool) error {
	return c.exec("channelgroupdel", []param{
		Uint("cgid", channelGroupID),
		Bool("force", force),
	})
}

// RenameChannelGroup renames a channel group.
func (c *Client) RenameChannelGroup(channelGroupID uint64, name string) error {
	return c.exec("channelgrouprename", []param{
		Uint("cgid", channelGroupID),
		Str("name", name),
	})
}

// CopyChannelGroup copies a channel group; a targetGroupID of 0 allocates one.
func (c *Client) CopyChannelGroup(sourceGroupID, targetGroupID uint64, name string, groupType int) (uint64, error) {
	rows, err := c.query("channelgroupcopy", []param{
		Uint("scgid", sourceGroupID),
		Uint("tcgid", targetGroupID),
		Str("name", name),
		Int("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	// Copying onto an existing group keeps that group's id.
	if targetGroupID != 0 {
		return targetGroupID, nil
	}

	return createdGroupID(rows, "cgid", name)
}

// ChannelGroupMembership is which channel group a client holds in a channel.
type ChannelGroupMembership struct {
	ChannelID  uint64
	DatabaseID uint64
	GroupID    uint64
}

// ListChannelGroupClients returns which channel group each client holds in
// which channel. Pass at least one filter; called with none the server may
// return nothing.
func (c *Client) ListChannelGroupClients(
	channelID, clientDBID, channelGroupID *uint64,
) ([]ChannelGroupMembership, error) {
	rows, err := c.query("channelgroupclientlist", []param{
		UintPtr("cid", channelID),
		UintPtr("cldbid", clientDBID),
		UintPtr("cgid", channelGroupID),
	})
	if err != nil {
		return nil, err
	}

	out := make([]ChannelGroupMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChannelGroupMembership{
			ChannelID:  fieldUint(row, "cid"),
			DatabaseID: fieldUint(row, "cldbid"),
			GroupID:    fieldUint(row, "cgid"),
		})
	}

	return out, nil
}

// ListChannelGroupPermissions returns the permissions set on a channel group.
func (c *Client) ListChannelGroupPermissions(channelGroupID uint64) ([]PermissionEntry, error) {
	rows, err := c.query("channelgrouppermlist", []param{Uint("cgid", channelGroupID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// AddChannelGroupPermission grants a permission to a channel group.
func (c *Client) AddChannelGroupPermission(
	channelGroupID uint64, permValue int32, permID *uint64, permSID *string,
) error {
	return c.exec("channelgroupaddperm", []param{
		Uint("cgid", channelGroupID),
		Int("permvalue", int64(permValue)),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// DeleteChannelGroupPermission removes a permission from a channel group.
func (c *Client) DeleteChannelGroupPermission(channelGroupID uint64, permID *uint64, permSID *string) error {
	return c.exec("channelgroupdelperm", []param{
		Uint("cgid", channelGroupID),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// ---- Permissions ------------------------------------------------------------

// ListPermissions returns the server's full permission catalogue.
func (c *Client) ListPermissions() ([]map[string]string, error) {
	return c.query("permissionlist", nil)
}

// GetPermissionIDByName resolves a permission name to its numeric id. The
// second return value is false when the server knows no such permission.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Client) GetPermissionIDByName(permSID string) (uint64, bool, error) {
	rows, err := c.query("permidgetbyname", []param{Str("permsid", permSID)})
	if err != nil {
		return 0, false, err
	}

	if len(rows) == 0 {
		return 0, false, nil
	}

	return fieldUint(rows[0], "permid"), true, nil
}

// PermissionLocation is one place a permission is set, as permfind reports it.
type PermissionLocation struct {
	ID1        uint64
	ID2        uint64
	Permission uint64
	Type       int
}

// FindPermission returns every place a permission is set.
func (c *Client) FindPermission(permID *uint64, permSID *string) ([]PermissionLocation, error) {
	rows, err := c.query("permfind", []param{
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionLocation, 0, len(rows))
	for _, row := range rows {
		out = append(out, PermissionLocation{
			Type:       int(fieldInt(row, "t")),
			ID1:        fieldUint(row, "id1"),
			ID2:        fieldUint(row, "id2"),
			Permission: fieldUint(row, "p"),
		})
	}

	return out, nil
}

// GetPermissionOverview returns a client's effective permissions in a channel.
func (c *Client) GetPermissionOverview(
	channelID, clientDBID uint64, permID *uint64, permSID *string,
) ([]map[string]string, error) {
	return c.query("permoverview", []param{
		Uint("cid", channelID),
		Uint("cldbid", clientDBID),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// ResetPermissions wipes all permission overrides and restores the defaults.
//
// Destructive: every custom permission on the server goes, including the
// caller's own rights, because it resets the group they rely on.
func (c *Client) ResetPermissions() error {
	return c.exec("permreset", nil)
}

// ---- Tokens and privilege keys ----------------------------------------------

// PrivilegeKey grants a group when redeemed.
//
// "token" and "privilegekey" name the same thing; the server accepts both
// command families.
type PrivilegeKey struct {
	Token       string
	Description string
	ID1         uint64
	ID2         uint64
	CreatedAt   uint64
	Type        int
}

func parseKey(row map[string]string) PrivilegeKey {
	return PrivilegeKey{
		Token:       fieldStr(row, "token"),
		Type:        int(fieldInt(row, "token_type")),
		ID1:         fieldUint(row, "token_id1"),
		ID2:         fieldUint(row, "token_id2"),
		Description: fieldStr(row, "token_description"),
		CreatedAt:   fieldUint(row, "token_created"),
	}
}

func (c *Client) listKeys(command string) ([]PrivilegeKey, error) {
	rows, err := c.query(command, nil)
	if err != nil {
		return nil, err
	}

	out := make([]PrivilegeKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseKey(row))
	}

	return out, nil
}

// ListPrivilegeKeys returns every privilege key.
func (c *Client) ListPrivilegeKeys() ([]PrivilegeKey, error) {
	return c.listKeys("privilegekeylist")
}

// ListTokens returns every token.
func (c *Client) ListTokens() ([]PrivilegeKey, error) {
	return c.listKeys("tokenlist")
}

// PrivilegeKeyOptions describe a key to create.
type PrivilegeKeyOptions struct {
	Description *string
	// ID1 is the group id for a server group, the channel id for a channel
	// group.
	ID1 uint64
	// ID2 is the channel id for a channel group, otherwise 0.
	ID2 uint64
	// Type is 0 for a server group, 1 for a channel group.
	Type int
}

func (c *Client) addKey(command string, opts PrivilegeKeyOptions) (string, error) {
	rows, err := c.query(command, []param{
		Int("tokentype", int64(opts.Type)),
		Uint("tokenid1", opts.ID1),
		Uint("tokenid2", opts.ID2),
		StrPtr("tokendescription", opts.Description),
	})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "token"), nil
}

// AddPrivilegeKey creates a privilege key and returns it as the server
// generated it.
func (c *Client) AddPrivilegeKey(opts PrivilegeKeyOptions) (string, error) {
	return c.addKey("privilegekeyadd", opts)
}

// AddToken creates a token and returns it as the server generated it.
func (c *Client) AddToken(opts PrivilegeKeyOptions) (string, error) {
	return c.addKey("tokenadd", opts)
}

// DeletePrivilegeKey removes a privilege key.
func (c *Client) DeletePrivilegeKey(token string) error {
	return c.exec("privilegekeydelete", []param{Str("token", token)})
}

// DeleteToken removes a token.
func (c *Client) DeleteToken(token string) error {
	return c.exec("tokendelete", []param{Str("token", token)})
}

// UsePrivilegeKey redeems a privilege key. The key grants only if this
// connection has not already used one.
func (c *Client) UsePrivilegeKey(token string) error {
	return c.exec("privilegekeyuse", []param{Str("token", token)})
}

// UseToken redeems a token.
func (c *Client) UseToken(token string) error {
	return c.exec("tokenuse", []param{Str("token", token)})
}
