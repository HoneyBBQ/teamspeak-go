package teamspeak

import "context"

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
func (c *Commands) ListChannelGroups(ctx context.Context) ([]ChannelGroup, error) {
	rows, err := c.query(ctx, "channelgrouplist", nil)
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
func (c *Commands) CreateChannelGroup(ctx context.Context, name string, groupType *int) (uint64, error) {
	params := []param{strArg("name", name)}
	if groupType != nil {
		params = append(params, intArg("type", int64(*groupType)))
	}

	rows, err := c.query(ctx, "channelgroupadd", params)
	if err != nil {
		return 0, err
	}

	return createdGroupID(rows, "cgid", name)
}

// DeleteChannelGroup deletes a channel group.
func (c *Commands) DeleteChannelGroup(ctx context.Context, channelGroupID uint64, force bool) error {
	return c.exec(ctx, "channelgroupdel", []param{
		uintArg("cgid", channelGroupID),
		boolArg("force", force),
	})
}

// RenameChannelGroup renames a channel group.
func (c *Commands) RenameChannelGroup(ctx context.Context, channelGroupID uint64, name string) error {
	return c.exec(ctx, "channelgrouprename", []param{
		uintArg("cgid", channelGroupID),
		strArg("name", name),
	})
}

// CopyChannelGroup copies a channel group; a targetGroupID of 0 allocates one.
func (c *Commands) CopyChannelGroup(
	ctx context.Context, sourceGroupID, targetGroupID uint64, name string, groupType int,
) (uint64, error) {
	rows, err := c.query(ctx, "channelgroupcopy", []param{
		uintArg("scgid", sourceGroupID),
		uintArg("tcgid", targetGroupID),
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
func (c *Commands) ListChannelGroupClients(
	ctx context.Context, channelID, clientDBID, channelGroupID *uint64,
) ([]ChannelGroupMembership, error) {
	rows, err := c.query(ctx, "channelgroupclientlist", []param{
		uintPtrArg("cid", channelID),
		uintPtrArg("cldbid", clientDBID),
		uintPtrArg("cgid", channelGroupID),
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
func (c *Commands) ListChannelGroupPermissions(ctx context.Context, channelGroupID uint64) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelgrouppermlist", []param{uintArg("cgid", channelGroupID)})
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
func (c *Commands) AddChannelGroupPermission(
	ctx context.Context, channelGroupID uint64, permValue int32, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "channelgroupaddperm", []param{
		uintArg("cgid", channelGroupID),
		intArg("permvalue", int64(permValue)),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// DeleteChannelGroupPermission removes a permission from a channel group.
func (c *Commands) DeleteChannelGroupPermission(
	ctx context.Context, channelGroupID uint64, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "channelgroupdelperm", []param{
		uintArg("cgid", channelGroupID),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// ---- Permissions ------------------------------------------------------------

// ListPermissions returns the server's full permission catalogue.
func (c *Commands) ListPermissions(ctx context.Context) ([]map[string]string, error) {
	return c.query(ctx, "permissionlist", nil)
}

// GetPermissionIDByName resolves a permission name to its numeric id. The
// second return value is false when the server knows no such permission.
//
// Needs an instance-level permission (b_serverinstance_*), which not even the
// Server Admin group holds by default — expect error 2568 until it is granted.
// Granted, it works over the voice protocol like any other query.
func (c *Commands) GetPermissionIDByName(ctx context.Context, permSID string) (uint64, bool, error) {
	rows, err := c.query(ctx, "permidgetbyname", []param{strArg("permsid", permSID)})
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
func (c *Commands) FindPermission(ctx context.Context, permID *uint64, permSID *string) ([]PermissionLocation, error) {
	rows, err := c.query(ctx, "permfind", []param{
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
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
func (c *Commands) GetPermissionOverview(
	ctx context.Context, channelID, clientDBID uint64, permID *uint64, permSID *string,
) ([]map[string]string, error) {
	return c.query(ctx, "permoverview", []param{
		uintArg("cid", channelID),
		uintArg("cldbid", clientDBID),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// ResetPermissions wipes all permission overrides and restores the defaults.
//
// Destructive: every custom permission on the server goes, including the
// caller's own rights, because it resets the group they rely on.
func (c *Commands) ResetPermissions(ctx context.Context) error {
	return c.exec(ctx, "permreset", nil)
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

func (c *Commands) listKeys(ctx context.Context, command string) ([]PrivilegeKey, error) {
	rows, err := c.query(ctx, command, nil)
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
func (c *Commands) ListPrivilegeKeys(ctx context.Context) ([]PrivilegeKey, error) {
	return c.listKeys(ctx, "privilegekeylist")
}

// ListTokens returns every token.
func (c *Commands) ListTokens(ctx context.Context) ([]PrivilegeKey, error) {
	return c.listKeys(ctx, "tokenlist")
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

func (c *Commands) addKey(ctx context.Context, command string, opts PrivilegeKeyOptions) (string, error) {
	rows, err := c.query(ctx, command, []param{
		intArg("tokentype", int64(opts.Type)),
		uintArg("tokenid1", opts.ID1),
		uintArg("tokenid2", opts.ID2),
		strPtrArg("tokendescription", opts.Description),
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
func (c *Commands) AddPrivilegeKey(ctx context.Context, opts PrivilegeKeyOptions) (string, error) {
	return c.addKey(ctx, "privilegekeyadd", opts)
}

// AddToken creates a token and returns it as the server generated it.
func (c *Commands) AddToken(ctx context.Context, opts PrivilegeKeyOptions) (string, error) {
	return c.addKey(ctx, "tokenadd", opts)
}

// DeletePrivilegeKey removes a privilege key.
func (c *Commands) DeletePrivilegeKey(ctx context.Context, token string) error {
	return c.exec(ctx, "privilegekeydelete", []param{strArg("token", token)})
}

// DeleteToken removes a token.
func (c *Commands) DeleteToken(ctx context.Context, token string) error {
	return c.exec(ctx, "tokendelete", []param{strArg("token", token)})
}

// UsePrivilegeKey redeems a privilege key. The key grants only if this
// connection has not already used one.
func (c *Commands) UsePrivilegeKey(ctx context.Context, token string) error {
	return c.exec(ctx, "privilegekeyuse", []param{strArg("token", token)})
}

// UseToken redeems a token.
func (c *Commands) UseToken(ctx context.Context, token string) error {
	return c.exec(ctx, "tokenuse", []param{strArg("token", token)})
}
