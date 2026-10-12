package teamspeak

import (
	"context"
	"time"
)

// Channel groups, permissions, and the tokens used to join groups.

// ChannelGroup is a channel group as channelgrouplist reports it.
type ChannelGroup struct {
	Name              string
	ID                ChannelGroupID
	IconID            IconID
	SortID            uint64
	Type              GroupType
	NameMode          GroupNameMode
	ModifyPower       int32
	MemberAddPower    int32
	MemberRemovePower int32
	SavedInDatabase   bool
}

func parseChannelGroup(row map[string]string) ChannelGroup {
	return ChannelGroup{
		ID:                ChannelGroupID(fieldUint(row, "cgid")),
		Name:              fieldStr(row, "name"),
		Type:              GroupType(fieldInt(row, "type")),
		IconID:            fieldIconID(row, "iconid"),
		SavedInDatabase:   fieldBool(row, "savedb"),
		SortID:            fieldUint(row, "sortid"),
		NameMode:          GroupNameMode(fieldInt(row, "namemode")),
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
//
// groupType is sent rather than left to the server's default, which is
// GroupRegular: the zero GroupType is GroupTemplate, and a parameter that
// silently meant "regular" when omitted and "template" when zero would be a
// trap.
func (c *Commands) CreateChannelGroup(ctx context.Context, name string, groupType GroupType) (ChannelGroupID, error) {
	rows, err := c.query(ctx, "channelgroupadd", []param{
		strArg("name", name),
		intArg("type", int64(groupType)),
	})
	if err != nil {
		return 0, err
	}

	return createdGroupID[ChannelGroupID](rows, "cgid", name)
}

// DeleteChannelGroup deletes a channel group.
func (c *Commands) DeleteChannelGroup(ctx context.Context, channelGroupID ChannelGroupID, force bool) error {
	return c.exec(ctx, "channelgroupdel", []param{
		idArg("cgid", channelGroupID),
		boolArg("force", force),
	})
}

// RenameChannelGroup renames a channel group.
func (c *Commands) RenameChannelGroup(ctx context.Context, channelGroupID ChannelGroupID, name string) error {
	return c.exec(ctx, "channelgrouprename", []param{
		idArg("cgid", channelGroupID),
		strArg("name", name),
	})
}

// CopyChannelGroup copies a channel group; a targetGroupID of 0 allocates one.
func (c *Commands) CopyChannelGroup(
	ctx context.Context, sourceGroupID, targetGroupID ChannelGroupID, name string, groupType GroupType,
) (ChannelGroupID, error) {
	rows, err := c.query(ctx, "channelgroupcopy", []param{
		idArg("scgid", sourceGroupID),
		idArg("tcgid", targetGroupID),
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

	return createdGroupID[ChannelGroupID](rows, "cgid", name)
}

// ChannelGroupMembership is which channel group a client holds in a channel.
type ChannelGroupMembership struct {
	ChannelID  ChannelID
	DatabaseID ClientDBID
	GroupID    ChannelGroupID
}

// ListChannelGroupClients returns which channel group each client holds in
// which channel, filtered by channel, client and group. A 0 filter matches
// any; pass at least one, since called with none the server may return
// nothing.
func (c *Commands) ListChannelGroupClients(
	ctx context.Context, channelID ChannelID, clientDBID ClientDBID, channelGroupID ChannelGroupID,
) ([]ChannelGroupMembership, error) {
	rows, err := c.list(ctx, "channelgroupclientlist", []param{
		optIDArg("cid", channelID),
		optIDArg("cldbid", clientDBID),
		optIDArg("cgid", channelGroupID),
	})
	if err != nil {
		return nil, err
	}

	out := make([]ChannelGroupMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChannelGroupMembership{
			ChannelID:  ChannelID(fieldUint(row, "cid")),
			DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
			GroupID:    ChannelGroupID(fieldUint(row, "cgid")),
		})
	}

	return out, nil
}

// ListChannelGroupPermissions returns the permissions set on a channel group.
func (c *Commands) ListChannelGroupPermissions(
	ctx context.Context, channelGroupID ChannelGroupID,
) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelgrouppermlist", []param{idArg("cgid", channelGroupID)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// AddChannelGroupPermission sets a permission on a channel group.
func (c *Commands) AddChannelGroupPermission(
	ctx context.Context, channelGroupID ChannelGroupID, perm Permission, value int32,
) error {
	return c.exec(ctx, "channelgroupaddperm", []param{
		idArg("cgid", channelGroupID),
		permArg(perm),
		intArg("permvalue", int64(value)),
	})
}

// DeleteChannelGroupPermission removes a permission from a channel group.
func (c *Commands) DeleteChannelGroupPermission(
	ctx context.Context, channelGroupID ChannelGroupID, perm Permission,
) error {
	return c.exec(ctx, "channelgroupdelperm", []param{
		idArg("cgid", channelGroupID),
		permArg(perm),
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
func (c *Commands) GetPermissionIDByName(ctx context.Context, name string) (PermissionID, bool, error) {
	rows, err := c.query(ctx, "permidgetbyname", []param{strArg("permsid", name)})
	if err != nil {
		return 0, false, err
	}

	if len(rows) == 0 {
		return 0, false, nil
	}

	return PermissionID(fieldUint32(rows[0], "permid")), true, nil
}

// PermissionLocation is one place a permission is set, as permfind reports it.
//
// What ID1 and ID2 name depends on Target — a group, a client, a channel, or
// a channel and a client for a channel client permission — which is why they
// stay raw numbers rather than typed ids.
type PermissionLocation struct {
	ID1        uint64
	ID2        uint64
	Permission PermissionID
	Target     PermissionTarget
}

// FindPermission returns every place a permission is set.
func (c *Commands) FindPermission(ctx context.Context, perm Permission) ([]PermissionLocation, error) {
	rows, err := c.list(ctx, "permfind", []param{permArg(perm)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionLocation, 0, len(rows))
	for _, row := range rows {
		out = append(out, PermissionLocation{
			Target:     PermissionTarget(fieldInt(row, "t")),
			ID1:        fieldUint(row, "id1"),
			ID2:        fieldUint(row, "id2"),
			Permission: PermissionID(fieldUint32(row, "p")),
		})
	}

	return out, nil
}

// GetPermissionOverview returns every permission that applies to a client in a
// channel, from every source, unfiltered.
//
// It always asks for all of them (permid=0): the server requires a permission
// parameter and treats 0 as "all", while the zero Permission is refused
// everywhere else, so taking one here would make the useful call impossible.
// Each row names its permission (p), so one is easy to pick out.
func (c *Commands) GetPermissionOverview(
	ctx context.Context, channelID ChannelID, clientDBID ClientDBID,
) ([]map[string]string, error) {
	return c.query(ctx, "permoverview", []param{
		idArg("cid", channelID),
		idArg("cldbid", clientDBID),
		uintArg("permid", 0),
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
	CreatedAt   time.Time
	Token       string
	Description string
	// ServerGroupID is the group a TokenServerGroup key grants.
	ServerGroupID ServerGroupID
	// ChannelGroupID and ChannelID are the group a TokenChannelGroup key
	// grants and the channel it grants it in.
	ChannelGroupID ChannelGroupID
	ChannelID      ChannelID
	Type           TokenType
}

// parseKey reads a key. The wire carries the group as token_id1 and the
// channel as token_id2, whichever kind of group it is; which typed field the
// id belongs in depends on the token type.
func parseKey(row map[string]string) PrivilegeKey {
	key := PrivilegeKey{
		Token:       fieldStr(row, "token"),
		Type:        TokenType(fieldInt(row, "token_type")),
		Description: fieldStr(row, "token_description"),
		CreatedAt:   fieldTime(row, "token_created"),
	}
	if key.Type == TokenChannelGroup {
		key.ChannelGroupID = ChannelGroupID(fieldUint(row, "token_id1"))
		key.ChannelID = ChannelID(fieldUint(row, "token_id2"))
	} else {
		key.ServerGroupID = ServerGroupID(fieldUint(row, "token_id1"))
	}

	return key
}

func (c *Commands) listKeys(ctx context.Context, command string) ([]PrivilegeKey, error) {
	rows, err := c.list(ctx, command, nil)
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

// PrivilegeKeyOptions describe a key to create: set ServerGroupID for a key
// that grants a server group, or ChannelGroupID and ChannelID for one that
// grants a channel group in a channel. Anything else is refused with
// ErrInvalidCommand.
type PrivilegeKeyOptions struct {
	// Description is shown in the key list; "" sends none.
	Description    string
	ServerGroupID  ServerGroupID
	ChannelGroupID ChannelGroupID
	ChannelID      ChannelID
}

// keyParams encodes the group a key grants. The wire form is a type and two
// untyped ids whose meaning depends on it — the old options took them as such,
// and documented the first wrongly as a channel id — so the typed fields are
// checked to describe exactly one kind of key.
func (opts PrivilegeKeyOptions) keyParams() []param {
	serverGroup := opts.ServerGroupID != 0
	channelGroup := opts.ChannelGroupID != 0 || opts.ChannelID != 0
	switch {
	case serverGroup && !channelGroup:
		return []param{
			intArg("tokentype", int64(TokenServerGroup)),
			idArg("tokenid1", opts.ServerGroupID),
			uintArg("tokenid2", 0),
		}
	case channelGroup && !serverGroup && opts.ChannelGroupID != 0 && opts.ChannelID != 0:
		return []param{
			intArg("tokentype", int64(TokenChannelGroup)),
			idArg("tokenid1", opts.ChannelGroupID),
			idArg("tokenid2", opts.ChannelID),
		}
	default:
		return []param{invalidArg("a key grants a server group, or a channel group in a channel")}
	}
}

func (c *Commands) addKey(ctx context.Context, command string, opts PrivilegeKeyOptions) (string, error) {
	rows, err := c.query(ctx, command, append(opts.keyParams(),
		optStrArg("tokendescription", opts.Description)))
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
