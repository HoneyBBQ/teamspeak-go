package teamspeak

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Channel groups, permissions, and the tokens used to join groups.

// ChannelGroup is a channel group as channelgrouplist reports it.
type ChannelGroup struct {
	Name              string
	ID                ChannelGroupID
	IconID            IconID
	SortID            int32
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
		SortID:            fieldInt32(row, "sortid"),
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

// GroupDeleteOptions are DeleteServerGroup's and DeleteChannelGroup's
// optional parameters.
type GroupDeleteOptions struct {
	// Force deletes a group that still has members, which the server
	// otherwise refuses.
	Force bool
}

// DeleteChannelGroup deletes a channel group.
func (c *Commands) DeleteChannelGroup(
	ctx context.Context, channelGroupID ChannelGroupID, opts GroupDeleteOptions,
) error {
	return c.exec(ctx, "channelgroupdel", []param{
		idArg("cgid", channelGroupID),
		boolArg("force", opts.Force),
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

// ChannelGroupClientListOptions filter ListChannelGroupClients. A 0 field
// matches any; set at least one, since called with none the server may return
// nothing.
type ChannelGroupClientListOptions struct {
	// ChannelID keeps only memberships in this channel (cid).
	ChannelID ChannelID
	// DatabaseID keeps only this client's memberships (cldbid).
	DatabaseID ClientDBID
	// GroupID keeps only memberships of this group (cgid).
	GroupID ChannelGroupID
}

// ListChannelGroupClients returns which channel group each client holds in
// which channel, filtered as opts says.
func (c *Commands) ListChannelGroupClients(
	ctx context.Context, opts ChannelGroupClientListOptions,
) ([]ChannelGroupMembership, error) {
	rows, err := c.list(ctx, "channelgroupclientlist", []param{
		optIDArg("cid", opts.ChannelID),
		optIDArg("cldbid", opts.DatabaseID),
		optIDArg("cgid", opts.GroupID),
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

// PermissionInfo is one permission of the server's catalogue.
type PermissionInfo struct {
	// Name is the permission's name, such as "i_client_talk_power" (permname).
	Name string
	// Description is what the permission controls (permdesc).
	Description string
	// ID is the permission's id on this server build (permid).
	ID PermissionID
}

// ListPermissions returns the server's full permission catalogue. Rows that
// name no permission — the group markers some servers interleave — are left
// out.
func (c *Commands) ListPermissions(ctx context.Context) ([]PermissionInfo, error) {
	rows, err := c.query(ctx, "permissionlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]PermissionInfo, 0, len(rows))
	for _, row := range rows {
		name, ok := row["permname"]
		if !ok {
			continue
		}
		out = append(out, PermissionInfo{
			ID:          PermissionID(fieldUint32(row, "permid")),
			Name:        name,
			Description: fieldStr(row, "permdesc"),
		})
	}

	return out, nil
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

// PermissionLocation is one place a permission is set, as permfind and
// permoverview report it. Target says which of the ids are set:
//
//   - PermissionTargetServerGroup: ServerGroupID
//   - PermissionTargetClient: ClientDBID
//   - PermissionTargetChannel: ChannelID
//   - PermissionTargetChannelGroup: ChannelID and ChannelGroupID
//   - PermissionTargetChannelClient: ChannelID and ClientDBID
//
// The others are 0. A row whose target is none of these is left out of the
// results.
type PermissionLocation struct {
	ServerGroupID  ServerGroupID
	ClientDBID     ClientDBID
	ChannelID      ChannelID
	ChannelGroupID ChannelGroupID
	Permission     PermissionID
	Target         PermissionTarget
}

// parseLocation reads a location from the wire's t, id1 and id2, whose
// meaning depends on t. It reports false for a target it does not know.
func parseLocation(row map[string]string) (PermissionLocation, bool) {
	loc := PermissionLocation{
		Target:     PermissionTarget(fieldInt(row, "t")),
		Permission: PermissionID(fieldUint32(row, "p")),
	}
	id1, id2 := fieldUint(row, "id1"), fieldUint(row, "id2")
	switch loc.Target {
	case PermissionTargetServerGroup:
		loc.ServerGroupID = ServerGroupID(id1)
	case PermissionTargetClient:
		loc.ClientDBID = ClientDBID(id1)
	case PermissionTargetChannel:
		loc.ChannelID = ChannelID(id1)
	case PermissionTargetChannelGroup:
		loc.ChannelID = ChannelID(id1)
		loc.ChannelGroupID = ChannelGroupID(id2)
	case PermissionTargetChannelClient:
		loc.ChannelID = ChannelID(id1)
		loc.ClientDBID = ClientDBID(id2)
	default:
		return PermissionLocation{}, false
	}

	return loc, true
}

// FindPermission returns every place a permission is set.
func (c *Commands) FindPermission(ctx context.Context, perm Permission) ([]PermissionLocation, error) {
	rows, err := c.list(ctx, "permfind", []param{permArg(perm)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionLocation, 0, len(rows))
	for _, row := range rows {
		if loc, ok := parseLocation(row); ok {
			out = append(out, loc)
		}
	}

	return out, nil
}

// PermissionOverviewEntry is one permission applying to a client in a
// channel, and where it is set, as permoverview reports it.
type PermissionOverviewEntry struct {
	PermissionLocation

	// Value is the permission's value there (v).
	Value int32
	// Negated reports a negated value (n).
	Negated bool
	// Skip reports a value that skips channel and client overrides (s).
	Skip bool
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
) ([]PermissionOverviewEntry, error) {
	rows, err := c.list(ctx, "permoverview", []param{
		idArg("cid", channelID),
		idArg("cldbid", clientDBID),
		uintArg("permid", 0),
	})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionOverviewEntry, 0, len(rows))
	for _, row := range rows {
		loc, ok := parseLocation(row)
		if !ok {
			continue
		}
		out = append(out, PermissionOverviewEntry{
			PermissionLocation: loc,
			Value:              fieldInt32(row, "v"),
			Negated:            fieldBool(row, "n"),
			Skip:               fieldBool(row, "s"),
		})
	}

	return out, nil
}

// ResetPermissions wipes all permission overrides and restores the defaults.
//
// Destructive: every custom permission on the server goes, including the
// caller's own rights, because it resets the group they rely on.
func (c *Commands) ResetPermissions(ctx context.Context) error {
	return c.exec(ctx, "permreset", nil)
}

// ---- Tokens and privilege keys ----------------------------------------------

// PrivilegeKey grants a group when redeemed. The server also calls it a
// token.
//
// String, GoString and LogValue redact the token, so the value can reach fmt
// and log/slog safely. encoding/json does not: the token is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type PrivilegeKey struct {
	CreatedAt   time.Time
	Token       string
	Description string
	// ServerGroupID is the group a PrivilegeKeyServerGroup key grants.
	ServerGroupID ServerGroupID
	// ChannelGroupID and ChannelID are the group a PrivilegeKeyChannelGroup key
	// grants and the channel it grants it in.
	ChannelGroupID ChannelGroupID
	ChannelID      ChannelID
	Type           PrivilegeKeyType
}

// parseKey reads a key. The wire carries the group as token_id1 and the
// channel as token_id2, whichever kind of group it is; which typed field the
// id belongs in depends on the token type.
func parseKey(row map[string]string) PrivilegeKey {
	key := PrivilegeKey{
		Token:       fieldStr(row, "token"),
		Type:        PrivilegeKeyType(fieldInt(row, "token_type")),
		Description: fieldStr(row, "token_description"),
		CreatedAt:   fieldTime(row, "token_created"),
	}
	if key.Type == PrivilegeKeyChannelGroup {
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
			intArg("tokentype", int64(PrivilegeKeyServerGroup)),
			idArg("tokenid1", opts.ServerGroupID),
			uintArg("tokenid2", 0),
		}
	case channelGroup && !serverGroup && opts.ChannelGroupID != 0 && opts.ChannelID != 0:
		return []param{
			intArg("tokentype", int64(PrivilegeKeyChannelGroup)),
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

// DeletePrivilegeKey removes a privilege key.
func (c *Commands) DeletePrivilegeKey(ctx context.Context, token string) error {
	return c.exec(ctx, "privilegekeydelete", []param{strArg("token", token)})
}

// UsePrivilegeKey redeems a privilege key. The key grants only if this
// connection has not already used one.
func (c *Commands) UsePrivilegeKey(ctx context.Context, token string) error {
	return c.exec(ctx, "privilegekeyuse", []param{strArg("token", token)})
}

// String describes the key without the token itself, which grants the group
// to whoever redeems it.
func (k PrivilegeKey) String() string {
	return fmt.Sprintf("{Type:%v ServerGroupID:%d ChannelGroupID:%d ChannelID:%d Description:%q Token:redacted}",
		k.Type, k.ServerGroupID, k.ChannelGroupID, k.ChannelID, k.Description)
}

// GoString is String, so %#v redacts too.
func (k PrivilegeKey) GoString() string { return k.String() }

// LogValue describes the key to log/slog without the token, so the JSON
// handler, which would otherwise marshal the fields, redacts too.
func (k PrivilegeKey) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", k.Type.String()),
		slog.Uint64("server_group_id", uint64(k.ServerGroupID)),
		slog.Uint64("channel_group_id", uint64(k.ChannelGroupID)),
		slog.Uint64("channel_id", uint64(k.ChannelID)),
		slog.String("description", k.Description),
		slog.String("token", "redacted"),
	)
}
