package teamspeak

import (
	"context"
	"strconv"
)

// The permission batches: each sets or removes several permissions of one
// target in one command, as the server takes them, a row per permission.
//
// What every one of them measured, on TeamSpeak 3 3.13.8 and 6 beta13.1 over
// raw ServerQuery, SSH, WebQuery and the voice protocol alike: the server
// checks the permission and value of every row before it applies any. A
// permission it does not know (2562),
// a value it cannot read (1540) or a row missing a key (1539) refuses the
// command and nothing is applied, with ContinueOnError or without; the two
// answered the same wherever it was tried. A permission removed that was not
// set is not an error. The server answers one status for the command and none
// per permission, so the result is an error and nothing more.
//
// An error found while applying is another matter, and there the rows are
// applied in order. Measured on TeamSpeak 3 3.13.8 and 6 beta13.1 for every
// batch but the by-type ones, over raw ServerQuery (TeamSpeak 3), SSH,
// WebQuery and the voice protocol, with one permission locked by an
// i_needed_modify_power_* of the caller's group above the caller's power (2570,
// "insufficient permission modify power") and one free: the answer is that
// error in every case, and without ContinueOnError the first row that fails
// ends the command, so the rows before it are applied and the rows after it
// are not. With ContinueOnError the rows that fail are skipped and the others
// applied. Only the command's own error is returned, never which row it was
// about. Only one row failed in each case measured, so which error is returned
// when several fail is not known for these commands. The flag does nothing on
// DeleteChannelPermissions, DeleteChannelClientPermissions and
// DeleteClientPermissions, whose commands the server documents without it. The
// by-type batches need an instance permission no ordinary account holds, so
// the case could not be reached for them.
//
// Rows may name a permission by id in one row and by name in the next
// (measured on TeamSpeak 3 over raw ServerQuery).

// PermissionBatchOptions are the optional parameters of the permission batches
// whose command takes -continueonerror.
type PermissionBatchOptions struct {
	// ContinueOnError sends -continueonerror, which the server's documentation
	// lists for the command: a row that fails for want of permission modify
	// power is skipped and the ones after it are applied. See the notes on the
	// permission batches for what was measured.
	ContinueOnError bool
}

// permissionRow is one row of a batch: the permission by name or id.
func permissionRow(perm Permission) ([2]string, bool) {
	switch {
	case perm.name != "":
		return [2]string{"permsid", perm.name}, true
	case perm.id != 0:
		return [2]string{"permid", strconv.FormatUint(uint64(perm.id), 10)}, true
	default:
		return [2]string{}, false
	}
}

// permissionTable encodes entries as rows of permission, value and the flags
// the command takes. An entry that sets a flag the command does not take is
// refused, rather than sent without it: the entry would mean something the
// server never did.
func permissionTable(entries []PermissionEntry, takesNegated, takesSkip bool) param {
	rows := make([][][2]string, 0, len(entries))
	for _, entry := range entries {
		perm, ok := permissionRow(entry.Permission)
		switch {
		case !ok:
			return invalidArg("no permission given")
		case entry.Negated && !takesNegated:
			return invalidArg("this command takes no negated flag, and " + perm[1] + " sets one")
		case entry.Skip && !takesSkip:
			return invalidArg("this command takes no skip flag, and " + perm[1] + " sets one")
		}

		row := [][2]string{perm, {"permvalue", strconv.FormatInt(int64(entry.Value), 10)}}
		if takesNegated {
			row = append(row, [2]string{"permnegated", boolText(entry.Negated)})
		}
		if takesSkip {
			row = append(row, [2]string{"permskip", boolText(entry.Skip)})
		}
		rows = append(rows, row)
	}

	return tableArg(rows)
}

// permissionNames encodes perms as rows of the permission alone.
func permissionNames(perms []Permission) param {
	rows := make([][][2]string, 0, len(perms))
	for _, perm := range perms {
		row, ok := permissionRow(perm)
		if !ok {
			return invalidArg("no permission given")
		}
		rows = append(rows, [][2]string{row})
	}

	return tableArg(rows)
}

func boolText(on bool) string {
	if on {
		return "1"
	}

	return "0"
}

// AddChannelPermissions sets several permissions on a channel in one command
// (channeladdperm). Only Permission and Value of an entry are sent; one that
// sets Negated or Skip is refused with ErrInvalidCommand, as the command takes
// neither. Setting none sends nothing.
func (c *Commands) AddChannelPermissions(
	ctx context.Context, cid ChannelID, perms []PermissionEntry, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channeladdperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cid", cid),
		permissionTable(perms, false, false),
	})
}

// DeleteChannelPermissions removes several permissions from a channel in one
// command (channeldelperm), which the server documents without
// -continueonerror, so there is no option. Removing none sends nothing.
func (c *Commands) DeleteChannelPermissions(ctx context.Context, cid ChannelID, perms []Permission) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channeldelperm", []param{
		idArg("cid", cid),
		permissionNames(perms),
	})
}

// AddChannelGroupPermissions sets several permissions on a channel group in
// one command (channelgroupaddperm). Only Permission and Value of an entry are
// sent; one that sets Negated or Skip is refused with ErrInvalidCommand.
// Setting none sends nothing.
func (c *Commands) AddChannelGroupPermissions(
	ctx context.Context, channelGroupID ChannelGroupID, perms []PermissionEntry, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channelgroupaddperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cgid", channelGroupID),
		permissionTable(perms, false, false),
	})
}

// DeleteChannelGroupPermissions removes several permissions from a channel
// group in one command (channelgroupdelperm). Removing none sends nothing.
func (c *Commands) DeleteChannelGroupPermissions(
	ctx context.Context, channelGroupID ChannelGroupID, perms []Permission, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channelgroupdelperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cgid", channelGroupID),
		permissionNames(perms),
	})
}

// AddChannelClientPermissions sets several permissions on one client in one
// channel in one command (channelclientaddperm). Only Permission and Value of
// an entry are sent; one that sets Negated or Skip is refused with
// ErrInvalidCommand. Setting none sends nothing.
func (c *Commands) AddChannelClientPermissions(
	ctx context.Context, cid ChannelID, clientDBID ClientDBID, perms []PermissionEntry, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channelclientaddperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cid", cid),
		idArg("cldbid", clientDBID),
		permissionTable(perms, false, false),
	})
}

// DeleteChannelClientPermissions removes several permissions from one client
// in one channel in one command (channelclientdelperm), which the server
// documents without -continueonerror, so there is no option. Removing none
// sends nothing.
func (c *Commands) DeleteChannelClientPermissions(
	ctx context.Context, cid ChannelID, clientDBID ClientDBID, perms []Permission,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "channelclientdelperm", []param{
		idArg("cid", cid),
		idArg("cldbid", clientDBID),
		permissionNames(perms),
	})
}

// AddClientPermissions sets several permissions on a client, server-wide, in
// one command (clientaddperm). Each entry's Skip is sent; one that sets
// Negated is refused with ErrInvalidCommand, as the command takes no such
// flag. Setting none sends nothing.
func (c *Commands) AddClientPermissions(
	ctx context.Context, clientDBID ClientDBID, perms []PermissionEntry, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "clientaddperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("cldbid", clientDBID),
		permissionTable(perms, false, true),
	})
}

// DeleteClientPermissions removes several permissions from a client in one
// command (clientdelperm), which the server documents without
// -continueonerror, so there is no option. Removing none sends nothing.
func (c *Commands) DeleteClientPermissions(ctx context.Context, clientDBID ClientDBID, perms []Permission) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "clientdelperm", []param{
		idArg("cldbid", clientDBID),
		permissionNames(perms),
	})
}

// AddServerGroupPermissions sets several permissions on a server group in one
// command (servergroupaddperm); every field of an entry is sent. Setting none
// sends nothing.
func (c *Commands) AddServerGroupPermissions(
	ctx context.Context, serverGroupID ServerGroupID, perms []PermissionEntry, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupaddperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("sgid", serverGroupID),
		permissionTable(perms, true, true),
	})
}

// DeleteServerGroupPermissions removes several permissions from a server group
// in one command (servergroupdelperm). Removing none sends nothing.
func (c *Commands) DeleteServerGroupPermissions(
	ctx context.Context, serverGroupID ServerGroupID, perms []Permission, opts PermissionBatchOptions,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupdelperm", []param{
		continueOnErrorArg(opts.ContinueOnError),
		idArg("sgid", serverGroupID),
		permissionNames(perms),
	})
}

// AddServerGroupPermissionsByType sets several permissions on every regular
// server group of one kind, on every virtual server of the instance, in one
// command (servergroupautoaddperm), which the server documents without
// -continueonerror, so there is no option. Every field of an entry is sent. It
// needs what AddServerGroupPermissionByType needs. Setting none sends nothing.
func (c *Commands) AddServerGroupPermissionsByType(
	ctx context.Context, groups GroupAutoUpdateType, perms []PermissionEntry,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupautoaddperm", []param{
		intArg("sgtype", int64(groups)),
		permissionTable(perms, true, true),
	})
}

// DeleteServerGroupPermissionsByType removes several permissions from every
// regular server group of one kind, on every virtual server of the instance, in
// one command (servergroupautodelperm). Removing none sends nothing.
func (c *Commands) DeleteServerGroupPermissionsByType(
	ctx context.Context, groups GroupAutoUpdateType, perms []Permission,
) error {
	if len(perms) == 0 {
		return nil
	}

	return c.exec(ctx, "servergroupautodelperm", []param{
		intArg("sgtype", int64(groups)),
		permissionNames(perms),
	})
}
