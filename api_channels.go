package teamspeak

import (
	"context"
	"math"
	"time"
)

// Channel commands.
//
// Channel settings are a wide, mostly-optional set, so the options structs use
// the names the server uses (ChannelCodec, ChannelTopic) rather than inventing
// shorter aliases: the wire name is what you find in the server documentation
// and in channelinfo output, and a second vocabulary would be one more thing to
// translate.

// Channel is a channel as channellist or channelinfo reports it.
type Channel struct {
	UniqueIdentifier string
	Name             string
	Topic            string
	Description      string
	ID               ChannelID
	// ParentID is the channel this one sits under, or 0 at the top level.
	//
	// channellist names this cpid and channelinfo names it pid — the same value
	// under two keys, which is why both are read.
	ParentID ChannelID
	// Order is the channel this one is sorted after, among its siblings, or 0
	// for the first: channel_order is a channel id, not a position.
	Order           ChannelID
	IconID          IconID
	Codec           Codec
	CodecQuality    int32
	MaxClients      int32
	NeededTalkPower int32
	IsDefault       bool
	IsPermanent     bool
	HasPassword     bool
}

func parseChannel(row map[string]string) Channel {
	parent := fieldUint(row, "pid")
	if parent == 0 {
		parent = fieldUint(row, "cpid")
	}

	return Channel{
		ID:               ChannelID(fieldUint(row, "cid")),
		ParentID:         ChannelID(parent),
		Name:             fieldStr(row, "channel_name"),
		Topic:            fieldStr(row, "channel_topic"),
		Description:      fieldStr(row, "channel_description"),
		Order:            ChannelID(fieldUint(row, "channel_order")),
		HasPassword:      fieldBool(row, "channel_flag_password"),
		IsDefault:        fieldBool(row, "channel_flag_default"),
		IsPermanent:      fieldBool(row, "channel_flag_permanent"),
		Codec:            Codec(min(fieldUint(row, "channel_codec"), math.MaxUint8)),
		CodecQuality:     fieldInt32(row, "channel_codec_quality"),
		MaxClients:       fieldInt32(row, "channel_maxclients"),
		NeededTalkPower:  fieldInt32(row, "channel_needed_talk_power"),
		IconID:           fieldIconID(row, "channel_icon_id"),
		UniqueIdentifier: fieldStr(row, "channel_unique_identifier"),
	}
}

// ChannelCreateOptions are the parameters for channelcreate.
//
// Only ChannelName is required. A nil pointer omits the parameter entirely,
// which is not the same as sending an empty value: clearing a password takes
// `channel_password=`, while leaving it alone takes no parameter at all.
// Build one with new: ChannelTopic: new("the quiet one").
type ChannelCreateOptions struct {
	// ChannelOrder is the channel to sort the new one after; 0 sorts it first.
	ChannelOrder *ChannelID
	// ChannelDeleteDelay is how long a temporary channel survives its last
	// client leaving. Sent in whole seconds.
	ChannelDeleteDelay       *time.Duration
	ChannelCodec             *Codec
	ChannelCodecQuality      *int32
	ChannelMaxClients        *int32
	ChannelMaxFamilyClients  *int32
	ChannelFlagPassword      *bool
	ChannelFlagPermanent     *bool
	ChannelFlagSemiPermanent *bool
	ChannelFlagDefault       *bool
	ChannelTopic             *string
	ChannelDescription       *string
	ChannelPassword          *string
	ChannelNamePhonetic      *string

	ChannelName string
	// ParentID is the channel to create the new one under; 0 is the top level.
	ParentID ChannelID
}

// CreateChannel creates a channel and returns the id the server assigned.
func (c *Commands) CreateChannel(ctx context.Context, opts ChannelCreateOptions) (ChannelID, error) {
	params := []param{
		strArg("channel_name", opts.ChannelName),
		optIDArg("cpid", opts.ParentID),
		strPtrArg("channel_topic", opts.ChannelTopic),
		strPtrArg("channel_description", opts.ChannelDescription),
		strPtrArg("channel_password", opts.ChannelPassword),
		uintPtrArg("channel_codec", opts.ChannelCodec),
		int32PtrArg("channel_codec_quality", opts.ChannelCodecQuality),
		int32PtrArg("channel_maxclients", opts.ChannelMaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		uintPtrArg("channel_order", opts.ChannelOrder),
		boolPtrArg("channel_flag_password", opts.ChannelFlagPassword),
		boolPtrArg("channel_flag_permanent", opts.ChannelFlagPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		boolPtrArg("channel_flag_default", opts.ChannelFlagDefault),
		durationPtrArg("channel_delete_delay", opts.ChannelDeleteDelay, time.Second),
		strPtrArg("channel_name_phonetic", opts.ChannelNamePhonetic),
	}

	rows, err := c.query(ctx, "channelcreate", params, "channel_password")
	if err != nil {
		return 0, err
	}

	return ChannelID(firstOrEmpty(rows, "cid")), nil
}

// ChannelEditOptions are the parameters for channeledit. Only the fields you
// set are sent; as with ChannelCreateOptions, a nil pointer leaves a setting
// alone and a pointer to the zero value clears it.
type ChannelEditOptions struct {
	ChannelName        *string
	ChannelTopic       *string
	ChannelDescription *string
	ChannelPassword    *string
	// ChannelOrder is the channel to sort this one after; 0 sorts it first.
	ChannelOrder             *ChannelID
	ChannelCodec             *Codec
	ChannelCodecQuality      *int32
	ChannelMaxClients        *int32
	ChannelMaxFamilyClients  *int32
	ChannelNeededTalkPower   *int32
	ChannelFlagPassword      *bool
	ChannelFlagPermanent     *bool
	ChannelFlagSemiPermanent *bool
	ChannelFlagDefault       *bool
	// ChannelDeleteDelay is sent in whole seconds.
	ChannelDeleteDelay  *time.Duration
	ChannelNamePhonetic *string
}

// EditChannel changes a channel's settings.
func (c *Commands) EditChannel(ctx context.Context, cid ChannelID, opts ChannelEditOptions) error {
	return c.exec(ctx, "channeledit", []param{
		idArg("cid", cid),
		strPtrArg("channel_name", opts.ChannelName),
		strPtrArg("channel_topic", opts.ChannelTopic),
		strPtrArg("channel_description", opts.ChannelDescription),
		strPtrArg("channel_password", opts.ChannelPassword),
		uintPtrArg("channel_order", opts.ChannelOrder),
		uintPtrArg("channel_codec", opts.ChannelCodec),
		int32PtrArg("channel_codec_quality", opts.ChannelCodecQuality),
		int32PtrArg("channel_maxclients", opts.ChannelMaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		int32PtrArg("channel_needed_talk_power", opts.ChannelNeededTalkPower),
		boolPtrArg("channel_flag_password", opts.ChannelFlagPassword),
		boolPtrArg("channel_flag_permanent", opts.ChannelFlagPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		boolPtrArg("channel_flag_default", opts.ChannelFlagDefault),
		durationPtrArg("channel_delete_delay", opts.ChannelDeleteDelay, time.Second),
		strPtrArg("channel_name_phonetic", opts.ChannelNamePhonetic),
	}, "channel_password")
}

// DeleteChannel deletes a channel.
//
// force is required by the server, not just conventional: deleting a channel
// that still holds clients fails without it.
func (c *Commands) DeleteChannel(ctx context.Context, cid ChannelID, force bool) error {
	return c.exec(ctx, "channeldelete", []param{
		idArg("cid", cid),
		boolArg("force", force),
	})
}

// ListChannels returns every channel on the server, in the server's sort order.
func (c *Commands) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := c.query(ctx, "channellist", nil)
	if err != nil {
		return nil, err
	}

	channels := make([]Channel, 0, len(rows))
	for _, row := range rows {
		channels = append(channels, parseChannel(row))
	}

	return channels, nil
}

// GetChannelInfo returns one channel's full settings.
//
// channelinfo answers with pid and the settings but no cid — the channel is
// whatever was asked for — so the id is filled in from the argument rather than
// read from the row, which would come back 0.
func (c *Commands) GetChannelInfo(ctx context.Context, cid ChannelID) (Channel, error) {
	rows, err := c.query(ctx, "channelinfo", []param{idArg("cid", cid)})
	if err != nil {
		return Channel{}, err
	}

	if len(rows) == 0 {
		return Channel{}, ErrNoData
	}

	channel := parseChannel(rows[0])
	channel.ID = cid

	return channel, nil
}

// MoveChannel moves a channel under parentID (0 for the top level), sorted
// after the channel order names. A nil order leaves the position to the
// server; a pointer to 0 sorts the channel first.
func (c *Commands) MoveChannel(ctx context.Context, cid, parentID ChannelID, order *ChannelID) error {
	return c.exec(ctx, "channelmove", []param{
		idArg("cid", cid),
		idArg("cpid", parentID),
		uintPtrArg("order", order),
	})
}

// PermissionEntry is one entry of a permission list.
type PermissionEntry struct {
	// Permission is the permission the entry sets, named the way the server
	// sent it — by id, since the lists are requested without -permsid. It can
	// be passed straight back to the matching Delete command.
	Permission Permission
	Value      int32
	Negated    bool
	Skip       bool
}

func parsePermission(row map[string]string) PermissionEntry {
	perm := PermissionByID(PermissionID(fieldUint32(row, "permid")))
	if name := fieldStr(row, "permsid"); name != "" {
		perm = PermissionByName(name)
	}

	return PermissionEntry{
		Permission: perm,
		Value:      fieldInt32(row, "permvalue"),
		Negated:    fieldBool(row, "permnegated"),
		Skip:       fieldBool(row, "permskip"),
	}
}

// AddChannelPermission sets a permission on a channel.
func (c *Commands) AddChannelPermission(ctx context.Context, cid ChannelID, perm Permission, value int32) error {
	return c.exec(ctx, "channeladdperm", []param{
		idArg("cid", cid),
		permArg(perm),
		intArg("permvalue", int64(value)),
	})
}

// DeleteChannelPermission removes a permission from a channel.
func (c *Commands) DeleteChannelPermission(ctx context.Context, cid ChannelID, perm Permission) error {
	return c.exec(ctx, "channeldelperm", []param{
		idArg("cid", cid),
		permArg(perm),
	})
}

// ListChannelPermissions returns permissions set directly on a channel.
func (c *Commands) ListChannelPermissions(ctx context.Context, cid ChannelID) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelpermlist", []param{idArg("cid", cid)})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// ListChannelClientPermissions returns permissions granted to one client within
// one channel.
func (c *Commands) ListChannelClientPermissions(
	ctx context.Context, cid ChannelID, clientDBID ClientDBID,
) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelclientpermlist", []param{
		idArg("cid", cid),
		idArg("cldbid", clientDBID),
	})
	if err != nil {
		return nil, err
	}

	out := make([]PermissionEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parsePermission(row))
	}

	return out, nil
}

// AddChannelClientPermission sets a permission on one client in one channel.
func (c *Commands) AddChannelClientPermission(
	ctx context.Context, cid ChannelID, clientDBID ClientDBID, perm Permission, value int32,
) error {
	return c.exec(ctx, "channelclientaddperm", []param{
		idArg("cid", cid),
		idArg("cldbid", clientDBID),
		permArg(perm),
		intArg("permvalue", int64(value)),
	})
}

// DeleteChannelClientPermission removes a permission from one client in one
// channel.
func (c *Commands) DeleteChannelClientPermission(
	ctx context.Context, cid ChannelID, clientDBID ClientDBID, perm Permission,
) error {
	return c.exec(ctx, "channelclientdelperm", []param{
		idArg("cid", cid),
		idArg("cldbid", clientDBID),
		permArg(perm),
	})
}

// ChannelMatch is one row of a channelfind result.
type ChannelMatch struct {
	Name string
	ID   ChannelID
}

// FindChannels returns channels whose name contains pattern.
func (c *Commands) FindChannels(ctx context.Context, pattern string) ([]ChannelMatch, error) {
	rows, err := c.list(ctx, "channelfind", []param{strArg("pattern", pattern)})
	if err != nil {
		return nil, err
	}

	out := make([]ChannelMatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChannelMatch{
			ID:   ChannelID(fieldUint(row, "cid")),
			Name: fieldStr(row, "channel_name"),
		})
	}

	return out, nil
}
