package teamspeak

import "context"

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
	ID               uint64
	// ParentID is the channel this one sits under.
	//
	// channellist names this cpid and channelinfo names it pid — the same value
	// under two keys, which is why both are read.
	ParentID        uint64
	Order           uint64
	IconID          uint64
	Codec           int32
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
		ID:               fieldUint(row, "cid"),
		ParentID:         parent,
		Name:             fieldStr(row, "channel_name"),
		Topic:            fieldStr(row, "channel_topic"),
		Description:      fieldStr(row, "channel_description"),
		Order:            fieldUint(row, "channel_order"),
		HasPassword:      fieldBool(row, "channel_flag_password"),
		IsDefault:        fieldBool(row, "channel_flag_default"),
		IsPermanent:      fieldBool(row, "channel_flag_permanent"),
		Codec:            fieldInt32(row, "channel_codec"),
		CodecQuality:     fieldInt32(row, "channel_codec_quality"),
		MaxClients:       fieldInt32(row, "channel_maxclients"),
		NeededTalkPower:  fieldInt32(row, "channel_needed_talk_power"),
		IconID:           fieldUint(row, "channel_icon_id"),
		UniqueIdentifier: fieldStr(row, "channel_unique_identifier"),
	}
}

// ChannelCreateOptions are the parameters for channelcreate.
//
// Only ChannelName is required. A nil pointer omits the parameter entirely,
// which is not the same as sending an empty value: clearing a password takes
// `channel_password=`, while leaving it alone takes no parameter at all.
type ChannelCreateOptions struct {
	ParentID                 *uint64
	ChannelOrder             *uint64
	ChannelDeleteDelay       *uint64
	ChannelCodec             *int32
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
}

// CreateChannel creates a channel and returns the id the server assigned.
func (c *Commands) CreateChannel(ctx context.Context, opts ChannelCreateOptions) (uint64, error) {
	params := []param{
		strArg("channel_name", opts.ChannelName),
		uintPtrArg("cpid", opts.ParentID),
		strPtrArg("channel_topic", opts.ChannelTopic),
		strPtrArg("channel_description", opts.ChannelDescription),
		strPtrArg("channel_password", opts.ChannelPassword),
		int32PtrArg("channel_codec", opts.ChannelCodec),
		int32PtrArg("channel_codec_quality", opts.ChannelCodecQuality),
		int32PtrArg("channel_maxclients", opts.ChannelMaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		uintPtrArg("channel_order", opts.ChannelOrder),
		boolPtrArg("channel_flag_password", opts.ChannelFlagPassword),
		boolPtrArg("channel_flag_permanent", opts.ChannelFlagPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		boolPtrArg("channel_flag_default", opts.ChannelFlagDefault),
		uintPtrArg("channel_delete_delay", opts.ChannelDeleteDelay),
		strPtrArg("channel_name_phonetic", opts.ChannelNamePhonetic),
	}

	rows, err := c.query(ctx, "channelcreate", params, "channel_password")
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "cid"), nil
}

// ChannelEditOptions are the parameters for channeledit. Only the fields you
// set are sent.
type ChannelEditOptions struct {
	ChannelName              *string
	ChannelTopic             *string
	ChannelDescription       *string
	ChannelPassword          *string
	ChannelOrder             *uint64
	ChannelCodec             *int32
	ChannelCodecQuality      *int32
	ChannelMaxClients        *int32
	ChannelMaxFamilyClients  *int32
	ChannelNeededTalkPower   *int32
	ChannelFlagPassword      *bool
	ChannelFlagPermanent     *bool
	ChannelFlagSemiPermanent *bool
	ChannelFlagDefault       *bool
	ChannelDeleteDelay       *uint64
	ChannelNamePhonetic      *string
}

// EditChannel changes a channel's settings.
func (c *Commands) EditChannel(ctx context.Context, cid uint64, opts ChannelEditOptions) error {
	return c.exec(ctx, "channeledit", []param{
		uintArg("cid", cid),
		strPtrArg("channel_name", opts.ChannelName),
		strPtrArg("channel_topic", opts.ChannelTopic),
		strPtrArg("channel_description", opts.ChannelDescription),
		strPtrArg("channel_password", opts.ChannelPassword),
		uintPtrArg("channel_order", opts.ChannelOrder),
		int32PtrArg("channel_codec", opts.ChannelCodec),
		int32PtrArg("channel_codec_quality", opts.ChannelCodecQuality),
		int32PtrArg("channel_maxclients", opts.ChannelMaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		int32PtrArg("channel_needed_talk_power", opts.ChannelNeededTalkPower),
		boolPtrArg("channel_flag_password", opts.ChannelFlagPassword),
		boolPtrArg("channel_flag_permanent", opts.ChannelFlagPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		boolPtrArg("channel_flag_default", opts.ChannelFlagDefault),
		uintPtrArg("channel_delete_delay", opts.ChannelDeleteDelay),
		strPtrArg("channel_name_phonetic", opts.ChannelNamePhonetic),
	}, "channel_password")
}

// DeleteChannel deletes a channel.
//
// force is required by the server, not just conventional: deleting a channel
// that still holds clients fails without it.
func (c *Commands) DeleteChannel(ctx context.Context, cid uint64, force bool) error {
	return c.exec(ctx, "channeldelete", []param{
		uintArg("cid", cid),
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
func (c *Commands) GetChannelInfo(ctx context.Context, cid uint64) (Channel, error) {
	rows, err := c.query(ctx, "channelinfo", []param{uintArg("cid", cid)})
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

// MoveChannel moves a channel to a new parent and position.
func (c *Commands) MoveChannel(ctx context.Context, cid, parentID uint64, order *uint64) error {
	return c.exec(ctx, "channelmove", []param{
		uintArg("cid", cid),
		uintArg("cpid", parentID),
		uintPtrArg("order", order),
	})
}

// PermissionEntry is one entry of a permission list.
//
// A permission is addressable by id or by name, and the server answers in
// whichever form the request used, so exactly one of PermID and PermSID is
// populated.
type PermissionEntry struct {
	PermID  *uint64
	PermSID string
	Value   int32
	Negated bool
	Skip    bool
}

func parsePermission(row map[string]string) PermissionEntry {
	var permID *uint64
	if raw, ok := row["permid"]; ok && raw != "" {
		id := fieldUint(row, "permid")
		permID = &id
	}

	return PermissionEntry{
		PermID:  permID,
		PermSID: fieldStr(row, "permsid"),
		Value:   fieldInt32(row, "permvalue"),
		Negated: fieldBool(row, "permnegated"),
		Skip:    fieldBool(row, "permskip"),
	}
}

// AddChannelPermission grants a channel permission.
func (c *Commands) AddChannelPermission(
	ctx context.Context, cid uint64, permValue int32, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "channeladdperm", []param{
		uintArg("cid", cid),
		intArg("permvalue", int64(permValue)),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// DeleteChannelPermission removes a channel permission.
func (c *Commands) DeleteChannelPermission(ctx context.Context, cid uint64, permID *uint64, permSID *string) error {
	return c.exec(ctx, "channeldelperm", []param{
		uintArg("cid", cid),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// ListChannelPermissions returns permissions set directly on a channel.
func (c *Commands) ListChannelPermissions(ctx context.Context, cid uint64) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelpermlist", []param{uintArg("cid", cid)})
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
	ctx context.Context, cid, clientDBID uint64,
) ([]PermissionEntry, error) {
	rows, err := c.query(ctx, "channelclientpermlist", []param{
		uintArg("cid", cid),
		uintArg("cldbid", clientDBID),
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

// AddChannelClientPermission grants a permission to one client in one channel.
func (c *Commands) AddChannelClientPermission(
	ctx context.Context, cid, clientDBID uint64, permValue int32, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "channelclientaddperm", []param{
		uintArg("cid", cid),
		uintArg("cldbid", clientDBID),
		intArg("permvalue", int64(permValue)),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// DeleteChannelClientPermission removes a permission from one client in one
// channel.
func (c *Commands) DeleteChannelClientPermission(
	ctx context.Context, cid, clientDBID uint64, permID *uint64, permSID *string,
) error {
	return c.exec(ctx, "channelclientdelperm", []param{
		uintArg("cid", cid),
		uintArg("cldbid", clientDBID),
		uintPtrArg("permid", permID),
		strPtrArg("permsid", permSID),
	})
}

// ChannelMatch is one row of a channelfind result.
type ChannelMatch struct {
	Name string
	ID   uint64
}

// FindChannels returns channels whose name contains pattern.
func (c *Commands) FindChannels(ctx context.Context, pattern string) ([]ChannelMatch, error) {
	rows, err := c.query(ctx, "channelfind", []param{strArg("pattern", pattern)})
	if err != nil {
		return nil, err
	}

	out := make([]ChannelMatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChannelMatch{
			ID:   fieldUint(row, "cid"),
			Name: fieldStr(row, "channel_name"),
		})
	}

	return out, nil
}
