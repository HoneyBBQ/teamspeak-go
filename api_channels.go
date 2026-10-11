package teamspeak

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
func (c *Client) CreateChannel(opts ChannelCreateOptions) (uint64, error) {
	params := []param{
		Str("channel_name", opts.ChannelName),
		UintPtr("cpid", opts.ParentID),
		StrPtr("channel_topic", opts.ChannelTopic),
		StrPtr("channel_description", opts.ChannelDescription),
		StrPtr("channel_password", opts.ChannelPassword),
		Int32Ptr("channel_codec", opts.ChannelCodec),
		Int32Ptr("channel_codec_quality", opts.ChannelCodecQuality),
		Int32Ptr("channel_maxclients", opts.ChannelMaxClients),
		Int32Ptr("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		UintPtr("channel_order", opts.ChannelOrder),
		BoolPtr("channel_flag_password", opts.ChannelFlagPassword),
		BoolPtr("channel_flag_permanent", opts.ChannelFlagPermanent),
		BoolPtr("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		BoolPtr("channel_flag_default", opts.ChannelFlagDefault),
		UintPtr("channel_delete_delay", opts.ChannelDeleteDelay),
		StrPtr("channel_name_phonetic", opts.ChannelNamePhonetic),
	}

	rows, err := c.query("channelcreate", params, PlainPassword("channel_password"))
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
func (c *Client) EditChannel(cid uint64, opts ChannelEditOptions) error {
	return c.exec("channeledit", []param{
		Uint("cid", cid),
		StrPtr("channel_name", opts.ChannelName),
		StrPtr("channel_topic", opts.ChannelTopic),
		StrPtr("channel_description", opts.ChannelDescription),
		StrPtr("channel_password", opts.ChannelPassword),
		UintPtr("channel_order", opts.ChannelOrder),
		Int32Ptr("channel_codec", opts.ChannelCodec),
		Int32Ptr("channel_codec_quality", opts.ChannelCodecQuality),
		Int32Ptr("channel_maxclients", opts.ChannelMaxClients),
		Int32Ptr("channel_maxfamilyclients", opts.ChannelMaxFamilyClients),
		Int32Ptr("channel_needed_talk_power", opts.ChannelNeededTalkPower),
		BoolPtr("channel_flag_password", opts.ChannelFlagPassword),
		BoolPtr("channel_flag_permanent", opts.ChannelFlagPermanent),
		BoolPtr("channel_flag_semi_permanent", opts.ChannelFlagSemiPermanent),
		BoolPtr("channel_flag_default", opts.ChannelFlagDefault),
		UintPtr("channel_delete_delay", opts.ChannelDeleteDelay),
		StrPtr("channel_name_phonetic", opts.ChannelNamePhonetic),
	}, PlainPassword("channel_password"))
}

// DeleteChannel deletes a channel.
//
// force is required by the server, not just conventional: deleting a channel
// that still holds clients fails without it.
func (c *Client) DeleteChannel(cid uint64, force bool) error {
	return c.exec("channeldelete", []param{
		Uint("cid", cid),
		Bool("force", force),
	})
}

// ListChannels returns every channel on the server, in the server's sort order.
func (c *Client) ListChannels() ([]Channel, error) {
	rows, err := c.query("channellist", nil)
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
func (c *Client) GetChannelInfo(cid uint64) (Channel, error) {
	rows, err := c.query("channelinfo", []param{Uint("cid", cid)})
	if err != nil {
		return Channel{}, err
	}

	if len(rows) == 0 {
		return Channel{}, errNoDataReturned
	}

	channel := parseChannel(rows[0])
	channel.ID = cid

	return channel, nil
}

// GetChannelDescription returns the channel's description.
//
// channellist omits it for bandwidth, so it needs its own call.
func (c *Client) GetChannelDescription(cid uint64) (string, error) {
	rows, err := c.query("channelgetdescription", []param{Uint("cid", cid)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "channel_description"), nil
}

// MoveChannel moves a channel to a new parent and position.
func (c *Client) MoveChannel(cid, parentID uint64, order *uint64) error {
	return c.exec("channelmove", []param{
		Uint("cid", cid),
		Uint("cpid", parentID),
		UintPtr("order", order),
	})
}

// SubscribeChannel subscribes to a channel's events.
func (c *Client) SubscribeChannel(cid uint64) error {
	return c.exec("channelsubscribe", []param{Uint("cid", cid)})
}

// UnsubscribeChannel stops receiving a channel's events.
func (c *Client) UnsubscribeChannel(cid uint64) error {
	return c.exec("channelunsubscribe", []param{Uint("cid", cid)})
}

// SubscribeAllChannels subscribes to every channel's events.
func (c *Client) SubscribeAllChannels() error {
	return c.exec("channelsubscribeall", nil)
}

// UnsubscribeAllChannels stops receiving channel events.
func (c *Client) UnsubscribeAllChannels() error {
	return c.exec("channelunsubscribeall", nil)
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
func (c *Client) AddChannelPermission(cid uint64, permValue int32, permID *uint64, permSID *string) error {
	return c.exec("channeladdperm", []param{
		Uint("cid", cid),
		Int("permvalue", int64(permValue)),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// DeleteChannelPermission removes a channel permission.
func (c *Client) DeleteChannelPermission(cid uint64, permID *uint64, permSID *string) error {
	return c.exec("channeldelperm", []param{
		Uint("cid", cid),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// ListChannelPermissions returns permissions set directly on a channel.
func (c *Client) ListChannelPermissions(cid uint64) ([]PermissionEntry, error) {
	rows, err := c.query("channelpermlist", []param{Uint("cid", cid)})
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
func (c *Client) ListChannelClientPermissions(cid, clientDBID uint64) ([]PermissionEntry, error) {
	rows, err := c.query("channelclientpermlist", []param{
		Uint("cid", cid),
		Uint("cldbid", clientDBID),
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
func (c *Client) AddChannelClientPermission(
	cid, clientDBID uint64, permValue int32, permID *uint64, permSID *string,
) error {
	return c.exec("channelclientaddperm", []param{
		Uint("cid", cid),
		Uint("cldbid", clientDBID),
		Int("permvalue", int64(permValue)),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}

// DeleteChannelClientPermission removes a permission from one client in one
// channel.
func (c *Client) DeleteChannelClientPermission(cid, clientDBID uint64, permID *uint64, permSID *string) error {
	return c.exec("channelclientdelperm", []param{
		Uint("cid", cid),
		Uint("cldbid", clientDBID),
		UintPtr("permid", permID),
		StrPtr("permsid", permSID),
	})
}
