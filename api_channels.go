package teamspeak

import (
	"context"
	"errors"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
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
	// UID is the channel's unique identifier (channel_unique_identifier),
	// which the server assigns once; empty when the server does not send it.
	// channellist does not, so ListChannels leaves it empty.
	UID ChannelUID
	// Name is the channel's name (channel_name).
	Name string
	// Topic is the topic shown under the name (channel_topic).
	Topic string
	// Description is the channel description (channel_description). channellist
	// does not carry it, so ListChannels leaves it empty; GetChannelInfo has it.
	Description string
	// ID is the channel's id (cid).
	ID ChannelID
	// ParentID is the channel this one sits under, or 0 at the top level.
	//
	// channellist names this cpid and channelinfo names it pid — the same value
	// under two keys, which is why both are read.
	ParentID ChannelID
	// Order is the channel this one is sorted after, among its siblings, or 0
	// for the first: channel_order is a channel id, not a position.
	Order ChannelID
	// IconID is the channel's icon, or 0 for none (channel_icon_id).
	IconID IconID
	// Codec is the channel's voice codec (channel_codec).
	Codec Codec
	// CodecQuality is the codec's quality, 0 to 10 (channel_codec_quality).
	CodecQuality int32
	// MaxClients is how many clients may be in the channel (channel_maxclients);
	// -1 when the server sends it as unlimited.
	MaxClients int32
	// MaxFamilyClients is how many clients may be in the channel and its
	// subchannels together (channel_maxfamilyclients); -1 when the server sends
	// it as unlimited.
	MaxFamilyClients int32
	// TotalClients is how many clients are in the channel (total_clients). It
	// is nil when the answer does not carry it, as channelinfo's does not, so
	// GetChannelInfo always leaves it nil; ListChannels sets it.
	TotalClients *int32
	// TotalFamilyClients is how many clients are in the channel and its
	// subchannels (total_clients_family). It is nil when the answer does not
	// carry it, as channelinfo's does not; ListChannels sets it.
	TotalFamilyClients *int32
	// NeededSubscribePower is the power a client needs to subscribe to the
	// channel (channel_needed_subscribe_power). It is nil when the answer does
	// not carry it, as channelinfo's does not; ListChannels sets it.
	NeededSubscribePower *int32
	// NeededTalkPower is the talk power a client needs to speak here
	// (channel_needed_talk_power).
	NeededTalkPower int32
	// IsDefault reports the channel new clients land in (channel_flag_default).
	IsDefault bool
	// IsPermanent reports a channel that survives a server restart
	// (channel_flag_permanent).
	IsPermanent bool
	// IsSemiPermanent reports a channel that survives its last client leaving
	// but not a server restart (channel_flag_semi_permanent).
	IsSemiPermanent bool
	// HasPassword reports a password-protected channel (channel_flag_password).
	HasPassword bool

	// The fields below are nil, empty or 0 where the answer did not carry them:
	// channellist brings none of them, so ListChannels leaves them unset;
	// GetChannelInfo fills the ones channelinfo has, and a channel notification
	// carries only those that changed.

	// CodecLatencyFactor is the codec's latency factor
	// (channel_codec_latency_factor).
	CodecLatencyFactor *int32
	// IsUnencrypted reports a channel whose voice is not encrypted
	// (channel_codec_is_unencrypted).
	IsUnencrypted *bool
	// IsMaxClientsUnlimited reports a channel with no client limit
	// (channel_flag_maxclients_unlimited).
	IsMaxClientsUnlimited *bool
	// IsMaxFamilyClientsUnlimited reports no family client limit
	// (channel_flag_maxfamilyclients_unlimited).
	IsMaxFamilyClientsUnlimited *bool
	// IsMaxFamilyClientsInherited reports a family limit taken from the parent
	// (channel_flag_maxfamilyclients_inherited).
	IsMaxFamilyClientsInherited *bool
	// DeleteDelay is how long a temporary channel survives its last client
	// leaving (channel_delete_delay, whole seconds on the wire).
	DeleteDelay *time.Duration
	// NamePhonetic is how the name is pronounced (channel_name_phonetic); empty
	// when not carried.
	NamePhonetic string
	// IsForcedSilence reports a channel where everyone needs talk power
	// (channel_forced_silence).
	IsForcedSilence *bool
	// BannerURL is the channel banner's address (channel_banner_gfx_url); empty
	// when not carried.
	BannerURL string
	// BannerMode is how the banner is shown (channel_banner_mode).
	BannerMode *int32
}

func parseChannel(row map[string]string) Channel {
	parent := fieldUint(row, "pid")
	if parent == 0 {
		parent = fieldUint(row, "cpid")
	}

	return Channel{
		ID:                   ChannelID(fieldUint(row, "cid")),
		ParentID:             ChannelID(parent),
		Name:                 fieldStr(row, "channel_name"),
		Topic:                fieldStr(row, "channel_topic"),
		Description:          fieldStr(row, "channel_description"),
		Order:                ChannelID(fieldUint(row, "channel_order")),
		HasPassword:          fieldBool(row, "channel_flag_password"),
		IsDefault:            fieldBool(row, "channel_flag_default"),
		IsPermanent:          fieldBool(row, "channel_flag_permanent"),
		Codec:                Codec(fieldUint8(row, "channel_codec")),
		CodecQuality:         fieldInt32(row, "channel_codec_quality"),
		MaxClients:           fieldInt32(row, "channel_maxclients"),
		MaxFamilyClients:     fieldInt32(row, "channel_maxfamilyclients"),
		TotalClients:         fieldOptInt32(row, "total_clients"),
		TotalFamilyClients:   fieldOptInt32(row, "total_clients_family"),
		NeededSubscribePower: fieldOptInt32(row, "channel_needed_subscribe_power"),
		IsSemiPermanent:      fieldBool(row, "channel_flag_semi_permanent"),
		NeededTalkPower:      fieldInt32(row, "channel_needed_talk_power"),
		IconID:               fieldIconID(row, "channel_icon_id"),
		UID:                  ChannelUID(fieldStr(row, "channel_unique_identifier")),

		CodecLatencyFactor:          fieldOptInt32(row, "channel_codec_latency_factor"),
		IsUnencrypted:               fieldOptBool(row, "channel_codec_is_unencrypted"),
		IsMaxClientsUnlimited:       fieldOptBool(row, "channel_flag_maxclients_unlimited"),
		IsMaxFamilyClientsUnlimited: fieldOptBool(row, "channel_flag_maxfamilyclients_unlimited"),
		IsMaxFamilyClientsInherited: fieldOptBool(row, "channel_flag_maxfamilyclients_inherited"),
		DeleteDelay:                 fieldOptDuration(row, "channel_delete_delay", time.Second),
		NamePhonetic:                fieldStr(row, "channel_name_phonetic"),
		IsForcedSilence:             fieldOptBool(row, "channel_forced_silence"),
		BannerURL:                   fieldStr(row, "channel_banner_gfx_url"),
		BannerMode:                  fieldOptInt32(row, "channel_banner_mode"),
	}
}

// ChannelCreateOptions are the parameters for channelcreate. The fields are
// named as on Channel.
//
// Only Name is required. A nil pointer omits the parameter entirely, which is
// not the same as sending an empty value: clearing a password takes
// `channel_password=`, while leaving it alone takes no parameter at all.
// Build one with new: Topic: new("the quiet one").
type ChannelCreateOptions struct {
	// Order is the channel to sort the new one after among its siblings; 0
	// sorts it first (channel_order).
	Order *ChannelID
	// DeleteDelay is how long a temporary channel survives its last client
	// leaving (channel_delete_delay). Sent in whole seconds.
	DeleteDelay *time.Duration
	// Codec is the voice codec (channel_codec).
	Codec *Codec
	// CodecQuality is the codec's quality, 0 to 10 (channel_codec_quality).
	CodecQuality *int32
	// MaxClients is how many clients may be in the channel
	// (channel_maxclients).
	MaxClients *int32
	// MaxFamilyClients is how many clients may be in the channel and those
	// under it (channel_maxfamilyclients).
	MaxFamilyClients *int32
	// NeededTalkPower is the talk power a client needs to speak here
	// (channel_needed_talk_power).
	NeededTalkPower *int32
	// HasPassword marks the channel password-protected
	// (channel_flag_password). The server sets it itself when Password is
	// set.
	HasPassword *bool
	// IsPermanent makes the channel survive a server restart
	// (channel_flag_permanent).
	IsPermanent *bool
	// IsSemiPermanent makes the channel survive its last client leaving, but
	// not a restart (channel_flag_semi_permanent).
	IsSemiPermanent *bool
	// IsDefault makes the channel the one new clients land in
	// (channel_flag_default).
	IsDefault *bool
	// Topic is the topic shown under the name (channel_topic).
	Topic *string
	// Description is the channel description (channel_description). channellist
	// does not carry it, so ListChannels leaves it empty; GetChannelInfo has it.
	Description *string
	// Password is the channel password (channel_password), in cleartext: the
	// voice client hashes it on the wire. A pointer to "" sets none.
	Password *string
	// NamePhonetic is how the name is pronounced, for text-to-speech
	// (channel_name_phonetic).
	NamePhonetic *string

	// Name is the channel's name (channel_name). Required.
	Name string
	// ParentID is the channel to create the new one under; 0 is the top level
	// (cpid).
	ParentID ChannelID
}

// CreateChannel creates a channel and returns the id the server assigned.
func (c *Commands) CreateChannel(ctx context.Context, opts ChannelCreateOptions) (ChannelID, error) {
	params := []param{
		strArg("channel_name", opts.Name),
		optIDArg("cpid", opts.ParentID),
		strPtrArg("channel_topic", opts.Topic),
		strPtrArg("channel_description", opts.Description),
		strPtrArg("channel_password", opts.Password),
		uintPtrArg("channel_codec", opts.Codec),
		int32PtrArg("channel_codec_quality", opts.CodecQuality),
		int32PtrArg("channel_maxclients", opts.MaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.MaxFamilyClients),
		int32PtrArg("channel_needed_talk_power", opts.NeededTalkPower),
		uintPtrArg("channel_order", opts.Order),
		boolPtrArg("channel_flag_password", opts.HasPassword),
		boolPtrArg("channel_flag_permanent", opts.IsPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.IsSemiPermanent),
		boolPtrArg("channel_flag_default", opts.IsDefault),
		durationPtrArg("channel_delete_delay", opts.DeleteDelay, time.Second),
		strPtrArg("channel_name_phonetic", opts.NamePhonetic),
	}

	row, err := c.queryRow(ctx, "channelcreate", "cid", params, "channel_password")
	if err != nil {
		return 0, err
	}

	return ChannelID(fieldUint(row, "cid")), nil
}

// ChannelEditOptions are the parameters for channeledit, named as on
// ChannelCreateOptions. Only the fields you set are sent: a nil pointer leaves
// a setting alone and a pointer to the zero value clears it.
type ChannelEditOptions struct {
	// Name is the channel's new name (channel_name).
	Name *string
	// Topic is the topic shown under the name (channel_topic).
	Topic *string
	// Description is the channel description (channel_description). channellist
	// does not carry it, so ListChannels leaves it empty; GetChannelInfo has it.
	Description *string
	// Password is the channel password (channel_password), in cleartext: the
	// voice client hashes it on the wire. A pointer to "" removes it.
	Password *string
	// Order is the channel to sort this one after among its siblings; 0 sorts
	// it first (channel_order).
	Order *ChannelID
	// Codec is the voice codec (channel_codec).
	Codec *Codec
	// CodecQuality is the codec's quality, 0 to 10 (channel_codec_quality).
	CodecQuality *int32
	// MaxClients is how many clients may be in the channel
	// (channel_maxclients).
	MaxClients *int32
	// MaxFamilyClients is how many clients may be in the channel and those
	// under it (channel_maxfamilyclients).
	MaxFamilyClients *int32
	// NeededTalkPower is the talk power a client needs to speak here
	// (channel_needed_talk_power).
	NeededTalkPower *int32
	// HasPassword marks the channel password-protected
	// (channel_flag_password). The server sets it itself when Password is
	// set.
	HasPassword *bool
	// IsPermanent makes the channel survive a server restart
	// (channel_flag_permanent).
	IsPermanent *bool
	// IsSemiPermanent makes the channel survive its last client leaving, but
	// not a restart (channel_flag_semi_permanent).
	IsSemiPermanent *bool
	// IsDefault makes the channel the one new clients land in
	// (channel_flag_default).
	IsDefault *bool
	// DeleteDelay is how long a temporary channel survives its last client
	// leaving (channel_delete_delay). Sent in whole seconds.
	DeleteDelay *time.Duration
	// NamePhonetic is how the name is pronounced, for text-to-speech
	// (channel_name_phonetic).
	NamePhonetic *string
}

// EditChannel changes a channel's settings.
func (c *Commands) EditChannel(ctx context.Context, cid ChannelID, opts ChannelEditOptions) error {
	return c.exec(ctx, "channeledit", []param{
		idArg("cid", cid),
		strPtrArg("channel_name", opts.Name),
		strPtrArg("channel_topic", opts.Topic),
		strPtrArg("channel_description", opts.Description),
		strPtrArg("channel_password", opts.Password),
		uintPtrArg("channel_order", opts.Order),
		uintPtrArg("channel_codec", opts.Codec),
		int32PtrArg("channel_codec_quality", opts.CodecQuality),
		int32PtrArg("channel_maxclients", opts.MaxClients),
		int32PtrArg("channel_maxfamilyclients", opts.MaxFamilyClients),
		int32PtrArg("channel_needed_talk_power", opts.NeededTalkPower),
		boolPtrArg("channel_flag_password", opts.HasPassword),
		boolPtrArg("channel_flag_permanent", opts.IsPermanent),
		boolPtrArg("channel_flag_semi_permanent", opts.IsSemiPermanent),
		boolPtrArg("channel_flag_default", opts.IsDefault),
		durationPtrArg("channel_delete_delay", opts.DeleteDelay, time.Second),
		strPtrArg("channel_name_phonetic", opts.NamePhonetic),
	}, "channel_password")
}

// ChannelDeleteOptions are DeleteChannel's optional parameters.
type ChannelDeleteOptions struct {
	// Force deletes a channel that still holds clients, which the server
	// otherwise refuses.
	Force bool
}

// DeleteChannel deletes a channel.
func (c *Commands) DeleteChannel(ctx context.Context, cid ChannelID, opts ChannelDeleteOptions) error {
	return c.exec(ctx, "channeldelete", []param{
		idArg("cid", cid),
		boolArg("force", opts.Force),
	})
}

// ChannelListOptions are ListChannels' optional parameters. It has no fields
// yet: it is reserved for the flags of channellist, which ListChannels sends
// in full today.
type ChannelListOptions struct{}

// ListChannels returns every channel on the server, in the server's sort order,
// with the topic, flags, voice settings, limits and icon: it asks channellist
// for -topic -flags -voice -limits -icon, without which the server answers
// only the id, parent, order, name, client count and subscribe power.
//
// Description and UID are not part of channellist and stay empty; use
// GetChannelInfo, or the voice client's GetChannelDescription, for them.
func (c *Commands) ListChannels(ctx context.Context, _ ChannelListOptions) ([]Channel, error) {
	flags := []string{"-topic", "-flags", "-voice", "-limits", "-icon"}
	params := make([]param, 0, len(flags))
	for _, flag := range flags {
		params = append(params, boolArg(flag, true))
	}
	rows, err := c.list(ctx, "channellist", params)
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
// TotalClients, TotalFamilyClients and NeededSubscribePower are nil:
// channelinfo does not carry them. ListChannels does.
//
// channelinfo answers with pid and the settings but no cid — the channel is
// whatever was asked for — so the id is filled in from the argument rather than
// read from the row, which would come back 0.
func (c *Commands) GetChannelInfo(ctx context.Context, cid ChannelID) (Channel, error) {
	row, err := c.queryRow(ctx, "channelinfo", "", []param{idArg("cid", cid)})
	if err != nil {
		return Channel{}, err
	}

	channel := parseChannel(row)
	channel.ID = cid

	return channel, nil
}

// ChannelMoveOptions are MoveChannel's optional parameters.
type ChannelMoveOptions struct {
	// Order is the channel to sort the moved one after. nil leaves the
	// position to the server; a pointer to 0 sorts the channel first.
	Order *ChannelID
}

// MoveChannel moves a channel under parentID (0 for the top level).
func (c *Commands) MoveChannel(ctx context.Context, cid, parentID ChannelID, opts ChannelMoveOptions) error {
	return c.exec(ctx, "channelmove", []param{
		idArg("cid", cid),
		idArg("cpid", parentID),
		uintPtrArg("order", opts.Order),
	})
}

// PermissionEntry is one entry of a permission list.
type PermissionEntry struct {
	// Permission is the permission the entry sets, named the way the server
	// sent it — by id, since the lists are requested without -permsid. It can
	// be passed straight back to the matching Delete command.
	Permission Permission
	// Value is the permission's value (permvalue).
	Value int32
	// Negated makes the lowest value among the client's groups win instead of
	// the highest (permnegated).
	Negated bool
	// Skip makes the value override channel and channel group permissions
	// (permskip).
	Skip bool
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
	rows, err := c.list(ctx, "channelpermlist", []param{idArg("cid", cid)})
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
	rows, err := c.list(ctx, "channelclientpermlist", []param{
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
	// Name is the channel's name (channel_name).
	Name string
	// ID is the channel's id (cid).
	ID ChannelID
}

// FindChannels returns channels whose name contains pattern, none when no
// channel matches.
func (c *Commands) FindChannels(ctx context.Context, pattern string) ([]ChannelMatch, error) {
	rows, err := c.list(ctx, "channelfind", []param{strArg("pattern", pattern)})
	// No match is 768, "invalid channelID", measured on TeamSpeak 3 and 6:
	// channelfind takes no cid, so the code can only mean none was found.
	if errors.Is(err, errcode.ChannelInvalidID) {
		return nil, nil
	}
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
