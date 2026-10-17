package teamspeak

import (
	"slices"
	"time"
)

// ClientChanges are the properties of a client that a notification carried: a
// field is nil when the notification did not name it, and points at the new
// value when it did. The fields are those of ClientEntry, apart from ID, under
// the same names, so what ClientUpdateOptions writes is what appears here.
//
// Every field is a pointer, strings and lists included, because here "zero"
// and "unchanged" are different facts: a pointer to "" is a cleared away
// message, and a pointer to an empty list is a client that now holds no
// groups. ServerGroups, when set, is the complete new list, not a difference.
//
// The notification reader sets only the properties a client's update carries;
// ChannelID (a move arrives as ClientMovedEvent), Created, LastConnected and
// IdleTime are never set by it, though Apply honours them.
type ClientChanges struct {
	// Created is the new ClientEntry.Created.
	Created *time.Time
	// LastConnected is the new ClientEntry.LastConnected.
	LastConnected *time.Time
	// IdleTime is the new ClientEntry.IdleTime.
	IdleTime *time.Duration
	// Nickname is the new ClientEntry.Nickname.
	Nickname *string
	// UID is the new ClientEntry.UID.
	UID *UID
	// ServerGroups is the new ClientEntry.ServerGroups.
	ServerGroups *[]ServerGroupID
	// ChannelID is the new ClientEntry.ChannelID.
	ChannelID *ChannelID
	// ChannelGroupID is the new ClientEntry.ChannelGroupID.
	ChannelGroupID *ChannelGroupID
	// Type is the new ClientEntry.Type.
	Type *ClientType
	// IsAway is the new ClientEntry.IsAway.
	IsAway *bool
	// IsRecording is the new ClientEntry.IsRecording.
	IsRecording *bool
	// IsTalker is the new ClientEntry.IsTalker.
	IsTalker *bool
	// DatabaseID is the new ClientEntry.DatabaseID.
	DatabaseID *ClientDBID
	// AwayMessage is the new ClientEntry.AwayMessage.
	AwayMessage *string
	// IsInputMuted is the new ClientEntry.IsInputMuted.
	IsInputMuted *bool
	// IsOutputMuted is the new ClientEntry.IsOutputMuted.
	IsOutputMuted *bool
	// IsOutputOnlyMuted is the new ClientEntry.IsOutputOnlyMuted.
	IsOutputOnlyMuted *bool
	// HasInputHardware is the new ClientEntry.HasInputHardware.
	HasInputHardware *bool
	// HasOutputHardware is the new ClientEntry.HasOutputHardware.
	HasOutputHardware *bool
	// IsChannelCommander is the new ClientEntry.IsChannelCommander.
	IsChannelCommander *bool
	// IsPrioritySpeaker is the new ClientEntry.IsPrioritySpeaker.
	IsPrioritySpeaker *bool
	// TalkPower is the new ClientEntry.TalkPower.
	TalkPower *int32
	// IsRequestingTalk is the new ClientEntry.IsRequestingTalk.
	IsRequestingTalk *bool
	// TalkRequestMessage is the new ClientEntry.TalkRequestMessage.
	TalkRequestMessage *string
	// Description is the new ClientEntry.Description.
	Description *string
	// MetaData is the new ClientEntry.MetaData.
	MetaData *string
	// Avatar is the new ClientEntry.Avatar.
	Avatar *string
	// IconID is the new ClientEntry.IconID.
	IconID *IconID
	// NicknamePhonetic is the new ClientEntry.NicknamePhonetic.
	NicknamePhonetic *string
	// UnreadMessages is the new ClientEntry.UnreadMessages.
	UnreadMessages *int32
	// NeededServerQueryViewPower is the new ClientEntry.NeededServerQueryViewPower.
	NeededServerQueryViewPower *int32
	// ChannelGroupInheritedChannelID is the new ClientEntry.ChannelGroupInheritedChannelID.
	ChannelGroupInheritedChannelID *ChannelID
	// Country is the new ClientEntry.Country.
	Country *string
	// Version is the new ClientEntry.Version.
	Version *string
	// Platform is the new ClientEntry.Platform.
	Platform *string
	// IP is the new ClientEntry.IP.
	IP *string
	// Badges is the new ClientEntry.Badges.
	Badges *string
	// SignedBadges is the new ClientEntry.SignedBadges.
	SignedBadges *string
	// MyTeamSpeakID is the new ClientEntry.MyTeamSpeakID.
	MyTeamSpeakID *string
	// MyTeamSpeakAvatar is the new ClientEntry.MyTeamSpeakAvatar.
	MyTeamSpeakAvatar *string
	// Integrations is the new ClientEntry.Integrations.
	Integrations *string
	// UserTag is the new ClientEntry.UserTag.
	UserTag *string
	// IsStreaming is the new ClientEntry.IsStreaming.
	IsStreaming *bool
}

// Apply returns e with the changes made. It returns a copy that shares no
// memory with e or with c: a field c does not set keeps e's value, and a list
// or pointer in the result is its own. ClientChanges{}.Apply(e) is a deep copy
// of e.
//
//nolint:funlen // one line per field, which the tests hold to the record
func (c ClientChanges) Apply(e ClientEntry) ClientEntry {
	e = e.Clone()
	set(&e.Created, c.Created)
	set(&e.LastConnected, c.LastConnected)
	set(&e.IdleTime, c.IdleTime)
	set(&e.Nickname, c.Nickname)
	set(&e.UID, c.UID)
	setList(&e.ServerGroups, c.ServerGroups)
	set(&e.ChannelID, c.ChannelID)
	set(&e.ChannelGroupID, c.ChannelGroupID)
	set(&e.Type, c.Type)
	set(&e.IsAway, c.IsAway)
	set(&e.IsRecording, c.IsRecording)
	set(&e.IsTalker, c.IsTalker)
	set(&e.DatabaseID, c.DatabaseID)
	set(&e.AwayMessage, c.AwayMessage)
	setPtr(&e.IsInputMuted, c.IsInputMuted)
	setPtr(&e.IsOutputMuted, c.IsOutputMuted)
	setPtr(&e.IsOutputOnlyMuted, c.IsOutputOnlyMuted)
	setPtr(&e.HasInputHardware, c.HasInputHardware)
	setPtr(&e.HasOutputHardware, c.HasOutputHardware)
	setPtr(&e.IsChannelCommander, c.IsChannelCommander)
	setPtr(&e.IsPrioritySpeaker, c.IsPrioritySpeaker)
	setPtr(&e.TalkPower, c.TalkPower)
	setPtr(&e.IsRequestingTalk, c.IsRequestingTalk)
	set(&e.TalkRequestMessage, c.TalkRequestMessage)
	set(&e.Description, c.Description)
	set(&e.MetaData, c.MetaData)
	set(&e.Avatar, c.Avatar)
	set(&e.IconID, c.IconID)
	set(&e.NicknamePhonetic, c.NicknamePhonetic)
	setPtr(&e.UnreadMessages, c.UnreadMessages)
	setPtr(&e.NeededServerQueryViewPower, c.NeededServerQueryViewPower)
	set(&e.ChannelGroupInheritedChannelID, c.ChannelGroupInheritedChannelID)
	set(&e.Country, c.Country)
	set(&e.Version, c.Version)
	set(&e.Platform, c.Platform)
	set(&e.IP, c.IP)
	set(&e.Badges, c.Badges)
	set(&e.SignedBadges, c.SignedBadges)
	set(&e.MyTeamSpeakID, c.MyTeamSpeakID)
	set(&e.MyTeamSpeakAvatar, c.MyTeamSpeakAvatar)
	set(&e.Integrations, c.Integrations)
	set(&e.UserTag, c.UserTag)
	setPtr(&e.IsStreaming, c.IsStreaming)

	return e
}

// ChannelChanges are the properties of a channel that a notification carried,
// as ClientChanges are a client's: a field is nil when the notification did not
// name it, and points at the new value when it did. The fields are those of
// Channel, apart from ID, under the same names, with the optional ones of
// Channel (TotalClients and the like) as plain pointers here as well.
type ChannelChanges struct {
	// UID is the new Channel.UID.
	UID *ChannelUID
	// Name is the new Channel.Name.
	Name *string
	// Topic is the new Channel.Topic.
	Topic *string
	// Description is the new Channel.Description.
	Description *string
	// ParentID is the new Channel.ParentID.
	ParentID *ChannelID
	// Order is the new Channel.Order.
	Order *ChannelID
	// IconID is the new Channel.IconID.
	IconID *IconID
	// Codec is the new Channel.Codec.
	Codec *Codec
	// CodecQuality is the new Channel.CodecQuality.
	CodecQuality *int32
	// MaxClients is the new Channel.MaxClients.
	MaxClients *int32
	// MaxFamilyClients is the new Channel.MaxFamilyClients.
	MaxFamilyClients *int32
	// TotalClients is the new Channel.TotalClients.
	TotalClients *int32
	// TotalFamilyClients is the new Channel.TotalFamilyClients.
	TotalFamilyClients *int32
	// NeededSubscribePower is the new Channel.NeededSubscribePower.
	NeededSubscribePower *int32
	// NeededTalkPower is the new Channel.NeededTalkPower.
	NeededTalkPower *int32
	// IsDefault is the new Channel.IsDefault.
	IsDefault *bool
	// IsPermanent is the new Channel.IsPermanent.
	IsPermanent *bool
	// IsSemiPermanent is the new Channel.IsSemiPermanent.
	IsSemiPermanent *bool
	// HasPassword is the new Channel.HasPassword.
	HasPassword *bool
	// CodecLatencyFactor is the new Channel.CodecLatencyFactor.
	CodecLatencyFactor *int32
	// IsUnencrypted is the new Channel.IsUnencrypted.
	IsUnencrypted *bool
	// IsMaxClientsUnlimited is the new Channel.IsMaxClientsUnlimited.
	IsMaxClientsUnlimited *bool
	// IsMaxFamilyClientsUnlimited is the new Channel.IsMaxFamilyClientsUnlimited.
	IsMaxFamilyClientsUnlimited *bool
	// IsMaxFamilyClientsInherited is the new Channel.IsMaxFamilyClientsInherited.
	IsMaxFamilyClientsInherited *bool
	// DeleteDelay is the new Channel.DeleteDelay.
	DeleteDelay *time.Duration
	// NamePhonetic is the new Channel.NamePhonetic.
	NamePhonetic *string
	// IsForcedSilence is the new Channel.IsForcedSilence.
	IsForcedSilence *bool
	// BannerURL is the new Channel.BannerURL.
	BannerURL *string
	// BannerMode is the new Channel.BannerMode.
	BannerMode *int32
}

// Apply returns ch with the changes made, as ClientChanges.Apply does.
//
//nolint:funlen // one line per field, which the tests hold to the record
func (c ChannelChanges) Apply(ch Channel) Channel {
	ch = ch.Clone()
	set(&ch.UID, c.UID)
	set(&ch.Name, c.Name)
	set(&ch.Topic, c.Topic)
	set(&ch.Description, c.Description)
	set(&ch.ParentID, c.ParentID)
	set(&ch.Order, c.Order)
	set(&ch.IconID, c.IconID)
	set(&ch.Codec, c.Codec)
	set(&ch.CodecQuality, c.CodecQuality)
	set(&ch.MaxClients, c.MaxClients)
	set(&ch.MaxFamilyClients, c.MaxFamilyClients)
	setPtr(&ch.TotalClients, c.TotalClients)
	setPtr(&ch.TotalFamilyClients, c.TotalFamilyClients)
	setPtr(&ch.NeededSubscribePower, c.NeededSubscribePower)
	set(&ch.NeededTalkPower, c.NeededTalkPower)
	set(&ch.IsDefault, c.IsDefault)
	set(&ch.IsPermanent, c.IsPermanent)
	set(&ch.IsSemiPermanent, c.IsSemiPermanent)
	set(&ch.HasPassword, c.HasPassword)
	setPtr(&ch.CodecLatencyFactor, c.CodecLatencyFactor)
	setPtr(&ch.IsUnencrypted, c.IsUnencrypted)
	setPtr(&ch.IsMaxClientsUnlimited, c.IsMaxClientsUnlimited)
	setPtr(&ch.IsMaxFamilyClientsUnlimited, c.IsMaxFamilyClientsUnlimited)
	setPtr(&ch.IsMaxFamilyClientsInherited, c.IsMaxFamilyClientsInherited)
	setPtr(&ch.DeleteDelay, c.DeleteDelay)
	set(&ch.NamePhonetic, c.NamePhonetic)
	setPtr(&ch.IsForcedSilence, c.IsForcedSilence)
	set(&ch.BannerURL, c.BannerURL)
	setPtr(&ch.BannerMode, c.BannerMode)

	return ch
}

// set copies a changed value into place, and leaves dst alone when the change is
// nil.
func set[T any](dst *T, change *T) {
	if change != nil {
		*dst = *change
	}
}

// setPtr is set for a record field that is itself a pointer: the record gets a
// pointer of its own, not the change's.
func setPtr[T any](dst **T, change *T) {
	if change != nil {
		*dst = clonePtr(change)
	}
}

// setList is set for a list, which the record gets a copy of. A pointer to an
// empty list sets an empty list.
func setList[T any](dst *[]T, change *[]T) {
	if change != nil {
		*dst = slices.Clone(*change)
	}
}

// clonePtr returns a pointer to a copy of what p points at, or nil.
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p

	return &v
}

// Clone returns a copy of e that shares no memory with it. A plain assignment
// copies the pointers and the list ServerGroups, so the copy and the original
// would change together; Clone gives the copy pointers and a list of its own.
// Use it before handing a record on, or keeping one, when either side may
// edit it.
func (e ClientEntry) Clone() ClientEntry {
	e.ServerGroups = slices.Clone(e.ServerGroups)
	e.IsInputMuted = clonePtr(e.IsInputMuted)
	e.IsOutputMuted = clonePtr(e.IsOutputMuted)
	e.IsOutputOnlyMuted = clonePtr(e.IsOutputOnlyMuted)
	e.HasInputHardware = clonePtr(e.HasInputHardware)
	e.HasOutputHardware = clonePtr(e.HasOutputHardware)
	e.IsChannelCommander = clonePtr(e.IsChannelCommander)
	e.IsPrioritySpeaker = clonePtr(e.IsPrioritySpeaker)
	e.TalkPower = clonePtr(e.TalkPower)
	e.IsRequestingTalk = clonePtr(e.IsRequestingTalk)
	e.UnreadMessages = clonePtr(e.UnreadMessages)
	e.NeededServerQueryViewPower = clonePtr(e.NeededServerQueryViewPower)
	e.IsStreaming = clonePtr(e.IsStreaming)

	return e
}

// Clone returns a copy of ch that shares no memory with it. A plain assignment
// copies the pointers, so the copy and the original would change together;
// Clone gives the copy pointers of its own. Use it before handing a record on,
// or keeping one, when either side may edit it.
func (ch Channel) Clone() Channel {
	ch.TotalClients = clonePtr(ch.TotalClients)
	ch.TotalFamilyClients = clonePtr(ch.TotalFamilyClients)
	ch.NeededSubscribePower = clonePtr(ch.NeededSubscribePower)
	ch.CodecLatencyFactor = clonePtr(ch.CodecLatencyFactor)
	ch.IsUnencrypted = clonePtr(ch.IsUnencrypted)
	ch.IsMaxClientsUnlimited = clonePtr(ch.IsMaxClientsUnlimited)
	ch.IsMaxFamilyClientsUnlimited = clonePtr(ch.IsMaxFamilyClientsUnlimited)
	ch.IsMaxFamilyClientsInherited = clonePtr(ch.IsMaxFamilyClientsInherited)
	ch.DeleteDelay = clonePtr(ch.DeleteDelay)
	ch.IsForcedSilence = clonePtr(ch.IsForcedSilence)
	ch.BannerMode = clonePtr(ch.BannerMode)

	return ch
}
