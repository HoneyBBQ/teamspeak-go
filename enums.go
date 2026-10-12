package teamspeak

import "strconv"

// Enumerations the server reports and accepts as small integers. Each value is
// the number on the wire. Later versions may add values, and the server may
// send one this package does not name: String describes it by number, and a
// switch over an enumeration should have a default case.

// GroupType is what kind of group a server or channel group is (type).
type GroupType int

const (
	// GroupTemplate is a template: the server copies it to create the groups
	// of a new virtual server, and no client can be a member.
	GroupTemplate GroupType = 0
	// GroupRegular is an ordinary group that voice clients join.
	GroupRegular GroupType = 1
	// GroupQuery is a group for ServerQuery clients.
	GroupQuery GroupType = 2
)

var groupTypeNames = [...]string{
	GroupTemplate: "template",
	GroupRegular:  "regular",
	GroupQuery:    "query",
}

func (t GroupType) String() string {
	return enumName(t, groupTypeNames[:], "group type")
}

// GroupNameMode is where a group's name is shown beside a member's nickname
// (namemode).
type GroupNameMode int

const (
	// GroupNameHidden shows no group name.
	GroupNameHidden GroupNameMode = 0
	// GroupNameBefore shows the group name before the nickname.
	GroupNameBefore GroupNameMode = 1
	// GroupNameAfter shows the group name after the nickname.
	GroupNameAfter GroupNameMode = 2
)

var groupNameModeNames = [...]string{
	GroupNameHidden: "hidden",
	GroupNameBefore: "before nickname",
	GroupNameAfter:  "after nickname",
}

func (m GroupNameMode) String() string {
	return enumName(m, groupNameModeNames[:], "name mode")
}

// TokenType is which kind of group a privilege key grants (token_type).
type TokenType int

const (
	// TokenServerGroup grants a server group.
	TokenServerGroup TokenType = 0
	// TokenChannelGroup grants a channel group in one channel.
	TokenChannelGroup TokenType = 1
)

var tokenTypeNames = [...]string{
	TokenServerGroup:  "server group",
	TokenChannelGroup: "channel group",
}

func (t TokenType) String() string {
	return enumName(t, tokenTypeNames[:], "token type")
}

// ClientType is what kind of connection a client is (client_type).
type ClientType int

const (
	// ClientTypeVoice is a voice client, such as the TeamSpeak application or
	// this SDK's client.
	ClientTypeVoice ClientType = 0
	// ClientTypeQuery is a ServerQuery client.
	ClientTypeQuery ClientType = 1
)

var clientTypeNames = [...]string{
	ClientTypeVoice: "voice",
	ClientTypeQuery: "query",
}

func (t ClientType) String() string {
	return enumName(t, clientTypeNames[:], "client type")
}

// Codec is a voice codec: the one a channel uses (channel_codec), and the one
// a voice packet is encoded with.
type Codec uint8

const (
	// CodecSpeexNarrowband is Speex at 8 kHz. Current clients no longer play it.
	CodecSpeexNarrowband Codec = 0
	// CodecSpeexWideband is Speex at 16 kHz. Current clients no longer play it.
	CodecSpeexWideband Codec = 1
	// CodecSpeexUltraWideband is Speex at 32 kHz. Current clients no longer
	// play it.
	CodecSpeexUltraWideband Codec = 2
	// CodecCELTMono is CELT at 48 kHz. Current clients no longer play it.
	CodecCELTMono Codec = 3
	// CodecOpusVoice is Opus tuned for speech, mono.
	CodecOpusVoice Codec = 4
	// CodecOpusMusic is Opus tuned for music, stereo.
	CodecOpusMusic Codec = 5
)

var codecNames = [...]string{
	CodecSpeexNarrowband:    "Speex narrowband",
	CodecSpeexWideband:      "Speex wideband",
	CodecSpeexUltraWideband: "Speex ultra-wideband",
	CodecCELTMono:           "CELT mono",
	CodecOpusVoice:          "Opus voice",
	CodecOpusMusic:          "Opus music",
}

func (c Codec) String() string {
	return enumName(c, codecNames[:], "codec")
}

// PermissionTarget is what a permission is set on, as permfind reports it (t).
type PermissionTarget int

const (
	// PermissionTargetServerGroup is a permission set on a server group.
	PermissionTargetServerGroup PermissionTarget = 0
	// PermissionTargetClient is a permission set on a client, server-wide.
	PermissionTargetClient PermissionTarget = 1
	// PermissionTargetChannel is a permission set on a channel.
	PermissionTargetChannel PermissionTarget = 2
	// PermissionTargetChannelGroup is a permission set on a channel group.
	PermissionTargetChannelGroup PermissionTarget = 3
	// PermissionTargetChannelClient is a permission set on a client within one
	// channel.
	PermissionTargetChannelClient PermissionTarget = 4
)

var permissionTargetNames = [...]string{
	PermissionTargetServerGroup:   "server group",
	PermissionTargetClient:        "client",
	PermissionTargetChannel:       "channel",
	PermissionTargetChannelGroup:  "channel group",
	PermissionTargetChannelClient: "channel client",
}

func (t PermissionTarget) String() string {
	return enumName(t, permissionTargetNames[:], "permission target")
}

// enumName names v from names, indexed by value, or describes it by number: the
// server may send a value newer than this package, and printing it beats
// printing nothing.
func enumName[T ~int | ~uint8](v T, names []string, kind string) string {
	if v >= 0 && int(v) < len(names) && names[v] != "" {
		return names[v]
	}

	return kind + " " + strconv.Itoa(int(v))
}
