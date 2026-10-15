package client

import (
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// ServerCapabilities describes what the connected server is, and what that
// means for the caller.
//
// TS3 and TS6 differ in ways that stay invisible until something breaks. The
// clearest: the server hashes a client's public key with SHA-1 on TS3 and
// SHA-256 on TS6, so a client that assumes either one computes a
// client_unique_identifier the other server never sends.
//
// Everything here comes from the handshake — initserver carries
// virtualserver_version, the one place the server names itself, along with its
// name, icon, banner and welcome message — so reading it costs no extra round
// trip. It is one record of what the handshake said rather than a getter per
// field.
type ServerCapabilities struct {
	// Version is the virtualserver_version string as the server sent it.
	Version string
	// Name is the virtual server's name (virtualserver_name).
	Name string
	// HostBannerImageURL is the host banner image's URL
	// (virtualserver_hostbanner_gfx_url), or "" when none is set.
	HostBannerImageURL string
	// WelcomeMessage is the message shown on connecting
	// (virtualserver_welcomemessage), as the server sent it, BBCode included.
	WelcomeMessage string
	// Family is the server generation.
	Family ServerFamily
	// UIDAlgorithm is the hash the server uses for client_unique_identifier.
	//
	// Read from the family rather than offered as a setting: the server decides
	// this, and a client that picks differently never matches.
	UIDAlgorithm identity.UIDAlgorithm
	// ServerUID is the virtual server's unique identifier
	// (virtualserver_unique_identifier), or "" when the server did not send
	// it.
	ServerUID string
	// HostMessage is the message the server asks clients to show
	// (virtualserver_hostmessage), or "" when none is set.
	HostMessage string
	// Major is the parsed major version, or 0 when it could not be parsed.
	Major int
	// ServerID is the virtual server's id (virtualserver_id).
	ServerID teamspeak.ServerID
	// HostMessageMode is how HostMessage is to be shown
	// (virtualserver_hostmessage_mode). The server may send a value
	// teamspeak.HostMessageMode does not name; compare it against the
	// constants.
	HostMessageMode teamspeak.HostMessageMode
	// IconID is the server's icon (virtualserver_icon_id), or 0 for none. The
	// server sends the icon's CRC32, sometimes as a negative 32-bit number;
	// this is the unsigned value, which names the icon file.
	IconID teamspeak.IconID
}

// parseServerCapabilities reads what a server says about itself in initserver.
//
// initserver is the command's parameters. To read a version string alone, such
// as "6.0.0-beta13.1 [Build: 1790080330]", pass it as virtualserver_version.
func parseServerCapabilities(initserver map[string]string) ServerCapabilities {
	version := initserver["virtualserver_version"]
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil {
		major = 0
	}

	serverID, _ := strconv.ParseUint(initserver["virtualserver_id"], 10, 64)
	hostMessageMode, err := strconv.Atoi(initserver["virtualserver_hostmessage_mode"])
	if err != nil {
		hostMessageMode = 0
	}

	return ServerCapabilities{
		ServerID:           teamspeak.ServerID(serverID),
		ServerUID:          initserver["virtualserver_unique_identifier"],
		HostMessage:        initserver["virtualserver_hostmessage"],
		HostMessageMode:    teamspeak.HostMessageMode(hostMessageMode),
		Version:            version,
		Major:              major,
		Family:             teamspeak.ServerFamilyForVersion(version),
		UIDAlgorithm:       identity.UIDAlgorithmForVersion(version),
		Name:               initserver["virtualserver_name"],
		IconID:             wire.ParseIconID[teamspeak.IconID](initserver["virtualserver_icon_id"]),
		HostBannerImageURL: strings.TrimSpace(initserver["virtualserver_hostbanner_gfx_url"]),
		WelcomeMessage:     initserver["virtualserver_welcomemessage"],
	}
}

// unknownServerCapabilities is the state before a server has identified
// itself: the family unknown, the uid hash SHA-1.
func unknownServerCapabilities() ServerCapabilities {
	return parseServerCapabilities(nil)
}
