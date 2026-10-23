package client

import (
	"slices"
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/identity"
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
// virtualserver_version, the one place the server names itself, along with the
// protocol extensions it supports and the messages it greets a client with —
// so reading it costs no extra round trip. It is one record of what the
// handshake said rather than a getter per field. Only what holds for the whole
// connection is kept: the server's name, icon and banner can be edited while a
// client is connected, so they are read from the view, which follows the
// edits: ServerView.ServerName, ServerView.ServerIconID and
// ServerView.ServerBannerImageURL.
type ServerCapabilities struct {
	// Version is the virtualserver_version string as the server sent it.
	Version string
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
	// Extensions lists the optional protocol features the server says it
	// supports (virtualserver_capability_extensions), in the server's order
	// and each once, such as FILETIME and STREAM_P2P. It is empty when the
	// server names none, as a TeamSpeak 3 server does; test one with
	// HasExtension.
	//
	// It is what the server claims, read as sent; the SDK does not refuse a
	// command because a name is missing from it. ServerCapabilities and the
	// trace hooks hand out a copy, so changing the slice changes nothing in
	// the client.
	Extensions []string
	// Major is the parsed major version, or 0 when it could not be parsed.
	Major int
	// ServerID is the virtual server's id (virtualserver_id).
	ServerID teamspeak.ServerID
	// HostMessageMode is how HostMessage is to be shown
	// (virtualserver_hostmessage_mode). The server may send a value
	// teamspeak.HostMessageMode does not name; compare it against the
	// constants.
	HostMessageMode teamspeak.HostMessageMode
}

// HasExtension reports whether the server named the extension, such as
// "STREAM_P2P". The names are compared as sent, so case matters.
func (c ServerCapabilities) HasExtension(name string) bool {
	return slices.Contains(c.Extensions, name)
}

// clone returns c with a slice of its own, so a copy handed out cannot be used
// to change the client's record.
func (c ServerCapabilities) clone() ServerCapabilities {
	c.Extensions = slices.Clone(c.Extensions)

	return c
}

// parseExtensions reads the names of a comma-separated extension list, without
// blanks or repeats, in order. It returns nil when there are none.
func parseExtensions(list string) []string {
	var names []string
	for name := range strings.SplitSeq(list, ",") {
		name = strings.TrimSpace(name)
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}

	return names
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
		ServerID:        teamspeak.ServerID(serverID),
		ServerUID:       initserver["virtualserver_unique_identifier"],
		HostMessage:     initserver["virtualserver_hostmessage"],
		HostMessageMode: teamspeak.HostMessageMode(hostMessageMode),
		Version:         version,
		Major:           major,
		Family:          teamspeak.ServerFamilyForVersion(version),
		UIDAlgorithm:    identity.UIDAlgorithmForVersion(version),
		Extensions:      parseExtensions(initserver["virtualserver_capability_extensions"]),
		WelcomeMessage:  initserver["virtualserver_welcomemessage"],
	}
}

// unknownServerCapabilities is the state before a server has identified
// itself: the family unknown, the uid hash SHA-1.
func unknownServerCapabilities() ServerCapabilities {
	return parseServerCapabilities(nil)
}
