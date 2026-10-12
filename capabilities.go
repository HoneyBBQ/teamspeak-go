package teamspeak

import (
	"strconv"
	"strings"

	"github.com/honeybbq/teamspeak-go/identity"
)

// ServerFamily is the server generation a version string belongs to.
type ServerFamily string

const (
	// ServerFamilyTS3 is TeamSpeak 3, which hashes client uids with SHA-1.
	ServerFamilyTS3 ServerFamily = "ts3"
	// ServerFamilyTS6 is TeamSpeak 6, which hashes client uids with SHA-256.
	ServerFamilyTS6 ServerFamily = "ts6"
	// ServerFamilyUnknown means the server has not identified itself yet.
	ServerFamilyUnknown ServerFamily = "unknown"
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
// virtualserver_version, the one place the server names itself — so reading it
// costs no extra round trip.
type ServerCapabilities struct {
	// Version is the virtualserver_version string as the server sent it.
	Version string
	// Family is the server generation.
	Family ServerFamily
	// UIDAlgorithm is the hash the server uses for client_unique_identifier.
	//
	// Read from the family rather than offered as a setting: the server decides
	// this, and a client that picks differently never matches.
	UIDAlgorithm identity.UIDAlgorithm
	// Major is the parsed major version, or 0 when it could not be parsed.
	Major int
}

// ParseServerCapabilities reads a virtualserver_version value such as
// "6.0.0-beta13.1 [Build: 1790080330]".
func ParseServerCapabilities(version string) ServerCapabilities {
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil {
		major = 0
	}

	family := ServerFamilyUnknown
	switch {
	case major == 3:
		family = ServerFamilyTS3
	case major >= 6:
		family = ServerFamilyTS6
	}

	return ServerCapabilities{
		Version:      version,
		Major:        major,
		Family:       family,
		UIDAlgorithm: identity.UIDAlgorithmForVersion(version),
	}
}

// unknownServerCapabilities is the state before a server has identified itself.
//
// The family is honestly unknown, while the uid hash stays SHA-1 so behaviour
// before connecting is exactly what it was before TS6 support existed.
func unknownServerCapabilities() ServerCapabilities {
	return ParseServerCapabilities("")
}
