package teamspeak

import (
	"strconv"
	"strings"
)

// Status is the state of a client's connection. Later versions may add
// states; a switch over them should have a default case.
type Status int

const (
	// StatusDisconnected is a client with no connection: before Connect, after
	// Disconnect, or after a drop until a reconnect starts.
	StatusDisconnected Status = iota
	// StatusConnecting is a client between Connect and the end of the
	// handshake.
	StatusConnecting
	// StatusConnected is a client whose connection is ready for commands.
	StatusConnected
)

var statusNames = [...]string{
	StatusDisconnected: "disconnected",
	StatusConnecting:   "connecting",
	StatusConnected:    "connected",
}

// String names the status, such as "connected".
func (s Status) String() string {
	if s >= 0 && int(s) < len(statusNames) {
		return statusNames[s]
	}

	return "status " + strconv.Itoa(int(s))
}

// ServerFamily is the server generation a version string belongs to. Its
// zero value is ServerFamilyUnknown. Later versions may add families; a switch
// over them should have a default case.
type ServerFamily string

const (
	// ServerFamilyUnknown means the server has not identified itself yet, or
	// named a version this module does not recognise. It is the zero value.
	ServerFamilyUnknown ServerFamily = ""
	// ServerFamilyTS3 is TeamSpeak 3, which hashes client uids with SHA-1.
	ServerFamilyTS3 ServerFamily = "ts3"
	// ServerFamilyTS6 is TeamSpeak 6, which hashes client uids with SHA-256.
	ServerFamilyTS6 ServerFamily = "ts6"
)

// String names the family, "unknown" for ServerFamilyUnknown.
func (f ServerFamily) String() string {
	if f == ServerFamilyUnknown {
		return "unknown"
	}

	return string(f)
}

// ServerFamilyForVersion picks the family from a version string such as
// "6.0.0-beta13.1", as the server reports it (virtualserver_version).
//
// It lives here rather than in a client because both clients ask it: the voice
// protocol reads the version from initserver, and a ServerQuery client from
// the version command, and a client that answered differently from the other
// would disagree about the same server.
func ServerFamilyForVersion(version string) ServerFamily {
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil {
		return ServerFamilyUnknown
	}
	switch {
	case major == 3:
		return ServerFamilyTS3
	case major >= 6:
		return ServerFamilyTS6
	default:
		return ServerFamilyUnknown
	}
}
