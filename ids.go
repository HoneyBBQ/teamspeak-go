package teamspeak

// Identifiers.
//
// Every id the server hands out is a number, and most of them share a width,
// so as plain integers any one could be passed where another belongs — a
// channel id to a command that wanted a client, a database id where a session
// id goes — and the server would act on whatever it found under that number.
// Each kind of id is its own type so the compiler catches the swap instead.

// ChannelID identifies a channel (cid). 0 names no channel; as a parent it is
// the top level.
type ChannelID uint64

// ClientID identifies a connected client for the length of its session (clid).
// It changes with every connection; ClientDBID and UID do not.
type ClientID uint16

// ClientDBID identifies a client's persistent record in the server database
// (cldbid), which outlives its sessions.
type ClientDBID uint64

// ServerGroupID identifies a server group (sgid).
type ServerGroupID uint64

// ChannelGroupID identifies a channel group (cgid).
type ChannelGroupID uint64

// PermissionID is a permission's numeric id (permid). Permission names a
// permission by id or by name.
type PermissionID uint32

// IconID identifies an icon by the CRC32 of its file; 0 is no icon, and the
// built-in icons use small fixed ids such as 100 or 300.
type IconID uint32

// ServerID identifies a virtual server within an instance.
type ServerID uint64

// UID is a client's unique identifier (client_unique_identifier): the base64
// hash of its identity's public key, stable across connections and servers.
// The hash depends on the server — SHA-1 on TS3, SHA-256 on TS6 — so the same
// identity has a different UID on each.
type UID string
