package teamspeak

import "strconv"

// Permission names a permission by id or by name.
//
// The server accepts either — permid=… or permsid=… — and every command that
// takes a permission takes exactly one of the two. Two optional parameters let
// a caller send both or neither; this sends one.
//
// The zero Permission names nothing: a command given one fails with
// ErrInvalidCommand rather than sending it.
type Permission struct {
	name string
	id   PermissionID
}

// PermissionByID names a permission by its numeric id.
//
// Ids are assigned by the server build and can differ between versions; a
// name is the portable choice, an id the compact one.
func PermissionByID(id PermissionID) Permission {
	return Permission{id: id}
}

// PermissionByName names a permission by its name, such as
// "i_client_talk_power". The perm package names the ones servers know:
// PermissionByName(perm.ClientTalkPower).
func PermissionByName(name string) Permission {
	return Permission{name: name}
}

// ID returns the permission's id, or 0 if it is named rather than numbered.
func (p Permission) ID() PermissionID {
	return p.id
}

// Name returns the permission's name, or "" if it is numbered rather than
// named.
func (p Permission) Name() string {
	return p.name
}

// IsZero reports whether p names no permission.
func (p Permission) IsZero() bool {
	return p.name == "" && p.id == 0
}

// String returns the permission's name if it has one, its id otherwise, and
// "no permission" for the zero Permission.
func (p Permission) String() string {
	switch {
	case p.name != "":
		return p.name
	case p.id != 0:
		return "permission " + strconv.FormatUint(uint64(p.id), 10)
	default:
		return "no permission"
	}
}
