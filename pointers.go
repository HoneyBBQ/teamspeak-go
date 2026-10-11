package teamspeak

// Pointer helpers for the optional fields of the options structs.
//
// A nil pointer means "omit this parameter", which the protocol distinguishes
// from an empty value: clearing a channel password takes `channel_password=`,
// while leaving it alone takes no parameter at all. Without these, callers would
// write a local variable for every optional field they want to set.

// String returns a pointer to v, for an optional string field.
func String(v string) *string { return new(v) }

// IntOf returns a pointer to v, for an optional signed 32-bit field such as
// ChannelCodec.
func IntOf(v int32) *int32 { return new(v) }

// UintOf returns a pointer to v, for an optional unsigned field such as
// ParentID.
func UintOf(v uint64) *uint64 { return new(v) }

// BoolOf returns a pointer to v, for an optional boolean field such as
// ChannelFlagPermanent.
func BoolOf(v bool) *bool { return new(v) }
