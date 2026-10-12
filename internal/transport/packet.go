package transport

import (
	"encoding/binary"
	"time"
)

// PacketType is the packet type in the low four bits of a header's type byte.
type PacketType byte

// The packet types of the voice protocol, as numbered on the wire.
const (
	PacketTypeVoice        PacketType = 0
	PacketTypeVoiceWhisper PacketType = 1
	PacketTypeCommand      PacketType = 2
	PacketTypeCommandLow   PacketType = 3
	PacketTypePing         PacketType = 4
	PacketTypePong         PacketType = 5
	PacketTypeAck          PacketType = 6
	PacketTypeAckLow       PacketType = 7
	PacketTypeInit1        PacketType = 8
)

// PacketFlags is the flags in the high four bits of a header's type byte.
type PacketFlags byte

// The packet flags of the voice protocol.
const (
	// PacketFlagFragmented marks the first and the last fragment of a split
	// command; the fragments between carry no flag.
	PacketFlagFragmented PacketFlags = 0x10
	// PacketFlagNewProtocol is set by the client on every Command and
	// CommandLow packet it sends.
	PacketFlagNewProtocol PacketFlags = 0x20
	// PacketFlagCompressed marks a payload compressed with QuickLZ.
	PacketFlagCompressed PacketFlags = 0x40
	// PacketFlagUnencrypted marks a payload sent in the clear, its MAC replaced
	// by the fake signature.
	PacketFlagUnencrypted PacketFlags = 0x80
)

// Packet is one packet of the voice protocol, decrypted. TypeFlagged is the
// header's type byte, a PacketType and PacketFlags combined; GenerationID
// counts how often ID has wrapped past 65535.
type Packet struct {
	ReceivedAt   time.Time
	Data         []byte
	GenerationID uint32
	ID           uint16
	ClientID     uint16
	TypeFlagged  byte
}

// Type returns the packet type from the low bits of TypeFlagged.
func (p *Packet) Type() PacketType {
	return PacketType(p.TypeFlagged & 0x0F)
}

// Flags returns the flags from the high bits of TypeFlagged.
func (p *Packet) Flags() PacketFlags {
	return PacketFlags(p.TypeFlagged & 0xF0)
}

// IsUnencrypted reports whether the packet has PacketFlagUnencrypted set.
func (p *Packet) IsUnencrypted() bool {
	return (p.Flags() & PacketFlagUnencrypted) != 0
}

// BuildC2SHeader returns the 5-byte client-to-server header: u16 packet ID,
// u16 client ID, then the type byte. It is also the encryption's associated data.
func (p *Packet) BuildC2SHeader() []byte {
	header := make([]byte, 5)
	binary.BigEndian.PutUint16(header[0:2], p.ID)
	binary.BigEndian.PutUint16(header[2:4], p.ClientID)
	header[4] = p.TypeFlagged

	return header
}

// ParseS2CHeader reads a 3-byte server-to-client header, u16 packet ID then
// the type byte; the server sends no client ID. raw must hold 3 bytes.
func (p *Packet) ParseS2CHeader(raw []byte) {
	p.ID = binary.BigEndian.Uint16(raw[0:2])
	p.TypeFlagged = raw[2]
}

// ParseC2SHeader reads a 5-byte client-to-server header, the inverse of
// BuildC2SHeader. raw must hold 5 bytes.
func (p *Packet) ParseC2SHeader(raw []byte) {
	p.ID = binary.BigEndian.Uint16(raw[0:2])
	p.ClientID = binary.BigEndian.Uint16(raw[2:4])
	p.TypeFlagged = raw[4]
}
