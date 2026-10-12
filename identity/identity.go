// Package identity creates, persists and inspects TeamSpeak client identities.
//
// An identity is a P-256 key pair plus a counter, the offset, whose hash with
// the public key sets the identity's security level. A server can demand a
// minimum level; raising it is deliberately expensive. The identity is what a
// server recognises across connections — its uid, groups and permissions hang
// off it — so it is generated once and kept.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the protocol's own security-level and uid hash
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/identitykey"
)

// init hands the private key to this module's own crypto, which needs it to
// sign and agree keys, without exporting it.
func init() { //nolint:gochecknoinits // the only way to share it with internal/ without exporting it
	identitykey.Register(func(v any) *ecdsa.PrivateKey {
		id, ok := v.(*Identity)
		if !ok || id == nil {
			return nil
		}

		return id.privateKey
	})
}

// ErrInvalidFormat reports an identity string Parse cannot read.
var ErrInvalidFormat = errors.New("invalid identity format")

// ErrInvalidLevel reports a security level outside 0 to MaxSecurityLevel.
var ErrInvalidLevel = errors.New("invalid security level")

// ErrNotSerializable is returned by MarshalJSON and MarshalText: an identity
// holds a private key, so it is stored only through Export, deliberately.
var ErrNotSerializable = errors.New("an identity is not marshalled; store Export's result instead")

// MaxSecurityLevel is the highest security level there is: the level counts
// zero bits of a SHA-1 digest, which has 160.
const MaxSecurityLevel = 160

const (
	decimalBase             = 10
	identityPartCount       = 2
	p256ScalarSize          = 32
	p256PointPrefix         = 0x04
	p256UncompressedKeySize = 65
	sha1NumBufSize          = 20
	bitsPerByte             = 8
)

// Identity is a TeamSpeak client identity. It is immutable: UpgradeToLevel
// returns a new one.
//
// Its private key is not exposed. String, GoString, LogValue and formatting
// with %v never reveal it, and MarshalJSON and MarshalText refuse with
// ErrNotSerializable, so an identity that reaches a log, an error message or
// an encoder does not leak; Export is the one way to get the secret form, for
// storing it. The zero Identity has no key: it formats safely, and New and
// Connect refuse it.
type Identity struct {
	privateKey *ecdsa.PrivateKey
	publicKey  string
	offset     uint64
}

// Generate creates an identity at the given security level, 0 to
// MaxSecurityLevel.
//
// Each level doubles the expected work, so a high level can take a long time;
// ctx bounds it.
func Generate(ctx context.Context, level int) (*Identity, error) {
	err := checkLevel(level)
	if err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newIdentity(priv, 0).UpgradeToLevel(ctx, level)
}

func newIdentity(priv *ecdsa.PrivateKey, offset uint64) *Identity {
	return &Identity{privateKey: priv, publicKey: encodePublicKey(priv), offset: offset}
}

func checkLevel(level int) error {
	if level < 0 || level > MaxSecurityLevel {
		return fmt.Errorf("%w: %d is not between 0 and %d", ErrInvalidLevel, level, MaxSecurityLevel)
	}

	return nil
}

// Parse reads an identity from the form Export writes.
func Parse(s string) (*Identity, error) {
	parts := strings.Split(s, ":")
	if len(parts) != identityPartCount {
		return nil, ErrInvalidFormat
	}
	dBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	offset, err := strconv.ParseUint(parts[1], decimalBase, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
	if err != nil {
		// Older identity strings may store a scalar without its leading zero
		// bytes; normalise to SEC 1's fixed size.
		if len(dBytes) >= p256ScalarSize {
			return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
		}
		padded := make([]byte, p256ScalarSize)
		copy(padded[p256ScalarSize-len(dBytes):], dBytes)
		priv, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), padded)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
		}
	}

	return newIdentity(priv, offset), nil
}

// Export returns the identity in the form Parse reads, private key included.
// Store it as you would a password. An identity without a key exports as "".
func (id *Identity) Export() string {
	if !id.hasKey() {
		return ""
	}
	d, err := id.privateKey.Bytes()
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(d) + ":" + strconv.FormatUint(id.offset, decimalBase)
}

// Offset returns the counter that, hashed with the public key, sets the
// security level.
func (id *Identity) Offset() uint64 {
	if id == nil {
		return 0
	}

	return id.offset
}

// String describes the identity by its TeamSpeak 3 UID, without its private
// key.
func (id *Identity) String() string {
	if !id.hasKey() {
		return "identity (none)"
	}

	return "identity " + string(id.UID(UIDSHA1)) + " (private key redacted)"
}

// GoString is String, so %#v redacts too.
func (id *Identity) GoString() string { return id.String() }

// LogValue keeps the private key out of structured logs.
func (id *Identity) LogValue() slog.Value {
	if !id.hasKey() {
		return slog.StringValue("identity (none)")
	}

	return slog.GroupValue(slog.String("uid_sha1", string(id.UID(UIDSHA1))), slog.Int("level", id.SecurityLevel()))
}

// MarshalJSON refuses with ErrNotSerializable; store Export's result instead.
func (id *Identity) MarshalJSON() ([]byte, error) {
	return nil, ErrNotSerializable
}

// MarshalText refuses with ErrNotSerializable; store Export's result instead.
func (id *Identity) MarshalText() ([]byte, error) {
	return nil, ErrNotSerializable
}

// PublicKey returns the public key in TeamSpeak's encoding: base64 DER of the
// curve point. An identity without a key returns "".
func (id *Identity) PublicKey() string {
	if id == nil {
		return ""
	}

	return id.publicKey
}

func encodePublicKey(priv *ecdsa.PrivateKey) string {
	if priv == nil {
		return ""
	}
	pubBytes, err := priv.PublicKey.Bytes()
	if err != nil {
		return ""
	}
	if len(pubBytes) != p256UncompressedKeySize || pubBytes[0] != p256PointPrefix {
		return ""
	}

	x := new(big.Int).SetBytes(pubBytes[1 : 1+p256ScalarSize])
	y := new(big.Int).SetBytes(pubBytes[1+p256ScalarSize : p256UncompressedKeySize])

	data := struct {
		BitInfo asn1.BitString
		Size    int
		X       *big.Int
		Y       *big.Int
	}{
		BitInfo: asn1.BitString{Bytes: []byte{0x00}, BitLength: 1},
		Size:    p256ScalarSize,
		X:       x,
		Y:       y,
	}
	bytes, err := asn1.Marshal(data)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(bytes)
}

// UID returns the identity's unique identifier under the given algorithm. An
// identity without a key returns "".
func (id *Identity) UID(algorithm UIDAlgorithm) teamspeak.UID {
	if !id.hasKey() {
		return ""
	}

	return UID(id.PublicKey(), algorithm)
}

// SecurityLevel is the number of trailing zero bits in SHA-1 of the public key
// followed by the offset; 0 for an identity without a key.
func (id *Identity) SecurityLevel() int {
	if !id.hasKey() {
		return 0
	}
	h := sha1.New() //nolint:gosec // the protocol's own security-level hash
	h.Write([]byte(id.PublicKey()))
	var numBuf [sha1NumBufSize]byte
	h.Write(strconv.AppendUint(numBuf[:0], id.offset, decimalBase))

	return countTrailingZeros(h.Sum(nil))
}

// UpgradeToLevel returns an identity with the same key and the lowest offset,
// from this one's on, that reaches level; id itself is unchanged. A level
// outside 0 to MaxSecurityLevel is refused with ErrInvalidLevel, and ctx
// bounds the search.
func (id *Identity) UpgradeToLevel(ctx context.Context, level int) (*Identity, error) {
	err := checkLevel(level)
	if err != nil {
		return nil, err
	}
	if !id.hasKey() {
		return nil, fmt.Errorf("%w: no private key", ErrInvalidFormat)
	}
	prefix := []byte(id.PublicKey())
	h := sha1.New() //nolint:gosec // the protocol's own security-level hash
	var numBuf [sha1NumBufSize]byte
	offset := id.offset
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		h.Reset()
		h.Write(prefix)
		h.Write(strconv.AppendUint(numBuf[:0], offset, decimalBase))
		if countTrailingZeros(h.Sum(nil)) >= level {
			return &Identity{privateKey: id.privateKey, publicKey: id.publicKey, offset: offset}, nil
		}
		offset++
	}
}

func (id *Identity) hasKey() bool {
	return id != nil && id.privateKey != nil
}

// countTrailingZeros counts zero bits from the least significant bit of the
// first byte, which is how TeamSpeak defines the security level.
func countTrailingZeros(data []byte) int {
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros += bitsPerByte

			continue
		}
		for i := range bitsPerByte {
			if b&(1<<uint(i)) != 0 {
				return zeros
			}
			zeros++
		}
	}

	return zeros
}

// UIDAlgorithm names the hash a server uses for client_unique_identifier.
// Later versions may add algorithms; a switch over them should have a default
// case.
//
// TeamSpeak 3 hashes the public key with SHA-1 (20 bytes); TeamSpeak 6 switched
// to SHA-256 (32 bytes). The algorithm is not negotiated on the wire, so a
// client that guesses wrong computes a uid that matches nothing the server
// sends, and recognising itself by uid silently fails.
type UIDAlgorithm string

const (
	// UIDSHA1 is TeamSpeak 3's uid hash.
	UIDSHA1 UIDAlgorithm = "sha1"
	// UIDSHA256 is TeamSpeak 6's.
	UIDSHA256 UIDAlgorithm = "sha256"
)

// UIDAlgorithmForVersion picks the uid hash from a virtualserver_version
// string, such as "6.0.0-beta13.1".
func UIDAlgorithmForVersion(version string) UIDAlgorithm {
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil || major < 6 {
		return UIDSHA1
	}

	return UIDSHA256
}

// UID returns the unique identifier of a public key, in TeamSpeak's encoding,
// under the given algorithm. Any algorithm other than UIDSHA256 is SHA-1.
func UID(publicKey string, algorithm UIDAlgorithm) teamspeak.UID {
	if algorithm == UIDSHA256 {
		sum := sha256.Sum256([]byte(publicKey))

		return teamspeak.UID(base64.StdEncoding.EncodeToString(sum[:]))
	}

	sum := sha1.Sum([]byte(publicKey)) //nolint:gosec // TeamSpeak 3's uid hash

	return teamspeak.UID(base64.StdEncoding.EncodeToString(sum[:]))
}
