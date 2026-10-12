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
)

// ErrInvalidFormat reports an identity string Parse cannot read.
var ErrInvalidFormat = errors.New("invalid identity format")

const (
	decimalBase             = 10
	identityPartCount       = 2
	p256ScalarSize          = 32
	p256PointPrefix         = 0x04
	p256UncompressedKeySize = 65
	sha1NumBufSize          = 20
	bitsPerByte             = 8
)

// Identity is a TeamSpeak client identity.
//
// Its String and LogValue methods never reveal the private key, so an identity
// that reaches a log or an error message does not leak; Export is the one way
// to get the secret form, for storing it.
type Identity struct {
	PrivateKey *ecdsa.PrivateKey
	Offset     uint64
}

// Generate creates an identity at the given security level.
//
// Each level doubles the expected work, so a high level can take a long time;
// ctx bounds it.
func Generate(ctx context.Context, level int) (*Identity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{PrivateKey: priv}

	err = id.UpgradeToLevel(ctx, level)
	if err != nil {
		return nil, err
	}

	return id, nil
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

	return &Identity{PrivateKey: priv, Offset: offset}, nil
}

// Export returns the identity in the form Parse reads, private key included.
// Store it as you would a password.
func (id *Identity) Export() string {
	d, err := id.PrivateKey.Bytes()
	if err != nil {
		return ":" + strconv.FormatUint(id.Offset, decimalBase)
	}

	return base64.StdEncoding.EncodeToString(d) + ":" + strconv.FormatUint(id.Offset, decimalBase)
}

// String describes the identity without its private key. It used to return the
// key itself, so formatting an identity with %v leaked it.
func (id *Identity) String() string {
	return "identity " + id.UID(UIDSHA1) + " (private key redacted)"
}

// LogValue keeps the private key out of structured logs.
func (id *Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("uid_sha1", id.UID(UIDSHA1)), slog.Int("level", id.SecurityLevel()))
}

// PublicKey returns the public key in TeamSpeak's encoding: base64 DER of the
// curve point.
func (id *Identity) PublicKey() string {
	pubBytes, err := id.PrivateKey.PublicKey.Bytes()
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

// UID returns the identity's unique identifier under the given algorithm.
func (id *Identity) UID(algorithm UIDAlgorithm) string {
	return UID(id.PublicKey(), algorithm)
}

// SecurityLevel is the number of trailing zero bits in SHA-1 of the public key
// followed by the offset.
func (id *Identity) SecurityLevel() int {
	h := sha1.New() //nolint:gosec // the protocol's own security-level hash
	h.Write([]byte(id.PublicKey()))
	var numBuf [sha1NumBufSize]byte
	h.Write(strconv.AppendUint(numBuf[:0], id.Offset, decimalBase))

	return countTrailingZeros(h.Sum(nil))
}

// UpgradeToLevel advances the offset until the security level reaches level.
func (id *Identity) UpgradeToLevel(ctx context.Context, level int) error {
	prefix := []byte(id.PublicKey())
	h := sha1.New() //nolint:gosec // the protocol's own security-level hash
	var numBuf [sha1NumBufSize]byte
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		h.Reset()
		h.Write(prefix)
		h.Write(strconv.AppendUint(numBuf[:0], id.Offset, decimalBase))
		if countTrailingZeros(h.Sum(nil)) >= level {
			return nil
		}
		id.Offset++
	}
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
// under the given algorithm.
func UID(publicKey string, algorithm UIDAlgorithm) string {
	if algorithm == UIDSHA256 {
		sum := sha256.Sum256([]byte(publicKey))

		return base64.StdEncoding.EncodeToString(sum[:])
	}

	sum := sha1.Sum([]byte(publicKey)) //nolint:gosec // TeamSpeak 3's uid hash

	return base64.StdEncoding.EncodeToString(sum[:])
}
