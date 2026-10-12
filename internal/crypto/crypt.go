// Package crypto implements TeamSpeak 3 packet protection: the per-packet key
// and nonce derivation from the handshake's shared secret, AES-128 EAX with a
// 64-bit tag, the fake signature that authenticates unencrypted packets, and
// the key exchange primitives the handshake uses.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/identitykey"
)

var (
	errRSAChallengeOutRange = errors.New("RSA challenge level out of range")
	errRSAChallengeShort    = errors.New("RSA challenge too short")
	errRSAChallengeModulus  = errors.New("RSA challenge modulus is zero")
	errInvalidPublicPoint   = errors.New("invalid public key point encoding")
	errSharedSecretCompute  = errors.New("failed to compute ECDH shared secret")
	errSharedSecretLength   = errors.New("alpha, beta and the shared secret do not fit together")
	errNoPrivateKey         = errors.New("identity has no private key")
)

const (
	decimalBase             = 10
	identityPartCount       = 2
	p256ScalarSize          = 32
	p256PointPrefix         = 0x04
	p256UncompressedKeySize = 65
	rsaChallengeBlockSize   = 64
	// MaxRSAChallengeLevel is the most squarings SolveRsaChallenge performs.
	// TeamSpeak 3 and 6 servers both ask for 10000; ten times that is still a
	// fraction of a second, where a forged Init1 asking for millions would
	// hold the connection's read loop for much longer.
	MaxRSAChallengeLevel = 100000
	packetTypeMask       = 0x0F
	generationIDShift    = 32
	fromServerShift      = 40
	fakeSignatureSize    = 8
	ivAlphaSize          = 10
	sha1NumBufSize       = 20
	bitsPerByte          = 8
)

// Crypt holds a connection's crypto state: the identity it authenticates with,
// the IV struct agreed in the handshake, and the keys derived from it.
//
// The handshake writes the state on the connection's read loop while packets
// are sent from other goroutines, so the IV struct, the fake signature and the
// key cache are guarded by a mutex, and whether the handshake has completed is
// an atomic flag.
type Crypt struct {
	// Identity is the identity the connection authenticates with.
	Identity *identity.Identity
	// AlphaTmp is the alpha the client sent in clientinitiv. Only the read
	// loop touches it.
	AlphaTmp []byte
	// RSAChallenge is the Init1 RSA challenge the connection answered, and
	// RSAAnswer the Init1 packet that answered it; nil until then. One
	// connection answers one challenge. Only the read loop touches them.
	RSAChallenge []byte
	// RSAAnswer is the answer to RSAChallenge.
	RSAAnswer    []byte
	cachedKeys   map[uint64]KeyNonce
	ivStruct     []byte
	fakeSig      [fakeSignatureSize]byte
	keyMu        sync.Mutex
	initComplete atomic.Bool
}

// KeyNonce is a derived AES key and EAX nonce for one direction, packet type
// and generation, before the packet ID is mixed into the key.
type KeyNonce struct {
	Key   []byte
	Nonce []byte
	Gen   uint32
}

// makeCacheKey packs (fromServer, packetType, generationID) into a map key without allocating.
func makeCacheKey(fromServer bool, packetType byte, generationID uint32) uint64 {
	var key uint64
	if fromServer {
		key = 1 << fromServerShift
	}
	key |= uint64(packetType&packetTypeMask) << generationIDShift
	key |= uint64(generationID)

	return key
}

// NewCrypt returns a Crypt for id with no shared secret; until one is set,
// packets use the protocol's fixed dummy key.
func NewCrypt(id *identity.Identity) *Crypt {
	return &Crypt{
		Identity:   id,
		cachedKeys: make(map[uint64]KeyNonce),
	}
}

// String describes the crypt without its keys.
func (tc *Crypt) String() string {
	if tc.InitComplete() {
		return "crypt (initialised, keys redacted)"
	}

	return "crypt (dummy key)"
}

// GoString is String, so %#v redacts too.
func (tc *Crypt) GoString() string { return tc.String() }

// InitComplete reports whether the handshake has agreed a shared secret, after
// which packets are encrypted with keys derived from it instead of the fixed
// dummy key.
func (tc *Crypt) InitComplete() bool {
	return tc.initComplete.Load()
}

// FakeSignature returns the MAC that authenticates unencrypted packets: zero
// until the handshake completes, then derived from the IV struct.
func (tc *Crypt) FakeSignature() [fakeSignatureSize]byte {
	tc.keyMu.Lock()
	defer tc.keyMu.Unlock()

	return tc.fakeSig
}

// SolveRsaChallenge solves the Init1 step 4 puzzle: y = x^(2^level) mod n,
// with x and n the two 64-byte numbers at data[offset:], returned as 64
// big-endian bytes. The server uses it as a proof of work against floods. A
// level above MaxRSAChallengeLevel, data too short to hold x and n, and a zero
// n are refused.
func (tc *Crypt) SolveRsaChallenge(data []byte, offset int, level int) ([]byte, error) {
	if level < 0 || level > MaxRSAChallengeLevel {
		return nil, fmt.Errorf("%w: %d", errRSAChallengeOutRange, level)
	}
	if offset < 0 || len(data)-offset < 2*rsaChallengeBlockSize {
		return nil, errRSAChallengeShort
	}
	x := new(big.Int).SetBytes(data[offset : offset+rsaChallengeBlockSize])
	n := new(big.Int).SetBytes(data[offset+rsaChallengeBlockSize : offset+2*rsaChallengeBlockSize])
	if n.Sign() == 0 {
		return nil, errRSAChallengeModulus
	}

	// y = x^(2^level) mod n via repeated squaring.
	y := new(big.Int).Set(x)
	for range level {
		y.Mul(y, y)
		y.Mod(y, n)
	}

	res := y.Bytes()
	if len(res) < rsaChallengeBlockSize {
		aligned := make([]byte, rsaChallengeBlockSize)
		copy(aligned[rsaChallengeBlockSize-len(res):], res)
		res = aligned
	} else if len(res) > rsaChallengeBlockSize {
		res = res[len(res)-rsaChallengeBlockSize:]
	}

	return res, nil
}

// InitCrypto completes the legacy initivexpand key exchange: P-256 ECDH with
// the server's omega key, hashed with SHA-1 and combined with alpha and beta.
func (tc *Crypt) InitCrypto(alpha, beta, omega string) error {
	alphaBytes, err := base64.StdEncoding.DecodeString(alpha)
	if err != nil {
		return fmt.Errorf("invalid alpha: %w", err)
	}
	betaBytes, err := base64.StdEncoding.DecodeString(beta)
	if err != nil {
		return fmt.Errorf("invalid beta: %w", err)
	}
	omegaBytes, err := base64.StdEncoding.DecodeString(omega)
	if err != nil {
		return fmt.Errorf("invalid omega: %w", err)
	}
	serverPubKey, err := ImportPublicKey(omegaBytes)
	if err != nil {
		return err
	}
	sharedSecret, err := tc.getSharedSecret(serverPubKey)
	if err != nil {
		return err
	}

	return tc.SetSharedSecret(alphaBytes, betaBytes, sharedSecret)
}

// SetSharedSecret builds the IV struct by XORing alpha and beta into sharedKey,
// derives the fake signature from it, and marks crypto as initialised. alpha
// must be 10 bytes and sharedKey at least as long as the IV struct, 10 bytes
// plus beta; anything else is refused, since the values come from the server.
func (tc *Crypt) SetSharedSecret(alpha, beta, sharedKey []byte) error {
	if len(alpha) != ivAlphaSize || len(beta) == 0 || ivAlphaSize+len(beta) > len(sharedKey) {
		return errSharedSecretLength
	}
	ivStruct := make([]byte, ivAlphaSize+len(beta))
	for i := range alpha {
		ivStruct[i] = sharedKey[i] ^ alpha[i]
	}
	for i := range beta {
		ivStruct[ivAlphaSize+i] = sharedKey[ivAlphaSize+i] ^ beta[i]
	}

	sum := sha1.Sum(ivStruct)

	tc.keyMu.Lock()
	tc.ivStruct = ivStruct
	copy(tc.fakeSig[:], sum[:fakeSignatureSize])
	clear(tc.cachedKeys)
	tc.keyMu.Unlock()

	tc.initComplete.Store(true)

	return nil
}

func (tc *Crypt) getSharedSecret(pub *ecdsa.PublicKey) ([]byte, error) {
	priv := identitykey.PrivateKey(tc.Identity)
	if priv == nil {
		return nil, errNoPrivateKey
	}
	privECDH, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSharedSecretCompute, err)
	}
	pubECDH, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSharedSecretCompute, err)
	}
	keyArr, err := privECDH.ECDH(pubECDH)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSharedSecretCompute, err)
	}
	if len(keyArr) > p256ScalarSize {
		keyArr = keyArr[len(keyArr)-p256ScalarSize:]
	} else if len(keyArr) < p256ScalarSize {
		aligned := make([]byte, p256ScalarSize)
		copy(aligned[p256ScalarSize-len(keyArr):], keyArr)
		keyArr = aligned
	}
	sum := sha1.Sum(keyArr)

	return sum[:], nil
}

// Hash512 returns the SHA-512 digest of data; license blocks are hashed with it.
func Hash512(data []byte) []byte {
	sum := sha512.Sum512(data)

	return sum[:]
}

// ImportPublicKey parses a P-256 public key in TeamSpeak's ASN.1 encoding, as
// sent in omega, accepting both the current and the legacy field order.
func ImportPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	// Canonical format (TS5/TS6): {BitString, Size, X, Y}
	var canonical struct {
		BitInfo asn1.BitString
		Size    int
		X       *big.Int
		Y       *big.Int
	}
	_, canonicalErr := asn1.Unmarshal(data, &canonical)
	if canonicalErr == nil {
		encoded, err := encodeUncompressedP256Point(canonical.X, canonical.Y)
		if err != nil {
			return nil, err
		}

		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	}

	// Legacy format (TeamSpeak): {X, Y, BitString, Size}
	var legacy struct {
		X       *big.Int
		Y       *big.Int
		BitInfo asn1.BitString
		Size    int
	}
	_, err := asn1.Unmarshal(data, &legacy)
	if err != nil {
		return nil, err
	}

	encoded, err := encodeUncompressedP256Point(legacy.X, legacy.Y)
	if err != nil {
		return nil, err
	}

	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
}

func encodeUncompressedP256Point(x, y *big.Int) ([]byte, error) {
	if x == nil || y == nil {
		return nil, errInvalidPublicPoint
	}
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	const fieldSize = 32
	if len(xBytes) > fieldSize || len(yBytes) > fieldSize {
		return nil, errInvalidPublicPoint
	}

	point := make([]byte, 1+fieldSize+fieldSize)
	point[0] = p256PointPrefix
	copy(point[1+fieldSize-len(xBytes):1+fieldSize], xBytes)
	copy(point[1+2*fieldSize-len(yBytes):], yBytes)

	return point, nil
}
