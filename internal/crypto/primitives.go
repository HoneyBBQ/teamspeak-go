package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

var errInvalidKeyLength = errors.New("invalid key length")

const (
	curve25519KeySize = 32
	clampMaskLow      = 248
	clampMaskHigh     = 127
	clampHighBit      = 64
	sharedSignBit     = 0x80
	privateKeyTopMask = 0x7F
)

// GenerateTemporaryKey returns an ephemeral Curve25519 key pair as (public,
// private); the public key is the Edwards point sent as clientek's ek.
func GenerateTemporaryKey() ([]byte, []byte, error) {
	privateKey := make([]byte, curve25519KeySize)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, nil, err
	}
	ClampScalar(privateKey)
	sc, err := scalar.NewFromBits(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := curve.NewEdwardsPoint().MulBasepoint(curve.ED25519_BASEPOINT_TABLE, sc).MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// Sign signs data's SHA-256 digest with priv as ASN.1 ECDSA, the form the
// clientek proof takes.
func Sign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	return ecdsa.SignASN1(rand.Reader, priv, hash[:])
}

// VerifySign reports whether sig is pub's ASN.1 ECDSA signature over data's
// SHA-256 digest; it checks the server's proof of the license in initivexpand2.
func VerifySign(pub *ecdsa.PublicKey, data, sig []byte) bool {
	hash := sha256.Sum256(data)

	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

// ClampScalar applies Curve25519 clamping to key in place; keys shorter than
// 32 bytes are left unchanged.
func ClampScalar(key []byte) {
	if len(key) < curve25519KeySize {
		return
	}
	key[0] &= clampMaskLow
	key[curve25519KeySize-1] &= clampMaskHigh
	key[curve25519KeySize-1] |= clampHighBit
}

// GetSharedSecret2 returns the 64-byte initivexpand2 shared secret: the SHA-512
// of the license-derived publicKey times privateKey. The point negation and
// sign-bit flip match TeamSpeak's arithmetic, so both sides agree.
func GetSharedSecret2(publicKey, privateKey []byte) ([]byte, error) {
	if len(publicKey) != curve25519KeySize || len(privateKey) != curve25519KeySize {
		return nil, errInvalidKeyLength
	}

	privateKeyCpy := make([]byte, curve25519KeySize)
	copy(privateKeyCpy, privateKey)
	privateKeyCpy[curve25519KeySize-1] &= privateKeyTopMask
	sc, err := scalar.NewFromBits(privateKeyCpy)
	if err != nil {
		return nil, err
	}

	pub := curve.NewEdwardsPoint()
	err = pub.UnmarshalBinary(publicKey)
	if err != nil {
		return nil, err
	}
	pub.Neg(pub)

	sharedPoint := curve.NewEdwardsPoint().Mul(pub, sc)
	shared, err := sharedPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}
	shared[curve25519KeySize-1] ^= sharedSignBit

	hash := sha512.Sum512(shared)

	return hash[:], nil
}
