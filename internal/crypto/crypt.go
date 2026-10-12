package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/honeybbq/teamspeak-go/identity"
)

var (
	errRSAChallengeOutRange = errors.New("RSA challenge level out of range")
	errInvalidPublicPoint   = errors.New("invalid public key point encoding")
	errSharedSecretCompute  = errors.New("failed to compute ECDH shared secret")
)

const (
	decimalBase             = 10
	identityPartCount       = 2
	p256ScalarSize          = 32
	p256PointPrefix         = 0x04
	p256UncompressedKeySize = 65
	rsaChallengeBlockSize   = 64
	maxRSAChallengeLevel    = 1000000
	packetTypeMask          = 0x0F
	generationIDShift       = 32
	fromServerShift         = 40
	fakeSignatureSize       = 8
	ivAlphaSize             = 10
	sha1NumBufSize          = 20
	bitsPerByte             = 8
)

type Crypt struct {
	Identity           *identity.Identity
	CachedKeys         map[uint64]KeyNonce
	IvStruct           []byte
	FakeSignature      []byte
	AlphaTmp           []byte
	keyMu              sync.Mutex
	CryptoInitComplete bool
}

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

func NewCrypt(id *identity.Identity) *Crypt {
	return &Crypt{
		Identity:      id,
		FakeSignature: make([]byte, fakeSignatureSize),
		CachedKeys:    make(map[uint64]KeyNonce),
	}
}

func (tc *Crypt) SolveRsaChallenge(data []byte, offset int, level int) ([]byte, error) {
	if level < 0 || level > maxRSAChallengeLevel {
		return nil, errRSAChallengeOutRange
	}
	x := new(big.Int).SetBytes(data[offset : offset+rsaChallengeBlockSize])
	n := new(big.Int).SetBytes(data[offset+rsaChallengeBlockSize : offset+2*rsaChallengeBlockSize])

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
	sharedSecret := tc.getSharedSecret(serverPubKey)
	if len(sharedSecret) == 0 {
		return errSharedSecretCompute
	}

	return tc.SetSharedSecret(alphaBytes, betaBytes, sharedSecret)
}

func (tc *Crypt) SetSharedSecret(alpha, beta, sharedKey []byte) error {
	tc.IvStruct = make([]byte, ivAlphaSize+len(beta))
	for i := range alpha {
		tc.IvStruct[i] = sharedKey[i] ^ alpha[i]
	}
	for i := range beta {
		tc.IvStruct[ivAlphaSize+i] = sharedKey[ivAlphaSize+i] ^ beta[i]
	}

	h := sha1.New()
	h.Write(tc.IvStruct)
	copy(tc.FakeSignature, h.Sum(nil)[:fakeSignatureSize])

	tc.CryptoInitComplete = true

	return nil
}

func (tc *Crypt) DebugCryptoState() (int, string) {
	if len(tc.IvStruct) == 0 {
		return 0, ""
	}

	return len(tc.IvStruct), hex.EncodeToString(tc.FakeSignature)
}

func (tc *Crypt) getSharedSecret(pub *ecdsa.PublicKey) []byte {
	privECDH, err := tc.Identity.PrivateKey.ECDH()
	if err != nil {
		return nil
	}
	pubECDH, err := pub.ECDH()
	if err != nil {
		return nil
	}
	keyArr, err := privECDH.ECDH(pubECDH)
	if err != nil {
		return nil
	}
	if len(keyArr) > p256ScalarSize {
		keyArr = keyArr[len(keyArr)-p256ScalarSize:]
	} else if len(keyArr) < p256ScalarSize {
		aligned := make([]byte, p256ScalarSize)
		copy(aligned[p256ScalarSize-len(keyArr):], keyArr)
		keyArr = aligned
	}
	h := sha1.New()
	h.Write(keyArr)

	return h.Sum(nil)
}

func Hash512(data []byte) []byte {
	sum := sha512.Sum512(data)

	return sum[:]
}

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
