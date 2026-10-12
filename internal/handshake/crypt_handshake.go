// Package handshake implements the client's side of the TeamSpeak 3 connection
// handshake: the Init1 packet exchange, including the RSA puzzle, and the
// initivexpand2 key exchange that checks the server's license chain.
package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// InitVersion is the client build timestamp every Init1 packet the client
// sends starts with; it names a real client release, 3.5.0.
const InitVersion = 1566914096 // 3.5.0 [Stable]
const (
	initVersionLen = 4
	initTypeLen    = 1
	initStepLen    = 21
)

// ErrMalformedInit1 reports an Init1 packet the client cannot answer: empty,
// of the wrong length for its step, or naming a step the server never sends.
var ErrMalformedInit1 = errors.New("malformed Init1 packet")

// StartInit1 returns the Init1 packet data that opens the exchange.
func StartInit1() ([]byte, error) {
	return buildInit1StartPacket()
}

// ProcessInit1 returns the client's answer to the server's Init1 packet data.
//
// One RSA challenge is answered per connection, whose Crypt is its own: each
// costs up to a second of squarings, and a second answer would choose a new
// alpha behind the clientinitiv already sent. The same challenge again means
// the answer was lost, and gets the same answer without solving anything; a
// different one gets none, a nil answer with a nil error.
//
// An unknown step is answered with none, as the other client does: Init1 is
// unauthenticated, so anyone who can reach the port can send one, and a
// datagram that never gets a correct answer must not end a connection attempt.
// A step the client does know but cannot answer — empty (nil included), the
// wrong length, an RSA puzzle out of range — is an error wrapping
// ErrMalformedInit1 or the puzzle's own error, never a panic: the bytes come
// from the network. StartInit1, not ProcessInit1, opens the exchange.
func ProcessInit1(tc *crypto.Crypt, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrMalformedInit1)
	}

	switch data[0] {
	case 0x7F:
		// The server asks to start over.
		return buildInit1StartPacket()
	case 0:
		return buildInit1Step1Packet(data)
	case 1:
		return buildInit1Step2Packet(data)
	case 2:
		return buildInit1Step3Packet(data)
	case 3:
		return buildInit1Step4Packet(tc, data)
	default:
		return nil, nil
	}
}

func wrongLength(step byte, got, want int) error {
	return fmt.Errorf("%w: step %d is %d bytes, want %d", ErrMalformedInit1, step, got, want)
}

func buildInit1StartPacket() ([]byte, error) {
	sendData := make([]byte, initVersionLen+initTypeLen+4+4+8)
	binary.BigEndian.PutUint32(sendData[0:4], InitVersion)
	sendData[4] = 0x00
	nowUnix := time.Now().Unix()
	nowUnix = max(nowUnix, 0)
	nowUnix = min(nowUnix, int64(math.MaxUint32))
	binary.BigEndian.PutUint32(sendData[5:9], uint32(nowUnix))
	_, err := rand.Read(sendData[9:13])
	if err != nil {
		return nil, err
	}

	return sendData, nil
}

func buildInit1Step1Packet(data []byte) ([]byte, error) {
	if len(data) != initStepLen {
		return nil, wrongLength(0, len(data), initStepLen)
	}
	sendData := make([]byte, initTypeLen+16+4)
	sendData[0] = 0x01
	tsRand := binary.LittleEndian.Uint32(data[initVersionLen+initTypeLen+4 : initVersionLen+initTypeLen+8])
	binary.BigEndian.PutUint32(sendData[initTypeLen+16:initTypeLen+16+4], tsRand)

	return sendData, nil
}

func buildInit1Step2Packet(data []byte) ([]byte, error) {
	if len(data) != initStepLen {
		return nil, wrongLength(1, len(data), initStepLen)
	}
	sendData := make([]byte, initVersionLen+initTypeLen+16+4)
	binary.BigEndian.PutUint32(sendData[0:4], InitVersion)
	sendData[4] = 0x02
	copy(sendData[5:25], data[1:21])

	return sendData, nil
}

func buildInit1Step3Packet(data []byte) ([]byte, error) {
	if want := initVersionLen + initTypeLen + 16 + 4; len(data) != want {
		return nil, wrongLength(2, len(data), want)
	}
	sendData := make([]byte, initTypeLen+64+64+4+100)
	sendData[0] = 0x03
	sendData[initTypeLen+64-1] = 1
	sendData[initTypeLen+64+64-1] = 1
	binary.BigEndian.PutUint32(sendData[initTypeLen+64+64:initTypeLen+64+64+4], 1)

	return sendData, nil
}

func buildInit1Step4Packet(tc *crypto.Crypt, data []byte) ([]byte, error) {
	if want := initTypeLen + 64 + 64 + 4 + 100; len(data) != want {
		return nil, wrongLength(3, len(data), want)
	}
	if tc.RSAChallenge != nil {
		if !bytes.Equal(tc.RSAChallenge, data) {
			return nil, nil
		}

		return bytes.Clone(tc.RSAAnswer), nil
	}
	// Read as unsigned and compared before narrowing, so a level near 2^32
	// cannot wrap into range on a 32-bit int.
	rawLevel := binary.BigEndian.Uint32(data[1+128 : 1+128+4])
	if rawLevel > crypto.MaxRSAChallengeLevel {
		return nil, fmt.Errorf("%w: RSA challenge level %d is above %d",
			ErrMalformedInit1, rawLevel, crypto.MaxRSAChallengeLevel)
	}
	y, err := tc.SolveRsaChallenge(data, 1, int(rawLevel))
	if err != nil {
		return nil, err
	}

	tc.AlphaTmp = make([]byte, 10)
	_, err = rand.Read(tc.AlphaTmp)
	if err != nil {
		return nil, err
	}

	cmd := wire.BuildCommandOrdered("clientinitiv", [][2]string{
		{"alpha", base64.StdEncoding.EncodeToString(tc.AlphaTmp)},
		{"omega", tc.Identity.PublicKey()},
		{"ot", "1"},
		{"ip", ""},
	})
	cmdBytes := []byte(cmd)

	sendData := make([]byte, initVersionLen+initTypeLen+232+64+len(cmdBytes))
	binary.BigEndian.PutUint32(sendData[0:4], InitVersion)
	sendData[4] = 0x04
	copy(sendData[5:5+232], data[1:1+232])
	copy(sendData[5+232:5+232+64], y)
	copy(sendData[5+232+64:], cmdBytes)
	tc.RSAChallenge = bytes.Clone(data)
	tc.RSAAnswer = bytes.Clone(sendData)

	return sendData, nil
}
