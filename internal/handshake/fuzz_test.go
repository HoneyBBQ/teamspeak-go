package handshake_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
)

// FuzzProcessInit1 checks that no Init1 payload panics, and that each is
// answered, refused with an error, or, as documented, ignored: an unknown step,
// and a second RSA challenge, get no answer and no error. A step the client
// knows and can answer never does.
func FuzzProcessInit1(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x7F})
	f.Add(make([]byte, 21))
	step1 := make([]byte, 21)
	step1[0] = 1
	f.Add(step1)
	step3 := make([]byte, 233)
	step3[0] = 3
	step3[128] = 1 // n = 1
	f.Add(step3)

	id, err := identity.Parse(testIdentityStr)
	if err != nil {
		f.Fatalf("Parse: %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := handshake.ProcessInit1(context.Background(), crypto.NewCrypt(id), data)
		if err != nil && out != nil {
			t.Fatalf("an answer of %d bytes and an error: %v", len(out), err)
		}
		answered := len(data) > 0 && (data[0] <= 2 || data[0] == 0x7F)
		if err == nil && out == nil && (len(data) == 0 || answered) {
			t.Fatalf("a %d-byte payload got no answer and no error", len(data))
		}
	})
}

// FuzzParseLicenses checks that no license chain panics, whether it parses or
// derives a key.
func FuzzParseLicenses(f *testing.F) {
	license, err := base64.StdEncoding.DecodeString(testLicenseBase64)
	if err != nil {
		f.Fatalf("decode: %v", err)
	}
	f.Add(license)
	f.Add([]byte{1})
	// An intermediate block too short for its issuer.
	f.Add(append([]byte{1}, make([]byte, 43)...))
	server := make([]byte, 1+42)
	server[0] = 1
	server[1+33] = 2
	f.Add(server)

	f.Fuzz(func(_ *testing.T, data []byte) {
		chain, err := handshake.ParseLicenses(data)
		if err != nil {
			return
		}
		_, _ = chain.DeriveKey()
	})
}
