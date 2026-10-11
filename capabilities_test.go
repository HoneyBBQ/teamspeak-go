package teamspeak_test

import (
	"testing"

	"github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/crypto"
)

func TestParseServerCapabilities(t *testing.T) {
	tests := []struct {
		version string
		family  teamspeak.ServerFamily
		uidAlgo crypto.UidAlgorithm
		major   int
	}{
		{"3.13.8 [Build: 1779874471]", teamspeak.ServerFamilyTS3, crypto.UidSha1, 3},
		{"3.0.11 [Build: 1374563791]", teamspeak.ServerFamilyTS3, crypto.UidSha1, 3},
		{"6.0.0-beta13.1 [Build: 1790080330]", teamspeak.ServerFamilyTS6, crypto.UidSha256, 6},
		{"6.1.0", teamspeak.ServerFamilyTS6, crypto.UidSha256, 6},
		{"7.0.0", teamspeak.ServerFamilyTS6, crypto.UidSha256, 7},
		// Never released as a server, but a version string should not be read
		// as the older generation by default.
		{"4.0.0", teamspeak.ServerFamilyUnknown, crypto.UidSha1, 4},
		{"5.0.0", teamspeak.ServerFamilyUnknown, crypto.UidSha1, 5},
		{"", teamspeak.ServerFamilyUnknown, crypto.UidSha1, 0},
		{"unknown", teamspeak.ServerFamilyUnknown, crypto.UidSha1, 0},
	}
	for _, tt := range tests {
		got := teamspeak.ParseServerCapabilities(tt.version)
		if got.Family != tt.family {
			t.Errorf("ParseServerCapabilities(%q).Family = %q, want %q", tt.version, got.Family, tt.family)
		}
		if got.Major != tt.major {
			t.Errorf("ParseServerCapabilities(%q).Major = %d, want %d", tt.version, got.Major, tt.major)
		}
		// The whole point of the type: reading the family is only useful if it
		// agrees with the hash the server actually applies.
		if got.UIDAlgorithm != tt.uidAlgo {
			t.Errorf("ParseServerCapabilities(%q).UIDAlgorithm = %q, want %q", tt.version, got.UIDAlgorithm, tt.uidAlgo)
		}
		if got.Version != tt.version {
			t.Errorf("ParseServerCapabilities(%q).Version = %q, want it preserved", tt.version, got.Version)
		}
	}
}
