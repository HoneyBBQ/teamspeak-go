package client_test

import (
	"testing"

	"github.com/honeybbq/teamspeak-go/client"

	"github.com/honeybbq/teamspeak-go/identity"
)

func TestParseServerCapabilities(t *testing.T) {
	tests := []struct {
		version string
		family  client.ServerFamily
		uidAlgo identity.UIDAlgorithm
		major   int
	}{
		{"3.13.8 [Build: 1779874471]", client.ServerFamilyTS3, identity.UIDSHA1, 3},
		{"3.0.11 [Build: 1374563791]", client.ServerFamilyTS3, identity.UIDSHA1, 3},
		{"6.0.0-beta13.1 [Build: 1790080330]", client.ServerFamilyTS6, identity.UIDSHA256, 6},
		{"6.1.0", client.ServerFamilyTS6, identity.UIDSHA256, 6},
		{"7.0.0", client.ServerFamilyTS6, identity.UIDSHA256, 7},
		// Never released as a server, but a version string should not be read
		// as the older generation by default.
		{"4.0.0", client.ServerFamilyUnknown, identity.UIDSHA1, 4},
		{"5.0.0", client.ServerFamilyUnknown, identity.UIDSHA1, 5},
		{"", client.ServerFamilyUnknown, identity.UIDSHA1, 0},
		{"unknown", client.ServerFamilyUnknown, identity.UIDSHA1, 0},
	}
	for _, tt := range tests {
		got := client.ParseServerCapabilities(tt.version)
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
