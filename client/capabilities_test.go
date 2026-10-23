package client_test

import (
	"slices"
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
		got := client.ParseServerCapabilities(map[string]string{"virtualserver_version": tt.version})
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

// initserver carries the welcome message alongside the version. The name, icon
// and banner are not kept here: the view follows their edits.
func TestParseServerCapabilities_WelcomeMessage(t *testing.T) {
	got := client.ParseServerCapabilities(map[string]string{
		"virtualserver_version":        "3.13.8 [Build: 1779874471]",
		"virtualserver_welcomemessage": "Welcome to [B]TeamSpeak[/B]",
	})
	if got.WelcomeMessage != "Welcome to [B]TeamSpeak[/B]" {
		t.Errorf("WelcomeMessage = %q", got.WelcomeMessage)
	}
	if got.Family != client.ServerFamilyTS3 {
		t.Errorf("Family = %q, want ts3", got.Family)
	}
}

func TestParseServerCapabilities_NoWelcomeMessage(t *testing.T) {
	got := client.ParseServerCapabilities(map[string]string{"virtualserver_version": "6.1.0"})
	if got.WelcomeMessage != "" || got.Extensions != nil {
		t.Errorf("got %+v, want no welcome message or extensions", got)
	}
}

func TestParseServerCapabilities_Extensions(t *testing.T) {
	tests := []struct {
		name string
		list string
		want []string
	}{
		// As TeamSpeak 6 6.0.0-beta13.1 sends them.
		{"ts6", "FILETIME,STREAM_P2P", []string{"FILETIME", "STREAM_P2P"}},
		// TeamSpeak 3 sends the key empty.
		{"ts3", "", nil},
		{"blanks and repeats", " B ,,A,B, ", []string{"B", "A"}},
		{"only separators", " , ,", nil},
		{"names the SDK does not know", "SOMETHING_NEW,FILETIME", []string{"SOMETHING_NEW", "FILETIME"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.ParseServerCapabilities(map[string]string{"virtualserver_capability_extensions": tt.list})
			if !slices.Equal(got.Extensions, tt.want) {
				t.Errorf("Extensions = %q, want %q", got.Extensions, tt.want)
			}
		})
	}
	if got := client.ParseServerCapabilities(nil).Extensions; len(got) != 0 {
		t.Errorf("Extensions without the key = %q, want none", got)
	}
}

func TestServerCapabilities_HasExtension(t *testing.T) {
	got := client.ParseServerCapabilities(map[string]string{"virtualserver_capability_extensions": "FILETIME,STREAM_P2P"})
	if !got.HasExtension("STREAM_P2P") || !got.HasExtension("FILETIME") {
		t.Errorf("HasExtension misses a name in %q", got.Extensions)
	}
	if got.HasExtension("STREAM") || got.HasExtension("stream_p2p") || got.HasExtension("") {
		t.Errorf("HasExtension matched a name that is not in %q", got.Extensions)
	}
	if client.ParseServerCapabilities(nil).HasExtension("STREAM_P2P") {
		t.Error("an empty record has an extension")
	}
}
