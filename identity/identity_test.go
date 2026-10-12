package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Formatting an identity, or logging it, must not reveal the private key. Its
// String used to return the key itself, so %v and slog.Any leaked it.
func TestIdentityNeverPrintsItsPrivateKey(t *testing.T) {
	id, err := Generate(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, _ := strings.Cut(id.Export(), ":")

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("connecting", slog.Any("identity", id))
	for name, out := range map[string]string{
		"%v":     fmt.Sprintf("%v", id),
		"String": id.String(),
		"slog":   logged.String(),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s output contains the private key: %s", name, out)
		}
	}
}

func TestIdentityExportRoundtrip(t *testing.T) {
	id, err := Generate(context.Background(), 0)
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	id2, err := Parse(id.Export())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if id.Export() != id2.Export() {
		t.Errorf("exported identity mismatch: %q vs %q", id.Export(), id2.Export())
	}
	if id.Offset() != id2.Offset() {
		t.Errorf("Offset mismatch: %d vs %d", id.Offset(), id2.Offset())
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"",
		"notvalidnocodon",
		"invalid==base64:0",
		"dGVzdA==:notanumber",
	}
	for _, s := range cases {
		_, err := Parse(s)
		if err == nil {
			t.Errorf("Parse(%q) expected error, got nil", s)
		}
	}
}

func TestIdentitySecurityLevel(t *testing.T) {
	id, err := Generate(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	lvl := id.SecurityLevel()
	if lvl < 0 {
		t.Errorf("SecurityLevel should be >= 0, got %d", lvl)
	}
}

func TestIdentityUpgradeToLevel(t *testing.T) {
	id, err := Generate(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	before := id.Export()
	upgraded, err := id.UpgradeToLevel(context.Background(), 1)
	if err != nil {
		t.Fatalf("UpgradeToLevel(1) failed: %v", err)
	}
	if upgraded.SecurityLevel() < 1 {
		t.Errorf("SecurityLevel after upgrade = %d, want >= 1", upgraded.SecurityLevel())
	}
	if id.Export() != before {
		t.Error("UpgradeToLevel changed the identity it was called on")
	}
	if upgraded.PublicKey() != id.PublicKey() {
		t.Error("the upgraded identity has a different key")
	}
}

func TestIdentityUpgradeCtxCancelled(t *testing.T) {
	id, err := Generate(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err = id.UpgradeToLevel(ctx, 100)
	if err == nil {
		t.Error("expected context cancellation error")
	}
}

func TestUIDIsDeterministic(t *testing.T) {
	id, err := Generate(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	uid1 := UID(id.PublicKey(), UIDSHA1)
	uid2 := UID(id.PublicKey(), UIDSHA1)
	if uid1 != uid2 {
		t.Error("UID is not deterministic")
	}
	// SHA-1 produces 20 bytes → base64 = 28 chars
	if len(uid1) != 28 {
		t.Errorf("UID length = %d, want 28", len(uid1))
	}
}

// The UID hash is not negotiable on the wire: TS3 hashes with SHA-1 and TS6 with
// SHA-256, so a client that assumes one silently computes a UID the other
// server never sends.
func TestUIDAlgorithmForVersion(t *testing.T) {
	tests := []struct {
		version string
		want    UIDAlgorithm
	}{
		{"3.13.8 [Build: 1779874471]", UIDSHA1},
		{"3.0.11 [Build: 1374563791]", UIDSHA1},
		{"6.0.0-beta13.1 [Build: 1790080330]", UIDSHA256},
		{"6.1.0", UIDSHA256},
		{"", UIDSHA1},
		{"unknown", UIDSHA1},
	}
	for _, tt := range tests {
		if got := UIDAlgorithmForVersion(tt.version); got != tt.want {
			t.Errorf("UIDAlgorithmForVersion(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestUID_UsesTheRequestedAlgorithm(t *testing.T) {
	pub := "AAAA"

	// SHA-1 is 20 bytes and SHA-256 32, so the base64 lengths differ and the
	// digests cannot be confused for one another.
	sha1UID := UID(pub, UIDSHA1)
	sha256UID := UID(pub, UIDSHA256)
	if len(sha1UID) != 28 {
		t.Errorf("SHA-1 UID length = %d, want 28 (20 bytes base64)", len(sha1UID))
	}
	if len(sha256UID) != 44 {
		t.Errorf("SHA-256 UID length = %d, want 44 (32 bytes base64)", len(sha256UID))
	}
	if sha1UID == sha256UID {
		t.Error("SHA-1 and SHA-256 UIDs must differ")
	}
	// The no-argument form stays TS3-compatible for existing callers.
	if got := UID(pub, UIDSHA1); got != sha1UID {
		t.Errorf("default UID = %q, want the SHA-1 one %q", got, sha1UID)
	}
}

func TestIdentityRefusesLevelsPastSHA1(t *testing.T) {
	id, err := Generate(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []int{-1, MaxSecurityLevel + 1} {
		_, err = id.UpgradeToLevel(t.Context(), level)
		if !errors.Is(err, ErrInvalidLevel) {
			t.Errorf("UpgradeToLevel(%d) = %v, want ErrInvalidLevel", level, err)
		}
		_, err = Generate(t.Context(), level)
		if !errors.Is(err, ErrInvalidLevel) {
			t.Errorf("Generate(%d) = %v, want ErrInvalidLevel", level, err)
		}
	}
}

func TestIdentityRefusesToMarshal(t *testing.T) {
	id, err := Generate(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(struct {
		ID *Identity `json:"id"`
	}{id})
	if !errors.Is(err, ErrNotSerializable) {
		t.Errorf("json.Marshal = %s, %v; want ErrNotSerializable", out, err)
	}
	secret, _, _ := strings.Cut(id.Export(), ":")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{id, *id} {
			if got := fmt.Sprintf(verb, v); strings.Contains(got, secret) {
				t.Errorf("%T with %s leaks the key: %s", v, verb, got)
			}
		}
	}
}

func TestZeroIdentityDoesNotPanic(t *testing.T) {
	var zero Identity
	var nilID *Identity
	for _, id := range []*Identity{&zero, nilID} {
		_ = id.String()
		_ = fmt.Sprintf("%v", id)
		slog.New(slog.DiscardHandler).Info("x", slog.Any("id", id))
		if id.PublicKey() != "" || id.UID(UIDSHA1) != "" || id.Export() != "" || id.SecurityLevel() != 0 {
			t.Errorf("an identity without a key reports key material")
		}
		_, err := id.UpgradeToLevel(t.Context(), 1)
		if err == nil {
			t.Error("UpgradeToLevel on an identity without a key succeeded")
		}
	}
}
