package sshalgo_test

import (
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/honeybbq/teamspeak-go/internal/sshalgo"
)

func TestHostKeyAlgorithms_PrefersRSASHA512OverRSASHA256(t *testing.T) {
	got := sshalgo.HostKeyAlgorithms()
	first := slices.Index(got, ssh.KeyAlgoRSASHA512)
	second := slices.Index(got, ssh.KeyAlgoRSASHA256)
	if first < 0 || second < 0 {
		t.Fatalf("both RSA algorithms are expected in %v", got)
	}
	if first > second {
		t.Errorf("rsa-sha2-512 at %d comes after rsa-sha2-256 at %d in %v", first, second, got)
	}
}

func TestHostKeyAlgorithms_KeepsTheLibrarysAlgorithms(t *testing.T) {
	got := sshalgo.HostKeyAlgorithms()
	want := ssh.SupportedAlgorithms().HostKeys
	if len(got) != len(want) {
		t.Fatalf("got %d algorithms, the library has %d", len(got), len(want))
	}
	for _, algorithm := range want {
		if !slices.Contains(got, algorithm) {
			t.Errorf("%s is missing from %v", algorithm, got)
		}
	}
	// Only that pair moves: the algorithms before it stay where they were.
	if len(want) > 0 && got[0] != want[0] {
		t.Errorf("first algorithm = %s, want %s", got[0], want[0])
	}
}
