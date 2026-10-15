package serverquery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const testHostKeyAddr = "127.0.0.1:10022"

// The failures a test makes a policy report, named so the assertion can match
// the same value that was returned.
var (
	errWrongHost = errors.New("wrong host")
	errNoConn    = errors.New("no connection")
)

// A generated key pair, as the server side of a handshake would present it.
func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	return signer.PublicKey()
}

// writeKnownHosts writes a known_hosts file holding one host's key, in the
// format ssh-keyscan writes, and returns its path.
func writeKnownHosts(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{addr}, key)
	err := os.WriteFile(path, []byte(line+"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing the known_hosts fixture: %v", err)
	}

	return path
}

// hostKeyFrom builds the value the transport hands a policy, from what the
// handshake would know.
func hostKeyFrom(key ssh.PublicKey) HostKey {
	return HostKey{
		Hostname:    testHostKeyAddr,
		KeyType:     key.Type(),
		Key:         key.Marshal(),
		Fingerprint: ssh.FingerprintSHA256(key),
	}
}

// The key recorded for the host is accepted.
func TestKnownHosts_AcceptsTheRecordedKey(t *testing.T) {
	key := newTestHostKey(t)
	path := writeKnownHosts(t, testHostKeyAddr, key)

	check, err := KnownHosts(path)
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	err = check(hostKeyFrom(key))
	if err != nil {
		t.Errorf("the recorded key was refused: %v", err)
	}
}

// A different key for the same host is refused, and the refusal is
// distinguishable from the host simply being unknown: one is a possible
// impersonation, the other only needs the key added.
func TestKnownHosts_RefusesAChangedKey(t *testing.T) {
	recorded := newTestHostKey(t)
	other := newTestHostKey(t)
	path := writeKnownHosts(t, testHostKeyAddr, recorded)

	check, err := KnownHosts(path)
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}

	err = check(hostKeyFrom(other))
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("a changed key = %v, want ErrHostKey", err)
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("the refusal does not carry the library's error: %v", err)
	}
	if len(keyErr.Want) == 0 {
		t.Error("a changed key was reported as an unknown host: Want is empty")
	}
}

// A host not in the file is refused, and its Want is empty, which is what
// tells a caller it is unknown rather than changed.
func TestKnownHosts_RefusesAnUnknownHost(t *testing.T) {
	key := newTestHostKey(t)
	path := writeKnownHosts(t, "other.example.com:10022", key)

	check, err := KnownHosts(path)
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}

	err = check(hostKeyFrom(key))
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("an unknown host = %v, want ErrHostKey", err)
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) != 0 {
		t.Errorf("an unknown host should carry a KeyError with no Want: %v", err)
	}
}

// A file that is not there is reported when the policy is built, before
// anything is dialled.
func TestKnownHosts_ReportsAMissingFile(t *testing.T) {
	_, err := KnownHosts(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("KnownHosts of a missing file = %v, want ErrHostKey", err)
	}
}

// A key blob that cannot be read is a refusal rather than a panic or an
// accidental pass.
func TestKnownHosts_RefusesAnUnreadableKey(t *testing.T) {
	key := newTestHostKey(t)
	path := writeKnownHosts(t, testHostKeyAddr, key)

	check, err := KnownHosts(path)
	if err != nil {
		t.Fatalf("KnownHosts: %v", err)
	}
	err = check(HostKey{Hostname: testHostKeyAddr, Key: []byte("not a key"), KeyType: "ssh-ed25519"})
	if !errors.Is(err, ErrHostKey) {
		t.Errorf("an unreadable key = %v, want ErrHostKey", err)
	}
}

// The deliberately insecure policy accepts anything, which is the whole of its
// contract.
func TestInsecureIgnoreHostKey_AcceptsAnything(t *testing.T) {
	check := InsecureIgnoreHostKey()
	err := check(HostKey{})
	if err != nil {
		t.Errorf("InsecureIgnoreHostKey refused an empty key: %v", err)
	}
	err = check(hostKeyFrom(newTestHostKey(t)))
	if err != nil {
		t.Errorf("InsecureIgnoreHostKey refused a key: %v", err)
	}
}

// An SSH dialer that would dial by itself has to say how to check the host
// key, and the error names every way to do it.
func TestNew_RefusesAnSSHDialerWithNoHostKeyPolicy(t *testing.T) {
	_, err := New(SSH(testHostKeyAddr, "serveradmin", "pw"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New with no host key policy = %v, want ErrInvalidConfig", err)
	}
	for _, want := range []string{"HostKeyCheck", "KnownHosts", "InsecureIgnoreHostKey"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s: %v", want, err)
		}
	}
}

// A policy is enough, and a connection the caller opens needs none: there the
// key is the caller's to check, and the transport never sees it.
func TestNew_AcceptsAnSSHDialerThatCanCheckTheHostKey(t *testing.T) {
	d := SSHWith(testHostKeyAddr, "serveradmin", "pw",
		SSHOptions{HostKeyCheck: InsecureIgnoreHostKey()})
	_, err := New(d)
	if err != nil {
		t.Errorf("New with a host key policy = %v, want it accepted", err)
	}

	d = SSHWith(testHostKeyAddr, "serveradmin", "pw", SSHOptions{Open: func(_ context.Context, _ string) (SSHConn, error) {
		return stubConn{}, nil
	}})
	_, err = New(d)
	if err != nil {
		t.Errorf("New with a caller-opened connection = %v, want it accepted", err)
	}
}

// stubConn is an SSHConn a test supplies where the connection's own behaviour
// is not what is under test.
type stubConn struct{}

// Shell reports no connection: the test only checks that the dialer is
// accepted, and never starts a session on it.
func (stubConn) Shell() (SSHShell, error) { return nil, errNoConn }

func (stubConn) Close() error { return nil }

// A host key check given alongside Open is refused: the connection Open
// returns has already made its handshake, so the transport never sees the key
// and the check could never run. Accepting it would read as a verified server
// when nothing was verified, so the message says why.
func TestNew_RefusesAHostKeyCheckThatCouldNeverRun(t *testing.T) {
	open := func(_ context.Context, _ string) (SSHConn, error) { return stubConn{}, nil }

	for name, check := range map[string]func(HostKey) error{
		"a check that accepts": InsecureIgnoreHostKey(),
		"a check that refuses": func(HostKey) error { return errWrongHost },
	} {
		d := SSHWith(testHostKeyAddr, "serveradmin", "pw",
			SSHOptions{Open: open, HostKeyCheck: check})
		_, err := New(d)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s with Open: New = %v, want ErrInvalidConfig", name, err)

			continue
		}
		for _, want := range []string{"HostKeyCheck", "Open", "handshake", "never"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s with Open: the error does not mention %q: %v", name, want, err)
			}
		}
	}
}

// The check runs before the login, so a server that is not the expected one
// never sees the password: the key is handed to the policy during the
// handshake, and a refusal ends the connection there.
func TestHostKeyCallback_CarriesWhatTheHandshakeKnows(t *testing.T) {
	key := newTestHostKey(t)
	var seen HostKey
	callback := hostKeyCallback(testHostKeyAddr, func(h HostKey) error {
		seen = h

		return nil
	})

	err := callback("ignored", nil, key)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if seen.Hostname != testHostKeyAddr {
		t.Errorf("Hostname = %q, want the dialled address", seen.Hostname)
	}
	if seen.KeyType != key.Type() {
		t.Errorf("KeyType = %q, want %q", seen.KeyType, key.Type())
	}
	if !strings.HasPrefix(seen.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want the OpenSSH SHA-256 form", seen.Fingerprint)
	}
	if len(seen.Key) == 0 {
		t.Error("Key is empty")
	}
}

// A policy that refuses ends the handshake with its own error, unchanged.
func TestHostKeyCallback_PropagatesARefusal(t *testing.T) {
	callback := hostKeyCallback(testHostKeyAddr, func(HostKey) error { return errWrongHost })

	err := callback("ignored", nil, newTestHostKey(t))
	if !errors.Is(err, errWrongHost) {
		t.Errorf("callback = %v, want the policy's own error", err)
	}
}

// The address the policy is shown is the one dialled, which is what a
// known_hosts entry is keyed on.
func TestHostKeyCallback_UsesTheDialledAddress(t *testing.T) {
	var got string
	callback := hostKeyCallback("ts.example.com:22", func(h HostKey) error {
		got = h.Hostname

		return nil
	})
	_ = callback("", nil, newTestHostKey(t))

	if got != "ts.example.com:22" {
		t.Errorf("Hostname = %q, want the dialled address", got)
	}
}
