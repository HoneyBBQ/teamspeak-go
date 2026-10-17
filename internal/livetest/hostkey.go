//go:build integration

// Package livetest holds what the live tests of more than one package share.
package livetest

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// EnvSSHKnownHosts is a known_hosts file to verify the SSH host key against,
// when the caller has one. Without it the tests record the key the server
// presents and verify against that, so the check itself is always exercised;
// there is deliberately no way to accept any key.
const EnvSSHKnownHosts = "TEAMSPEAK_QUERY_SSH_KNOWN_HOSTS"

// errKeyRecorded ends the probe dial once the host key has been captured,
// before any authentication: the check runs first, which is the point.
var errKeyRecorded = errors.New("the host key has been recorded")

// PresentedHostKey is the host key the server at addr presents.
func PresentedHostKey(t *testing.T, addr string) ssh.PublicKey {
	t.Helper()
	// The host key is checked before authentication, so a probe that is
	// refused for its credentials has still seen the key.
	var key ssh.PublicKey
	probe := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(_ string, _ net.Addr, presented ssh.PublicKey) error {
			key = presented

			return errKeyRecorded
		},
	}
	// The dial is expected to fail — the callback refuses the key — which is
	// what ends the probe after the key has been captured.
	conn, _ := ssh.Dial("tcp", addr, probe)
	if conn != nil {
		_ = conn.Close()
	}
	if key == nil {
		t.Fatalf("the server at %s presented no host key", addr)
	}

	return key
}

// WriteKnownHosts writes a known_hosts file holding key for the host at addr,
// in a directory the test owns.
func WriteKnownHosts(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	err := os.WriteFile(path, []byte(knownhosts.Line([]string{addr}, key)+"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}

	return path
}

// KnownHostsFor returns the known_hosts file an SSH test verifies against: the
// one the caller named, or one recorded from the server itself. There is no
// path that accepts any key, so the check is exercised either way.
func KnownHostsFor(t *testing.T, addr string) string {
	t.Helper()
	if path := os.Getenv(EnvSSHKnownHosts); path != "" {
		return path
	}

	key := PresentedHostKey(t, addr)
	t.Logf("verifying %s against the key it presented: %s", addr, ssh.FingerprintSHA256(key))

	return WriteKnownHosts(t, addr, key)
}
