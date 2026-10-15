package serverquery

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKey is the key an SSH server presented, as this package hands it to a
// caller's check. It is a struct of its own rather than the ssh library's
// type, so a policy can be written without importing that library.
//
// Experimental: this package may change in a minor release.
type HostKey struct {
	// Hostname is the address that was dialled, as host:port.
	Hostname string
	// KeyType is the key's algorithm, such as "ssh-ed25519", as the server
	// named it.
	KeyType string
	// Fingerprint is the key's SHA-256 fingerprint in OpenSSH form, such as
	// "SHA256:HR5y2ZQ…". It is what ssh-keygen -lf and ssh-keyscan print, so
	// it can be compared with what the server's operator published without
	// this package being involved.
	Fingerprint string
	// Key is the key's wire encoding: the blob a known_hosts line carries in
	// base64. It is last because it is the one field most callers never read.
	Key []byte
}

// String describes the key by its host, algorithm and fingerprint.
func (h HostKey) String() string {
	return fmt.Sprintf("%s %s %s", h.Hostname, h.KeyType, h.Fingerprint)
}

// InsecureIgnoreHostKey returns a check that accepts any key, which leaves the
// connection open to whoever answers the port: the query password goes to that
// server, and one that is not the server expected is indistinguishable from
// it.
//
// It is named so that the call site says out loud what it is giving up, and it
// is for a test or a throwaway server. [KnownHosts] is the check to use
// otherwise, and one of the two, or [SSHOptions.HostKeyCheck], has to be
// chosen: [SSH] refuses to dial without one.
//
// Experimental: this package may change in a minor release.
func InsecureIgnoreHostKey() func(HostKey) error {
	return func(HostKey) error {
		return nil
	}
}

// KnownHosts returns a check that verifies the server against the OpenSSH
// known_hosts file at path, in the format ssh-keyscan writes.
//
// The file is read once, here, when this is called. It is not read unless a
// caller names it: ~/.ssh/known_hosts is not assumed, because a library
// reading the user's home directory on its own is a surprise rather than a
// convenience.
//
// A host that is not in the file and a host whose key has changed are both
// refusals wrapping ErrHostKey; the wrapped error is the ssh library's own, so
// a caller can tell them apart.
//
// Experimental: this package may change in a minor release.
func KnownHosts(path string) (func(HostKey) error, error) {
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrHostKey, path, err)
	}

	return func(key HostKey) error {
		return checkAgainstKnownHosts(check, key)
	}, nil
}

// checkAgainstKnownHosts runs the ssh library's check for one HostKey. The
// library wants the address twice: once as the hostname to prefer, and once as
// the net.Addr it would have dialled.
func checkAgainstKnownHosts(check ssh.HostKeyCallback, key HostKey) error {
	public, err := ssh.ParsePublicKey(key.Key)
	if err != nil {
		return fmt.Errorf("%w: %s: unreadable host key: %w", ErrHostKey, key.Hostname, err)
	}
	err = check(key.Hostname, hostAddr(key.Hostname), public)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrHostKey, key.Hostname, err)
	}

	return nil
}

// hostAddr is a host:port net.Addr, so that a policy written against the ssh
// library's callback can be driven from here without that library appearing in
// the exported API.
type hostAddr string

func (a hostAddr) Network() string { return "tcp" }
func (a hostAddr) String() string  { return string(a) }

// hostKeyCallback converts a caller's check into the library's callback,
// filling in what the handshake itself knows.
func hostKeyCallback(addr string, check func(HostKey) error) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		return check(HostKey{
			Hostname:    addr,
			KeyType:     key.Type(),
			Key:         key.Marshal(),
			Fingerprint: ssh.FingerprintSHA256(key),
		})
	}
}
