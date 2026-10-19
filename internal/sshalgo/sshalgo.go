// Package sshalgo holds the SSH algorithm choices a ServerQuery client makes
// that the library's defaults get wrong for a TeamSpeak server.
package sshalgo

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

// HostKeyAlgorithms is the library's own list of host key algorithms with
// rsa-sha2-512 moved ahead of rsa-sha2-256.
//
// A TeamSpeak 3 server (measured on 3.13.8) offers both and signs the key
// exchange with rsa-sha2-512 whichever one was negotiated. The library prefers rsa-sha2-256,
// so it negotiates that, receives a rsa-sha2-512 signature, and refuses the
// handshake with "invalid signature algorithm". Preferring rsa-sha2-512 makes
// the two agree, and a server that signs with what was negotiated, such as
// TeamSpeak 6, is served the same way. Every other algorithm keeps its place.
// See the "Server behaviour the SDK works around" section of the serverquery
// package documentation.
func HostKeyAlgorithms() []string {
	algorithms := ssh.SupportedAlgorithms().HostKeys
	first := slices.Index(algorithms, ssh.KeyAlgoRSASHA512)
	second := slices.Index(algorithms, ssh.KeyAlgoRSASHA256)
	if first < 0 || second < 0 || first < second {
		return algorithms
	}
	algorithms[first], algorithms[second] = algorithms[second], algorithms[first]

	return algorithms
}
