//go:build integration

package client_test

import (
	"strings"
	"testing"
)

// Once crypto init completes the client accepts the public dummy key for one
// packet only, the server's Ack of clientek. This checks against the live
// server that nothing else arrives under it: a packet the client dropped for
// failing real decryption is logged, so a session that works and logged no
// such drop is one where the server never needed the old fallback.
func TestIntegration_NoDummyKeyPacketsAfterCryptoInit(t *testing.T) {
	addr := requireTeamSpeakAddr(t)
	peer := requireIntegrationPeer(t, addr)

	_, err := peer.ListChannels(t.Context())
	requireNoErr(t, err)
	_, err = peer.WhoAmI(t.Context())
	requireNoErr(t, err)

	logs := peerLogs.String()
	if strings.Contains(logs, "packet decryption failed") {
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "packet decryption failed") {
				t.Errorf("dropped a packet the server sent: %s", line)
			}
		}
	}
	if strings.Contains(logs, `"msg":"resending packet","type":2,"id":1,`) {
		t.Error("clientek was resent: its dummy-key Ack was not accepted")
	}
}
