package client

import (
	"testing"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// FuzzHandleCommandLines feeds arbitrary decrypted command data to the client:
// command parsing, the handshake steps, the response tracker and every
// notification handler. Nothing a server sends may panic.
func FuzzHandleCommandLines(f *testing.F) {
	f.Add("initserver aclid=1 virtualserver_version=6.0.0")
	f.Add("notifycliententerview clid=2 ctid=1 client_nickname=a|clid=3")
	f.Add("notifyclientleftview clid=1 reasonid=5|clid=2")
	f.Add("notifyclientmoved clid=1 ctid=2 reasonid=4")
	f.Add("notifytextmessage targetmode=1 msg=hi invokerid=2")
	f.Add("error id=0 msg=ok return_code=1")
	f.Add("clientinitiv alpha=AAAAAAAAAAAAAA== beta=AAAA omega=AAAA")
	f.Add("initivexpand2 l=AQ== beta=AAAA omega=AAAA proof=AAAA")
	f.Add("channellistfinished\nnotifystartupload clientftfid=1 status=2568")
	f.Add("-1 id=2|=|\x00\r\n")

	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		f.Fatalf("Parse: %v", err)
	}

	f.Fuzz(func(t *testing.T, data string) {
		c, err := New(id, "127.0.0.1:9987", "fuzz")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		markConnecting(c)
		c.OnVoiceData(func(VoiceData) {})
		c.handleCommandLines(c.handler, data)
		c.handlePacket(c.handler, &transport.Packet{
			TypeFlagged: byte(transport.PacketTypeVoice),
			Data:        []byte(data),
		})
	})
}
