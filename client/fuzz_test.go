package client

import (
	"maps"
	"slices"
	"testing"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// answeredCommands are the commands a fuzzed session may have in flight: every
// one with its own answer shape, and one the table does not know.
var answeredCommands = append(slices.Sorted(maps.Keys(responses)), "whoami")

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
		c.OnVoiceData(func(VoiceDataEvent) {})
		c.handleCommandLines(c.handler, data)
		c.handlePacket(c.handler, &transport.Packet{
			TypeFlagged: byte(transport.PacketTypeVoice),
			Data:        []byte(data),
		})
	})
}

// FuzzHandleCommandLinesConnected is FuzzHandleCommandLines on a session past
// the key exchange. Until then the client drops everything but the handshake's
// own commands, so that target never reaches the notification handlers,
// initserver, the client list or the command tracker; here all of them are
// reachable, with two commands in flight for the data to answer. The first is
// return code 1 and the second 2. Nothing a server sends may panic or leave a
// command's answer settled twice.
func FuzzHandleCommandLinesConnected(f *testing.F) {
	indexOf := func(name string) uint8 {
		return uint8(slices.Index(answeredCommands, name))
	}
	f.Add("initserver aclid=7 virtualserver_version=3.13.7 virtualserver_platform=Linux", true, uint8(0), uint8(0))
	f.Add("notifycliententerview clid=2 ctid=1 client_nickname=a client_servergroups=6,7|clid=3 client_nickname=b",
		false, uint8(0), uint8(0))
	f.Add("notifyclientleftview clid=7 reasonid=5 reasonmsg=bye invokerid=2|clid=2", false, uint8(0), uint8(0))
	f.Add("notifyclientmoved clid=7 ctid=2 reasonid=4 invokerid=2", false, uint8(0), uint8(0))
	f.Add("notifytextmessage targetmode=1 msg=hi invokerid=2\nnotifyclientpoke invokerid=2 msg=x",
		false, uint8(0), uint8(0))
	f.Add("notifyservergrouplist sgid=1 name=a|sgid=2 name=b\nerror id=0 msg=ok return_code=1",
		false, indexOf("servergrouplist"), indexOf("channelcreate"))
	f.Add("sgid=1 name=a|sgid=2\nerror id=2568 msg=x return_code=1", false, indexOf("whoami"), indexOf("channelcreate"))
	f.Add("notifychannelcreated cid=5 invokerid=7\nerror id=0 msg=ok return_code=1",
		false, indexOf("channelcreate"), indexOf("servergroupadd"))
	f.Add("error id=0 msg=ok return_code=1\nnotifystartupload clientftfid=1 status=0 ftkey=a port=1 size=2",
		false, indexOf("ftinitupload"), indexOf("ftinitdownload"))
	f.Add("notifystatusfiletransfer clientftfid=1 status=2568\nerror id=0 return_code=2",
		false, indexOf("ftinitupload"), indexOf("ftinitupload"))
	f.Add("-1 id=2|=|\x00\r\n", true, uint8(1), uint8(2))

	f.Fuzz(func(t *testing.T, data string, connecting bool, first, second uint8) {
		runConnectedSession(t, data, connecting, first, second)
	})
}

// runConnectedSession registers the two commands first and second pick out of
// answeredCommands, feeds data to a connected client and checks nothing panics.
func runConnectedSession(t *testing.T, data string, connecting bool, first, second uint8) {
	t.Helper()
	c := newTestClient(t)
	if connecting {
		markConnecting(c)
	}
	c.OnTextMessage(func(TextMessageEvent) {})
	c.OnClientEnter(func(ClientEnterEvent) {})
	c.OnClientLeave(func(ClientLeaveEvent) {})
	c.OnClientMoved(func(ClientMovedEvent) {})
	c.OnPoked(func(PokeEvent) {})
	c.OnKicked(func(KickedEvent) {})
	c.OnNotification(func(NotificationEvent) {})
	c.OnConnected(func() {})
	c.OnDisconnected(func(error) {})

	answers := make([]<-chan commandResult, 0, 2)
	for _, pick := range []uint8{first, second} {
		spec := responseFor(answeredCommands[int(pick)%len(answeredCommands)])
		correlated := spec != nil && spec.Correlated != nil
		_, answer := c.cmdTrack.register(spec, "1", correlated)
		answers = append(answers, answer)
	}

	c.handleCommandLines(c.handler, data)

	for _, answer := range answers {
		select {
		case <-answer:
		default:
		}
	}
}
