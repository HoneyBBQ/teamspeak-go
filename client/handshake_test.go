package client

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

func TestHandleInitServer_SetsStatusConnected(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)

	c.handleCommand(c.handler, "initserver aclid=7 virtualserver_name=TestServer")

	c.mu.Lock()
	status := c.status
	clid := c.clid
	c.mu.Unlock()

	if status != StatusConnected {
		t.Errorf("expected StatusConnected, got %v", status)
	}
	if clid != 7 {
		t.Errorf("expected clid=7, got %d", clid)
	}
}

func TestHandleInitServer_FallsBackToClid(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)

	c.handleCommand(c.handler, "initserver clid=42 virtualserver_name=X")

	c.mu.Lock()
	clid := c.clid
	c.mu.Unlock()

	if clid != 42 {
		t.Errorf("expected clid=42, got %d", clid)
	}
}

func TestHandleInitServer_ReleasesWaitConnected(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)

	c.handleCommand(c.handler, "initserver aclid=3 virtualserver_name=X")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := c.waitConnected(ctx)
	if err != nil {
		t.Errorf("WaitConnected after initserver: %v", err)
	}
}

func TestHandleInitServer_TriggersOnConnected(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)

	connected := make(chan struct{}, 1)
	c.OnConnected(func() { connected <- struct{}{} })

	c.handleCommand(c.handler, "initserver aclid=1")

	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Error("OnConnected not called after initserver")
	}
}

func TestHandleInitServer_CalledTwice_IgnoresTheSecond(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)

	c.handleCommand(c.handler, "initserver aclid=1")
	c.handleCommand(c.handler, "initserver aclid=2")

	c.mu.Lock()
	clid := c.clid
	status := c.status
	c.mu.Unlock()

	if status != StatusConnected {
		t.Errorf("expected StatusConnected, got %v", status)
	}
	if clid != 1 {
		t.Errorf("expected the first initserver's clid=1 to stand, got %d", clid)
	}
}

// An initserver arriving after Disconnect must not bring the client back.
func TestHandleInitServer_AfterDisconnect_StaysDisconnected(t *testing.T) {
	c := newTestClient(t)
	markConnecting(c)
	connected := make(chan struct{}, 1)
	c.OnConnected(func() { connected <- struct{}{} })

	err := c.Disconnect(t.Context())
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	c.handleCommand(c.handler, "initserver aclid=5")

	if got := c.Status(); got != StatusDisconnected {
		t.Errorf("status after a late initserver = %v, want disconnected", got)
	}
	select {
	case <-connected:
		t.Error("OnConnected ran for an initserver after Disconnect")
	case <-time.After(200 * time.Millisecond):
	}
}

// markConnecting puts the client in the state Connect leaves it in while the
// handshake runs.
// An initserver under the public dummy key, before the shared secret exists,
// could come from anyone on the path; it must not report the client connected.
func TestHandleInitServer_BeforeCryptoInit_StaysConnecting(t *testing.T) {
	c := newHandshakingClient(t)
	markConnecting(c)

	c.handleCommand(c.handler, "initserver aclid=7 virtualserver_name=Forged")

	if got := c.Status(); got != StatusConnecting {
		t.Errorf("status after a dummy-key initserver = %v, want StatusConnecting", got)
	}
	if got := c.ClientID(); got != 0 {
		t.Errorf("ClientID after a dummy-key initserver = %d, want 0", got)
	}
}

func markConnecting(c *Client) {
	c.mu.Lock()
	c.status = StatusConnecting
	c.mu.Unlock()
}

// handleHandshakeInitIV (old path)

func TestHandleHandshakeInitIV_InvalidAlpha_NoSendClientInit(t *testing.T) {
	c := newTestClient(t)
	// Invalid base64 for alpha: InitCrypto fails, handleHandshakeInitIV returns.
	// Must not panic.
	c.handleCommand(c.handler, "clientinitiv alpha=!!! beta=AAAAAAAAAA omega=")
}

func TestHandleHandshakeInitIV_ValidParams_SendsClientInit(t *testing.T) {
	c, serverConn := newTestClientWithPipe(t)

	// Drain the initial Init1 packet from Start().
	_ = readFromPipe(t, serverConn)

	// Wire OnPacket so that the handler routes Init1 packets to handlePacket.
	c.handler.OnClosed = func(error) {}

	// A valid old-style handshake: alpha + beta are 10-byte base64, omega is the
	// server's public key. We use the test identity's own public key as omega
	// (InitCrypto only validates format, not that it comes from a server).
	pubKey := c.handler.TsCrypt.Identity.PublicKey()

	cmd := "clientinitiv alpha=AAAAAAAAAAAAAA== beta=AAAAAAAAAAAAAA== omega=" + pubKey
	c.handleCommand(c.handler, cmd)

	// After successful InitCrypto, sendClientInit is called and a Command packet
	// (type 2) is sent through the handler. The payload is encrypted.
	pkt := readFromPipe(t, serverConn)
	if len(pkt) < 13 {
		t.Fatalf("expected clientinit packet, got %d bytes", len(pkt))
	}
	// C2S header[4] byte (index 12 in S2C layout) = TypeFlagged; lower nibble = type.
	pktType := pkt[12] & 0x0F
	if pktType != 0x02 {
		t.Errorf("expected PacketTypeCommand (2), got %d", pktType)
	}
}

// handleHandshakeExpand2 (new path)

func TestHandleHandshakeExpand2_InvalidBeta_NoSendClientInit(t *testing.T) {
	c := newTestClient(t)
	// Invalid base64 for beta: DecodeString fails, returns early.
	c.handleCommand(c.handler, "initivexpand2 l= omega= proof= beta=!!!")
}

func TestBuildClientInitCommand_DefaultAuthFieldsAreEmpty(t *testing.T) {
	c := newTestClient(t)

	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd == nil {
		t.Fatal("expected clientinit command")
	}

	if got := cmd.Params["client_default_channel"]; got != "" {
		t.Errorf("expected empty client_default_channel, got %q", got)
	}
	if got := cmd.Params["client_default_channel_password"]; got != "" {
		t.Errorf("expected empty client_default_channel_password, got %q", got)
	}
	if got := cmd.Params["client_server_password"]; got != "" {
		t.Errorf("expected empty client_server_password, got %q", got)
	}
}

func TestBuildClientInitCommand_IncludesConfiguredHandshakeCredentials(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("IdentityFromString: %v", err)
	}

	c := mustNew(t,
		id,
		"Test Bot",
		WithServerPassword("server secret"),
		WithDefaultChannel("Lobby Alpha"),
		WithDefaultChannelPassword("channel secret"),
	)

	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd == nil {
		t.Fatal("expected clientinit command")
	}

	if got := cmd.Params["client_server_password"]; got != prepareClientPassword("server secret") {
		t.Errorf("expected client_server_password to be %q, got %q", prepareClientPassword("server secret"), got)
	}
	if got := cmd.Params["client_default_channel"]; got != "Lobby Alpha" {
		t.Errorf("expected client_default_channel to be %q, got %q", "Lobby Alpha", got)
	}
	if got := cmd.Params["client_default_channel_password"]; got != prepareClientPassword("channel secret") {
		t.Errorf(
			"expected client_default_channel_password to be %q, got %q",
			prepareClientPassword("channel secret"),
			got,
		)
	}
}

func TestBuildClientInitCommand_PreservesCredentialFieldOrder(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("IdentityFromString: %v", err)
	}

	c := mustNew(t,
		id,
		"Test Bot",
		WithServerPassword("server secret"),
		WithDefaultChannel("Lobby Alpha"),
		WithDefaultChannelPassword("channel secret"),
	)

	raw := c.buildClientInitCommand(c.handler.TsCrypt)
	defaultChannelIndex := indexOfOrFail(t, raw, "client_default_channel=Lobby\\sAlpha")
	defaultChannelPasswordIndex := indexOfOrFail(
		t,
		raw,
		"client_default_channel_password="+wire.Escape(prepareClientPassword("channel secret")),
	)
	serverPasswordIndex := indexOfOrFail(
		t,
		raw,
		"client_server_password="+wire.Escape(prepareClientPassword("server secret")),
	)
	metaDataIndex := indexOfOrFail(t, raw, "client_meta_data=")

	if defaultChannelIndex >= defaultChannelPasswordIndex ||
		defaultChannelPasswordIndex >= serverPasswordIndex ||
		serverPasswordIndex >= metaDataIndex {
		t.Fatalf("unexpected credential field order in %q", raw)
	}
}

func TestHandlePacket_Init1_Step0_SendsStep1(t *testing.T) {
	c, serverConn := newTestClientWithPipe(t)
	c.handler.OnClosed = func(error) {}

	// Drain initial C2S Init1 from Start().
	_ = readFromPipe(t, serverConn)

	// Build step-0 server response: data[0]=0x00
	step0 := make([]byte, 21)
	step0[0] = 0x00
	binary.LittleEndian.PutUint32(step0[9:13], 0xCAFEBABE)

	// Wrap as S2C Init1 raw packet: [8 tag][2 ID][1 TypeFlagged][21 payload]
	pktBytes := make([]byte, 8+3+len(step0))
	pktBytes[10] = 0x08 // PacketTypeInit1
	copy(pktBytes[11:], step0)
	_, writeErr := serverConn.Write(pktBytes)
	if writeErr != nil {
		t.Fatalf("Write: %v", writeErr)
	}

	// handlePacket calls handler.SendPacket(8, step1Response, 0),
	// which writes through the pipe.
	resp := readFromPipe(t, serverConn)
	if len(resp) < 13 {
		t.Fatalf("expected step-1 response, got %d bytes", len(resp))
	}
	if resp[12]&0x0F != 0x08 {
		t.Errorf("expected PacketTypeInit1 (8), got %d", resp[12]&0x0F)
	}
	// Step-1 payload starts with 0x01
	if resp[13] != 0x01 {
		t.Errorf("expected step 0x01 payload, got 0x%02x", resp[13])
	}
}

func TestHandlePacket_CommandType_RoutedToHandleCommandLines(t *testing.T) {
	c := newTestClient(t)
	entered := make(chan struct{}, 1)
	c.OnClientEnter(func(_ ClientEnterEvent) { entered <- struct{}{} })

	enterLine := "notifycliententerview clid=9 client_nickname=G" +
		" ctid=1 client_type=0 client_servergroups= client_unique_identifier=g"
	p := &transport.Packet{
		TypeFlagged: 0x02, // PacketTypeCommand
		Data:        []byte(enterLine),
	}
	c.handlePacket(c.handler, p)

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Error("handlePacket did not route Command to handleCommandLines")
	}
}

// readFromPipe reads one datagram from the server-side pipe with a 2s timeout.
func readFromPipe(t *testing.T, server *pipePair) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	done := make(chan []byte, 1)
	go func() {
		n, readErr := server.Read(buf)
		if readErr != nil {
			done <- nil

			return
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		done <- cp
	}()
	select {
	case data := <-done:
		return data
	case <-time.After(2 * time.Second):
		t.Fatal("readFromPipe: timed out")

		return nil
	}
}

func indexOfOrFail(t *testing.T, s string, needle string) int {
	t.Helper()

	idx := strings.Index(s, needle)
	if idx < 0 {
		t.Fatalf("expected %q to contain %q", s, needle)
	}

	return idx
}

// A handshake step the client cannot use ends the attempt at once, with a
// cause wrapping ErrHandshake, instead of leaving Connect to time out.
func TestHandshakeFailureEndsTheAttemptWithErrHandshake(t *testing.T) {
	cases := map[string]func(c *Client){
		"malformed init1": func(c *Client) {
			c.handleInit1(c.handler, []byte{0x09})
		},
		"empty init1": func(c *Client) {
			c.handleInit1(c.handler, []byte{})
		},
		"initivexpand2 with a bad license": func(c *Client) {
			c.handler.TsCrypt.AlphaTmp = make([]byte, 10)
			c.handleCommand(c.handler, "initivexpand2 l=AQ== beta=AAAA omega=AAAA proof=AAAA")
		},
	}
	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			c := newHandshakingClient(t)
			markConnecting(c)
			attempt := c.attempt

			step(c)

			select {
			case <-attempt.done:
			case <-time.After(2 * time.Second):
				t.Fatal("the attempt did not end")
			}
			if !errors.Is(attempt.err, ErrHandshake) {
				t.Fatalf("attempt ended with %v, want ErrHandshake", attempt.err)
			}
			if got := c.Status(); got != StatusDisconnected {
				t.Errorf("status = %v, want disconnected", got)
			}
		})
	}
}

// Before crypto init everything arrives under the public dummy key, so only
// the key exchange and errors are handled: a forged notification, data row or
// unknown command is dropped.
func TestHandleCommand_BeforeCryptoInit_DropsAllButTheKeyExchange(t *testing.T) {
	c := newHandshakingClient(t)
	markConnecting(c)
	heard := make(chan TextMessageEvent, 1)
	c.OnTextMessage(func(e TextMessageEvent) { heard <- e })

	c.handleCommand(c.handler, "notifytextmessage targetmode=1 msg=forged invokerid=5")
	c.handleCommand(c.handler, "notifycliententerview clid=9 client_nickname=Forged ctid=1")

	select {
	case e := <-heard:
		t.Fatalf("a pre-init notification reached the handlers: %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
	c.mu.Lock()
	_, known := c.clients[9]
	c.mu.Unlock()
	if known {
		t.Error("a pre-init notifycliententerview was recorded")
	}
	if got := c.Status(); got != StatusConnecting {
		t.Errorf("status = %v, want connecting", got)
	}
}

// A ban before crypto init is as forgeable as anything else then: it may end
// the attempt, but must not stop the client for good.
func TestHandleError_BanBeforeCryptoInit_FailsTheAttemptOnly(t *testing.T) {
	c := newHandshakingClient(t)
	markConnecting(c)
	attempt := c.attempt

	c.handleCommand(c.handler, "error id=3329 msg=banned")

	select {
	case <-attempt.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the attempt did not end")
	}
	time.Sleep(50 * time.Millisecond) // the ban path runs on its own goroutine
	if c.isStopped() {
		t.Error("a pre-init ban stopped the client")
	}
}
