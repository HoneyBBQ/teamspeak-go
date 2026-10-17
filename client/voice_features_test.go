package client

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

func TestClientInit_CarriesPrivilegeKeyAndMetaData(t *testing.T) {
	c := newTestClient(t, WithPrivilegeKey("tok en="), WithMetaData("a b|c"))
	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd.Params["client_default_token"] != "tok en=" || cmd.Params["client_meta_data"] != "a b|c" {
		t.Errorf("token %q, meta data %q", cmd.Params["client_default_token"], cmd.Params["client_meta_data"])
	}
}

func TestClientInit_DefaultsCarryNoTokenOrMetaData(t *testing.T) {
	c := newTestClient(t)
	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd.Params["client_default_token"] != "" || cmd.Params["client_meta_data"] != "" {
		t.Errorf("token %q, meta data %q", cmd.Params["client_default_token"], cmd.Params["client_meta_data"])
	}
}

// The key is spent by the join that used it: once connected, a reconnection's
// clientinit leaves it out, while the meta data stays.
func TestPrivilegeKeyIsDroppedAfterTheFirstSuccessfulJoin(t *testing.T) {
	c := newTestClient(t, WithPrivilegeKey("secret-key"), WithMetaData("m"))
	markConnecting(c)
	before := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if got := before.Params["client_default_token"]; got != "secret-key" {
		t.Fatalf("before the join the token is %q", got)
	}
	c.handleCommand(c.handler, "initserver aclid=7 virtualserver_name=X")

	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd.Params["client_default_token"] != "" || cmd.Params["client_meta_data"] != "m" {
		t.Errorf("after the join: token %q, meta data %q", cmd.Params["client_default_token"], cmd.Params["client_meta_data"])
	}
}

func TestPrivilegeKeyIsRedactedWhenPrinted(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNew(t, id, "bot", WithPrivilegeKey("key-s3cret"))
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		for _, v := range []any{c, c.clientInitOptions, *c.clientInitOptions} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "key-s3cret") {
				t.Errorf("%T with %s leaks the key", v, verb)
			}
		}
	}
}

// The goodbye carries reasonid=8, without which both servers drop the message.
func TestDisconnect_SaysGoodbyeWithReasonEight(t *testing.T) {
	type leave struct {
		run  func(c *Client) error
		want string
	}
	for name, tc := range map[string]leave{
		"default": {
			func(c *Client) error { return c.Disconnect(t.Context()) },
			"clientdisconnect reasonid=8 reasonmsg=Shutdown",
		},
		"message": {
			func(c *Client) error { return c.DisconnectWithMessage(t.Context(), "back soon") },
			`clientdisconnect reasonid=8 reasonmsg=back\ssoon`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t)
			var mu sync.Mutex
			var lines []string
			c.wireHook = func(line string) error {
				mu.Lock()
				lines = append(lines, line)
				mu.Unlock()

				return errCaptured
			}
			_ = tc.run(c)
			mu.Lock()
			defer mu.Unlock()
			if len(lines) != 1 || !strings.HasPrefix(lines[0], tc.want+" return_code=") {
				t.Errorf("sent %q, want %q", lines, tc.want)
			}
		})
	}
}

func TestSendGroupWhisper_RefusesATargetThatIsNotAConstruction(t *testing.T) {
	c := newTestClient(t)
	for name, target := range map[string]GroupWhisperTarget{
		"zero value":    {},
		"unknown scope": WhisperToAllClients(GroupWhisperScope(7)),
	} {
		err := c.SendGroupWhisper([]byte{1}, target, teamspeak.CodecOpusVoice)
		if !errors.Is(err, ErrInvalidWhisperTarget) {
			t.Errorf("%s: err = %v, want ErrInvalidWhisperTarget", name, err)
		}
	}
	err := c.SendGroupWhisper([]byte{1}, WhisperToServerGroup(GroupWhisperCurrentChannel, 6), teamspeak.CodecOpusVoice)
	if err != nil {
		t.Errorf("a valid target: %v", err)
	}
}

func TestGroupWhisperConstructors(t *testing.T) {
	cases := []struct {
		target GroupWhisperTarget
		kind   GroupWhisperType
		scope  GroupWhisperScope
		id     uint64
	}{
		{WhisperToServerGroup(GroupWhisperAllChannels, 9), GroupWhisperServerGroup, GroupWhisperAllChannels, 9},
		{WhisperToChannelGroup(GroupWhisperSubchannels, 5), GroupWhisperChannelGroup, GroupWhisperSubchannels, 5},
		{WhisperToChannelCommanders(GroupWhisperChannelFamily), GroupWhisperChannelCommander, GroupWhisperChannelFamily, 0},
		{WhisperToAllClients(GroupWhisperCurrentChannel), GroupWhisperAllClients, GroupWhisperCurrentChannel, 0},
	}
	for _, c := range cases {
		if !c.target.valid || c.target.Type() != c.kind || c.target.Scope() != c.scope || c.target.id != c.id {
			t.Errorf("%+v, want type %d scope %d id %d", c.target, c.kind, c.scope, c.id)
		}
	}
	if GroupWhisperServerGroup != 0 || GroupWhisperChannelGroup != 1 || GroupWhisperChannelCommander != 2 ||
		GroupWhisperAllClients != 3 || GroupWhisperSubchannels != 6 {
		t.Error("the packet's enum values changed")
	}
}

func TestSendWhisper_ChannelsAndLimits(t *testing.T) {
	c := newTestClient(t)
	send := func(targets WhisperTargets) error {
		return c.SendWhisper([]byte{1}, targets, teamspeak.CodecOpusVoice)
	}
	err := send(WhisperTargets{})
	if !errors.Is(err, ErrNoWhisperTargets) {
		t.Errorf("none: %v", err)
	}
	err = send(WhisperTargets{Clients: make([]teamspeak.ClientID, 33)})
	if !errors.Is(err, ErrTooManyWhisperTargets) {
		t.Errorf("33 clients: %v", err)
	}
	err = send(WhisperTargets{Channels: make([]teamspeak.ChannelID, 256)})
	if !errors.Is(err, ErrTooManyWhisperChannels) {
		t.Errorf("256 channels: %v", err)
	}
	err = send(WhisperTargets{Channels: []teamspeak.ChannelID{3}})
	if err != nil {
		t.Errorf("one channel: %v", err)
	}
}

func TestVerifyPasswords_SendTheHashedForm(t *testing.T) {
	var sent []string
	c := newTestClient(t)
	c.wireHook = func(line string) error {
		sent = append(sent, line)

		return errCaptured
	}
	_, _ = c.VerifyServerPassword(t.Context(), "hunter2")
	_, _ = c.VerifyChannelPassword(t.Context(), 7, "hunter2")
	hash := commands.Escape(prepareClientPassword("hunter2"))
	want := []string{"verifyserverpassword password=" + hash, "verifychannelpassword cid=7 password=" + hash}
	if len(sent) != 2 || !strings.HasPrefix(sent[0], want[0]) || !strings.HasPrefix(sent[1], want[1]) {
		t.Errorf("sent %q, want prefixes %q", sent, want)
	}
	for _, line := range sent {
		if strings.Contains(line, "hunter2") {
			t.Errorf("the plain password was sent: %q", line)
		}
	}
}

func TestPasswordMatches(t *testing.T) {
	other := errCaptured
	for _, tc := range []struct {
		err      error
		mismatch errcode.Code
		match    bool
		fails    bool
	}{
		{nil, errcode.ServerInvalidPassword, true, false},
		{errcode.ServerInvalidPassword, errcode.ServerInvalidPassword, false, false},
		{fmt.Errorf("wrapped: %w", errcode.ChannelInvalidPassword), errcode.ChannelInvalidPassword, false, false},
		{errcode.ChannelInvalidPassword, errcode.ServerInvalidPassword, false, true},
		{other, errcode.ChannelInvalidPassword, false, true},
	} {
		got, err := passwordMatches(nil, tc.err)(tc.mismatch)
		if got != tc.match || (err != nil) != tc.fails {
			t.Errorf("%v / %v: got %v, %v", tc.err, tc.mismatch, got, err)
		}
	}
}

func TestBuildSetConnectionInfo_KeysAndOrder(t *testing.T) {
	var traffic transport.Traffic
	traffic.Sent[transport.TrafficSpeech] = transport.TrafficFigures{
		Packets: 3, Bytes: 300, BytesLastSecond: 20, BytesPerSecondLastMinute: 5,
	}
	traffic.Received[transport.TrafficControl] = transport.TrafficFigures{Packets: 2, Bytes: 90}

	rtt := transport.RoundTripEstimate{Mean: 12500 * time.Microsecond, Deviation: 1250 * time.Microsecond}
	withPing := wire.ParseCommand(buildSetConnectionInfo(traffic, rtt, true))
	if withPing.Name != "setconnectioninfo" ||
		withPing.Params["connection_ping"] != "12.5000" || withPing.Params["connection_ping_deviation"] != "1.2500" {
		t.Errorf("ping: %v", withPing.Params)
	}
	// Two ping fields, then 2 directions x 3 classes x (packets, bytes) and
	// 2 x 3 x (last second, last minute).
	if len(withPing.Params) != 2+12+12 {
		t.Errorf("%d fields, want 26", len(withPing.Params))
	}
	for k, v := range map[string]string{
		"connection_packets_sent_speech": "3", "connection_bytes_sent_speech": "300",
		"connection_bandwidth_sent_last_second_speech": "20", "connection_bandwidth_sent_last_minute_speech": "5",
		"connection_packets_received_control": "2", "connection_bytes_received_control": "90",
		"connection_bytes_sent_keepalive": "0",
	} {
		if withPing.Params[k] != v {
			t.Errorf("%s = %q, want %q", k, withPing.Params[k], v)
		}
	}

	without := wire.ParseCommand(buildSetConnectionInfo(traffic, transport.RoundTripEstimate{}, false))
	if _, ok := without.Params["connection_ping"]; ok || len(without.Params) != 24 {
		t.Errorf("before the first pong: %d fields, ping present = %v", len(without.Params), ok)
	}
}
