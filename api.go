package teamspeak

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/honeybbq/teamspeak-go/commands"
)

var errNoDataReturnedForClient = errors.New("no data returned for client")

// SendTextMessage sends a text message to a client, channel or server.
func (c *Client) SendTextMessage(targetMode int, targetID uint64, message string) error {
	cmd := commands.BuildCommandOrdered("sendtextmessage", [][2]string{
		{"targetmode", strconv.Itoa(targetMode)},
		{"target", strconv.FormatUint(targetID, 10)},
		{"msg", message},
	})

	return c.SendCommandNoWait(cmd)
}

// ClientMove moves a client to a different channel.
func (c *Client) ClientMove(clid uint16, channelID uint64, password string) error {
	params := [][2]string{
		{"clid", strconv.Itoa(int(clid))},
		{"cid", strconv.FormatUint(channelID, 10)},
	}
	if password != "" {
		// Channel passwords travel as base64(sha1(password)), the same encoding
		// clientinit uses; a plain password is rejected with error 781.
		params = append(params, [2]string{"cpw", prepareClientPassword(password)})
	}
	cmd := commands.BuildCommandOrdered("clientmove", params)

	return c.ExecCommand(cmd, 10*time.Second)
}

// Poke sends a poke message to a client.
func (c *Client) Poke(clid uint16, message string) error {
	cmd := commands.BuildCommandOrdered("clientpoke", [][2]string{
		{"clid", strconv.Itoa(int(clid))},
		{"msg", message},
	})

	return c.ExecCommand(cmd, 10*time.Second)
}

// SendVoice sends a raw Opus frame. Codec values: 4 = Opus voice, 5 = Opus music.
func (c *Client) SendVoice(data []byte, codec byte) error {
	return c.handler.SendVoicePacket(data, codec)
}

// SendWhisper sends Opus voice directly to up to 32 clients, regardless of which
// channel they are in. The bot's server group needs i_client_whisper_power.
func (c *Client) SendWhisper(data []byte, targetClientIDs []uint16, codec byte) error {
	return c.handler.SendWhisperPacket(data, targetClientIDs, codec)
}

// ClientID returns the client's own ID assigned by the server.
func (c *Client) ClientID() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.clid
}

// ChannelID returns the channel the client is currently in, or 0 if that is not
// known yet, for example before the first notifycliententerview.
func (c *Client) ChannelID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if info, ok := c.clients[c.clid]; ok {
		return info.ChannelID
	}

	return 0
}

// GetClientInfo fetches detailed information about a client.
func (c *Client) GetClientInfo(clid uint16) (map[string]string, error) {
	cmd := fmt.Sprintf("clientinfo clid=%d", clid)
	data, err := c.ExecCommandWithResponse(cmd, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: %d", errNoDataReturnedForClient, clid)
	}

	return data[0], nil
}

// ListChannels returns a list of all channels on the server.
func (c *Client) ListChannels() ([]ChannelInfo, error) {
	data, err := c.ExecCommandWithResponse("channellist", 5*time.Second)
	if err != nil {
		return nil, err
	}

	channels := make([]ChannelInfo, 0, len(data))
	for _, item := range data {
		cid, _ := parseUint64Value(item["cid"])
		pid, _ := parseUint64Value(item["pid"])
		order, _ := parseUint64Value(item["channel_order"])
		name := item["channel_name"]

		channels = append(channels, ChannelInfo{
			ID:       cid,
			ParentID: pid,
			Order:    order,
			Name:     commands.Unescape(name),
		})
	}

	return channels, nil
}

// ListClients returns a list of all clients currently connected to the server.
func (c *Client) ListClients() ([]ClientInfo, error) {
	data, err := c.ExecCommandWithResponse("clientlist -uid -away -voice -groups", 5*time.Second)
	if err != nil {
		return nil, err
	}

	clients := make([]ClientInfo, 0, len(data))
	for _, item := range data {
		clid, _ := parseUint16Value(item["clid"])
		nick := item["client_nickname"]
		cid, _ := parseUint64Value(item["cid"])
		uid := item["client_unique_identifier"]
		clientType, _ := strconv.Atoi(item["client_type"])
		groupsStr := item["client_servergroups"]

		groups := make([]string, 0)
		if groupsStr != "" {
			groups = strings.Split(groupsStr, ",")
		}

		clients = append(clients, ClientInfo{
			ID:           clid,
			Nickname:     commands.Unescape(nick),
			ChannelID:    cid,
			UID:          uid,
			Type:         clientType,
			ServerGroups: groups,
		})
	}

	return clients, nil
}

// WaitConnected waits for the connection handshake to be completed.
//
// It returns nil once the handshake completes. If the attempt fails, it returns
// the cause, such as the server's error for a rejected password, rather than
// waiting for ctx to expire. It may be called before or after Connect.
func (c *Client) WaitConnected(ctx context.Context) error {
	c.mu.Lock()
	attempt := c.attempt
	c.mu.Unlock()

	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
