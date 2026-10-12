package client

import (
	"context"
	"strconv"

	"github.com/honeybbq/teamspeak-go/commands"
)

// Commands only the voice protocol has. ServerQuery has no subscriptions — a
// query client hears every channel once it registers — and no
// channelgetdescription, since its channelinfo carries the description — so
// these live on the voice client rather than on the shared Commands.

// GetChannelDescription returns the channel's description, which channellist
// omits for bandwidth.
func (c *Client) GetChannelDescription(ctx context.Context, cid uint64) (string, error) {
	rows, err := c.send(ctx, channelCommand("channelgetdescription", cid))
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return rows[0]["channel_description"], nil
}

// SubscribeChannel subscribes to a channel: its clients' events and voice
// arrive without joining it.
func (c *Client) SubscribeChannel(ctx context.Context, cid uint64) error {
	_, err := c.send(ctx, channelCommand("channelsubscribe", cid))

	return err
}

// UnsubscribeChannel stops receiving a channel's events.
func (c *Client) UnsubscribeChannel(ctx context.Context, cid uint64) error {
	_, err := c.send(ctx, channelCommand("channelunsubscribe", cid))

	return err
}

// SubscribeAllChannels subscribes to every channel.
func (c *Client) SubscribeAllChannels(ctx context.Context) error {
	_, err := c.send(ctx, "channelsubscribeall")

	return err
}

// UnsubscribeAllChannels stops receiving every channel's events.
func (c *Client) UnsubscribeAllChannels(ctx context.Context) error {
	_, err := c.send(ctx, "channelunsubscribeall")

	return err
}

func channelCommand(name string, cid uint64) string {
	return commands.BuildCommandOrdered(name, [][2]string{{"cid", strconv.FormatUint(cid, 10)}})
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
