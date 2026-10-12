package teamspeak

import "context"

// Commands only the voice protocol has. ServerQuery has no subscriptions — a
// query client hears every channel once it registers — and no
// channelgetdescription, since its channelinfo carries the description — so
// these live on the voice client rather than on the shared Commands.

// GetChannelDescription returns the channel's description, which channellist
// omits for bandwidth.
func (c *Client) GetChannelDescription(ctx context.Context, cid uint64) (string, error) {
	rows, err := c.query(ctx, "channelgetdescription", []param{uintArg("cid", cid)})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", nil
	}

	return fieldStr(rows[0], "channel_description"), nil
}

// SubscribeChannel subscribes to a channel: its clients' events and voice
// arrive without joining it.
func (c *Client) SubscribeChannel(ctx context.Context, cid uint64) error {
	return c.exec(ctx, "channelsubscribe", []param{uintArg("cid", cid)})
}

// UnsubscribeChannel stops receiving a channel's events.
func (c *Client) UnsubscribeChannel(ctx context.Context, cid uint64) error {
	return c.exec(ctx, "channelunsubscribe", []param{uintArg("cid", cid)})
}

// SubscribeAllChannels subscribes to every channel.
func (c *Client) SubscribeAllChannels(ctx context.Context) error {
	return c.exec(ctx, "channelsubscribeall", nil)
}

// UnsubscribeAllChannels stops receiving every channel's events.
func (c *Client) UnsubscribeAllChannels(ctx context.Context) error {
	return c.exec(ctx, "channelunsubscribeall", nil)
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
