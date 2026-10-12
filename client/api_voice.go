package client

import (
	"context"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/request"
)

// Commands only the voice protocol has. ServerQuery has no subscriptions — a
// query client hears every channel once it registers — and no
// channelgetdescription, since its channelinfo carries the description — so
// these live on the voice client rather than on the shared Commands.

// GetChannelDescription returns the channel's description, which channellist
// omits for bandwidth. It fails with teamspeak.ErrNoData if the server answers
// with no row.
func (c *Client) GetChannelDescription(ctx context.Context, cid teamspeak.ChannelID) (string, error) {
	rows, err := c.Send(ctx, channelRequest("channelgetdescription", cid))
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", teamspeak.ErrNoData
	}

	return rows[0]["channel_description"], nil
}

// SubscribeChannel subscribes to a channel: its clients' events and voice
// arrive without joining it.
func (c *Client) SubscribeChannel(ctx context.Context, cid teamspeak.ChannelID) error {
	_, err := c.Send(ctx, channelRequest("channelsubscribe", cid))

	return err
}

// UnsubscribeChannel stops receiving a channel's events.
func (c *Client) UnsubscribeChannel(ctx context.Context, cid teamspeak.ChannelID) error {
	_, err := c.Send(ctx, channelRequest("channelunsubscribe", cid))

	return err
}

// SubscribeAllChannels subscribes to every channel.
func (c *Client) SubscribeAllChannels(ctx context.Context) error {
	_, err := c.Send(ctx, newRequest("channelsubscribeall", nil))

	return err
}

// UnsubscribeAllChannels stops receiving every channel's events.
func (c *Client) UnsubscribeAllChannels(ctx context.Context) error {
	_, err := c.Send(ctx, newRequest("channelunsubscribeall", nil))

	return err
}

// newRequest builds a typed request, so that the voice-only commands pass
// through the command middleware as the shared ones do.
func newRequest(command string, params [][2]string) teamspeak.Request {
	return request.New(command, params).(teamspeak.Request) //nolint:forcetypeassert // New returns a Request
}

func channelRequest(name string, cid teamspeak.ChannelID) teamspeak.Request {
	return newRequest(name, [][2]string{{"cid", strconv.FormatUint(uint64(cid), 10)}})
}

// ChannelID returns the channel the client is currently in, or 0 if that is not
// known yet, for example before the first notifycliententerview.
func (c *Client) ChannelID() teamspeak.ChannelID {
	c.mu.Lock()
	defer c.mu.Unlock()

	if info, ok := c.clients[c.clid]; ok {
		return info.ChannelID
	}

	return 0
}
