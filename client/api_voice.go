package client

import (
	"context"
	"errors"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/request"
)

// Commands only the voice protocol has. ServerQuery has no subscriptions — a
// query client hears every channel once it registers — and no
// channelgetdescription, since its channelinfo carries the description — so
// these live on the voice client rather than on the shared Commands.

// GetChannelDescription returns the channel's description, which channellist
// omits for bandwidth. It fails with teamspeak.ErrNoData if the server answers
// with no row for that channel.
//
// The server answers with a notifychanneledited holding the text. Another
// channel edit can arrive while the command waits, and it is collected as well:
// the answer is the row for this channel that carries channel_description, not
// the first row. The answer is no edit, so it produces no ChannelEditedEvent.
func (c *Client) GetChannelDescription(ctx context.Context, cid teamspeak.ChannelID) (string, error) {
	rows, err := c.Send(ctx, channelRequest("channelgetdescription", cid))
	if err != nil {
		return "", err
	}
	want := strconv.FormatUint(uint64(cid), 10)
	for _, row := range rows {
		description, ok := row["channel_description"]
		if ok && row["cid"] == want {
			return description, nil
		}
	}

	return "", teamspeak.ErrNoData
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

// VerifyServerPassword reports whether password is the server's password,
// without joining (verifyserverpassword). The password is given in cleartext
// and hashed on the wire, as when connecting. The server answers a match with
// plain success and a mismatch with error 1028
// (errcode.ServerInvalidPassword), which returns false; any other error is
// returned.
func (c *Client) VerifyServerPassword(ctx context.Context, password string) (bool, error) {
	req := newRequest("verifyserverpassword", [][2]string{{"password", prepareClientPassword(password)}})

	return passwordMatches(c.Send(ctx, req))(errcode.ServerInvalidPassword)
}

// VerifyChannelPassword reports whether password is channel cid's password,
// without moving (verifychannelpassword). The password is given in cleartext
// and hashed on the wire, as MoveClient does. A mismatch is error 781
// (errcode.ChannelInvalidPassword) and returns false; a channel without a
// password accepts any value and returns true; any other error, such as an
// unknown channel, is returned.
func (c *Client) VerifyChannelPassword(ctx context.Context, cid teamspeak.ChannelID, password string) (bool, error) {
	req := newRequest("verifychannelpassword", [][2]string{
		{"cid", strconv.FormatUint(uint64(cid), 10)},
		{"password", prepareClientPassword(password)},
	})

	return passwordMatches(c.Send(ctx, req))(errcode.ChannelInvalidPassword)
}

// MuteClients stops hearing the given clients (clientmute): the server no
// longer forwards their voice to this client. It is per listener, so everyone
// else still hears them, and it sends no notification and changes no client
// property. Several clients go in one command; muting none does nothing. The
// server accepts this client's own id, and ids of clients that are not
// connected, without an error. Undo it with UnmuteClients. Measured on
// TeamSpeak 3 and 6.
func (c *Client) MuteClients(ctx context.Context, clientIDs []teamspeak.ClientID) error {
	return c.sendClientList(ctx, "clientmute", clientIDs)
}

// UnmuteClients hears the given clients again (clientunmute): the server
// resumes forwarding their voice to this client after MuteClients. Measured on
// TeamSpeak 3 and 6.
func (c *Client) UnmuteClients(ctx context.Context, clientIDs []teamspeak.ClientID) error {
	return c.sendClientList(ctx, "clientunmute", clientIDs)
}

// sendClientList sends a command whose one parameter is a list of client ids,
// one clid row each. An empty list sends nothing.
func (c *Client) sendClientList(ctx context.Context, command string, clientIDs []teamspeak.ClientID) error {
	if len(clientIDs) == 0 {
		return nil
	}
	values := make([]string, len(clientIDs))
	for i, id := range clientIDs {
		values[i] = strconv.FormatUint(uint64(id), 10)
	}
	req := request.NewList(command, "clid", values).(teamspeak.Request) //nolint:forcetypeassert // returns a Request
	_, err := c.Send(ctx, req)

	return err
}

// passwordMatches turns the answer to a password check into a verdict: success
// is a match, the given mismatch error is not, anything else is an error.
func passwordMatches(_ []map[string]string, err error) func(mismatch errcode.Code) (bool, error) {
	return func(mismatch errcode.Code) (bool, error) {
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, mismatch):
			return false, nil
		default:
			return false, err
		}
	}
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
