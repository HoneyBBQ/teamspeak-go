package stream

import (
	"context"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
)

// host is what a Streams needs of the client it attaches to. *client.Client
// satisfies it through clientHost; the tests give it a fake, which is why it is
// a small interface of its own and not the client's whole surface.
//
// Entries is a list and Entry a lookup, not a ServerView, because a
// ServerView can only be built by the client.
type host interface {
	state
	events
}

// state is what a Streams reads of the client, and the commands it sends.
type state interface {
	Send(ctx context.Context, req teamspeak.Request) ([]map[string]string, error)
	ClientID() teamspeak.ClientID
	Session() uint64
	Status() client.Status
	ServerCapabilities() client.ServerCapabilities
	Entries() []teamspeak.ClientEntry
	Entry(id teamspeak.ClientID) (teamspeak.ClientEntry, bool)
}

// events is what a Streams listens to.
type events interface {
	OnNotification(handler func(client.NotificationEvent)) func()
	OnClientEnter(handler func(client.ClientEnterEvent)) func()
	OnClientUpdated(handler func(client.ClientUpdatedEvent)) func()
	OnClientLeave(handler func(client.ClientLeaveEvent)) func()
	OnConnected(handler func(client.ConnectedEvent)) func()
	OnDisconnected(handler func(client.DisconnectedEvent)) func()
}

// clientHost adds to a *client.Client the two reads of the server view that
// host asks for.
type clientHost struct {
	*client.Client
}

func (h clientHost) Entries() []teamspeak.ClientEntry {
	return h.View().Clients()
}

func (h clientHost) Entry(id teamspeak.ClientID) (teamspeak.ClientEntry, bool) {
	return h.View().Client(id)
}
