package client

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// buildSetConnectionInfo is the setconnectioninfo line that answers a
// notifyconnectioninforequest, from what the connection has measured: the
// keepalive round trip (left out until a pong has come back), packets and
// bytes sent and received per class, and the bandwidth of the last second and
// of the last minute per class, in bytes per second. Packet loss and file
// transfer figures are not tracked, so they are not sent.
func buildSetConnectionInfo(traffic transport.Traffic, rtt transport.RoundTripEstimate, havePing bool) string {
	classes := [...]string{"speech", "keepalive", "control"}
	fields := make([][2]string, 0, 2+4*3*3)
	if havePing {
		fields = append(fields,
			[2]string{"connection_ping", milliseconds(rtt.Mean)},
			[2]string{"connection_ping_deviation", milliseconds(rtt.Deviation)})
	}
	directions := [...]struct {
		name    string
		figures [3]transport.TrafficFigures
	}{{"sent", traffic.Sent}, {"received", traffic.Received}}
	for _, d := range directions {
		for i, class := range classes {
			fields = append(fields, [2]string{"connection_packets_" + d.name + "_" + class, u(d.figures[i].Packets)})
		}
		for i, class := range classes {
			fields = append(fields, [2]string{"connection_bytes_" + d.name + "_" + class, u(d.figures[i].Bytes)})
		}
	}
	for _, d := range directions {
		for i, class := range classes {
			fields = append(fields, [2]string{
				"connection_bandwidth_" + d.name + "_last_second_" + class, u(d.figures[i].BytesLastSecond),
			})
		}
		for i, class := range classes {
			fields = append(fields, [2]string{
				"connection_bandwidth_" + d.name + "_last_minute_" + class, u(d.figures[i].BytesPerSecondLastMinute),
			})
		}
	}

	return wire.BuildCommandOrdered("setconnectioninfo", fields)
}

func u(n uint64) string { return strconv.FormatUint(n, 10) }

// milliseconds formats d as the decimal count of milliseconds the server
// reads, four places after the point.
func milliseconds(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 4, 64)
}

// answerConnectionInfoRequest answers a notifyconnectioninforequest: someone
// asked the server for this client's connection info, and the server asks us
// for the figures. It sends what the session h has measured and does not wait,
// since the server answers the command with nothing useful (error id=3 even
// for a bogus key). A failure is only logged: the request is not one a caller
// made.
func (c *Client) answerConnectionInfoRequest(h *transport.PacketHandler) {
	rtt, havePing := h.RoundTrip()
	line := buildSetConnectionInfo(h.Traffic(), rtt, havePing)

	// Detached from the packet handler's goroutine, which must keep reading
	// while the flood throttle makes this wait; it ends with the session.
	c.background.Go(func() {
		ctx, cancel := contextUntil(context.Background(), h.Done())
		defer cancel()
		err := c.throttle.wait(ctx)
		if err != nil || c.connectedHandler() != h {
			return
		}
		err = c.sendLine(h, line)
		if err != nil {
			c.logger.Debug("could not answer a connection info request", slog.Any("error", err))
		}
	})
}
