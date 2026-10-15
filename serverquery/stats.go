package serverquery

import "time"

// TransportStats is what the current connection reports about itself: enough
// for a metrics exporter to publish without reaching into the client.
//
// The zero value is what a client that has never connected reports, with
// ConnectedAt the zero time.
//
// Experimental: this package may change in a minor release.
type TransportStats struct {
	// ConnectedAt is when the current connection was opened. It is the zero
	// time when there is none.
	ConnectedAt time.Time
	// Transport is the kind of connection: "tcp", "ssh" or "web".
	Transport string
	// Address is where it points, with the user for SSH and the base URL for
	// WebQuery. It never includes a password or an api key.
	Address string
	// BytesSent counts what the line protocol has written, terminators
	// included. It is what the transport sent, not what the socket did: header
	// bytes and retries are not counted.
	BytesSent uint64
	// BytesReceived counts the lines the server sent, terminators included,
	// before any banner was dropped.
	BytesReceived uint64
}

// Stats reports the current connection's identity and counters, or the zero
// value when there is none. It is read-only: a caller never sees the transport
// itself, so the numbers cannot be used to drive it.
//
// Experimental: this package may change in a minor release.
func (c *Client) Stats() TransportStats {
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()

	statter, ok := transport.(statter)
	if !ok {
		return TransportStats{}
	}

	return statter.stats()
}

// statter is what each transport implements so Stats can read it without
// knowing which one it is.
type statter interface {
	stats() TransportStats
}
