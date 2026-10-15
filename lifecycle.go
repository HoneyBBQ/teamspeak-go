package teamspeak

// The events that report the connection itself rather than what happened on
// it. They are not server events: no notification carries them, so they do not
// implement Event and no transport has to deliver them.

// ConnectedEvent is what a client's OnConnected handlers receive: the
// connection is ready.
type ConnectedEvent struct {
	// Reconnected is true when the connection came from the reconnect loop
	// that WithReconnect turns on, and false for the one a Connect call made.
	Reconnected bool
}

// DisconnectedEvent is what a client's OnDisconnected handlers receive: a
// connection, or an attempt to make one, ended.
type DisconnectedEvent struct {
	// Err is the cause: a failed handshake, a timeout for a server that
	// stopped answering, or the client's own error for a removal. It is nil
	// after a deliberate disconnect.
	Err error
	// WillReconnect is true when the reconnect loop will try again:
	// reconnection is on, the client was not stopped, the attempts are not
	// used up, and the policy's ShouldRetry accepts Err. It is false after a
	// deliberate disconnect and for a failed Connect, which is never retried.
	WillReconnect bool
}
