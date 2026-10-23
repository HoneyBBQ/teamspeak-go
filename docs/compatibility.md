# Compatibility

From v1.0.0 the module follows semantic versioning. Minor releases may add
members to `Status`, `ServerFamily`, `identity.UIDAlgorithm`, the set of
`client.Event` types and the enumerations (`GroupType`, `Codec`, `Reason` and
the rest), and the server may send values this module does not name, so a
`switch` over any of them should have a default case.

## Supported Go versions

The module supports the two newest Go major releases, as Go itself does; CI
tests both, 1.26 and 1.27. The `go` line in `go.mod` is the oldest of them.
When that release leaves support, a minor release may raise the line; that is
not a breaking change.

## Differences from teamspeak-js

The two SDKs make the same decisions and use the same names, except where the
languages differ:

- **Backoff zero values.** Go cannot tell an unset field from 0, so a zero
  `BackoffPolicy` field takes the default, and a negative `Jitter` turns
  jitter off. JavaScript takes `undefined` as the default and 0 as 0.
- **A handler that panics or throws.** Go recovers the panic, logs it at
  Error, and keeps delivering. JavaScript rethrows it through
  `queueMicrotask`, as an uncaught exception from an EventEmitter listener
  would be, and keeps delivering to the other listeners.
- **Durations** are `time.Duration` in Go and milliseconds, with an `Ms`
  suffix, in JavaScript. Go's `ClientListOptions.OmitUID` is JavaScript's
  `uid` flag, because a Go bool's zero value must be the default.
- **When disconnect returns.** JavaScript's `disconnect()` resolves after
  its `disconnected` has been delivered, which is safe there: a listener that
  awaits `disconnect()` yields to the delivery loop. Go's `Disconnect`
  returns once the event is queued and guarantees order instead — the old
  session's `disconnected` before the new session's `connected` and any
  other event of it — since a Go handler blocking on its own delivery would
  deadlock. A Go handler may call `Connect` and `Disconnect` freely.
- **Streams.** The same behaviour and names, in Go's terms: handlers
  registered with `On...` (each returns its remove function) instead of
  `on(event)`; a `context.Context` instead of `signal` and `timeoutMs`;
  `Close(ctx) error`, which waits for the goodbyes and returns what failed,
  instead of `dispose()`, which reports to the `error` event; pointer fields
  (`*Source`, `*int`) instead of `undefined`; `Watch(ctx, id, opts)`
  with `WatchOptions.ClientID` for a stream not in `List`, instead of a
  `watch` that takes the id or the info; separate `EndCause` and `PeerCause`
  types, as the JavaScript SDK has `StreamEndCause` and `PeerCloseCause`; numeric
  `Source` and `Accessibility` types with `String()` instead of string
  unions; and `Shutdown` in the causes for `"disposed"`. The
  JSON of a signalling message differs from JSON.stringify's in one byte
  sequence only: encoding/json writes U+2028 and U+2029 escaped.
- **connected.** Both deliver it once `Connect` has succeeded, on the event
  queue. JavaScript's single thread lets a listener added right after
  `connect()` resolves still hear it; Go's event goroutine may run first, so
  register `OnConnected` before `Connect` to be sure to.
