# Configuration

Options for the client, and what to do with the connection around it: the client version it presents and tracing.

## Options

```go
c, err := client.New(id, "ts.example.com", "Bot",
	client.WithLogger(slog.Default()), // silent without it
	client.WithResolver(customResolver),
	client.WithCommandMiddleware(timeCommands),
	client.WithEventMiddleware(filterMiddleware),
	client.WithServerPassword(os.Getenv("TEAMSPEAK_SERVER_PASSWORD")),
	client.WithDefaultChannel("Lobby"),
	client.WithDefaultChannelPassword(os.Getenv("TEAMSPEAK_DEFAULT_CHANNEL_PASSWORD")),
)
```

Command middleware wraps the typed commands. It sees each request and the
caller's context, and returns the rows or an error, so it can time, retry or
answer a command itself. Raw `Exec` and `ExecNoWait` lines, and the commands
the client sends on its own during the handshake, do not pass through it.

```go
timeCommands := func(next teamspeak.Executor) teamspeak.Executor {
	return teamspeak.ExecutorFunc(func(ctx context.Context, req teamspeak.Request) ([]map[string]string, error) {
				rows, err := next.Send(ctx, req)
		slog.Debug("command", "name", req.Command(), "took", time.Since(start), "err", err)

		return rows, err
	})
}
```

`WithNicknameLookup()` resolves a dot-less address as a MyTeamSpeak nickname
at named.myteamspeak.com first. It is off by default, since the lookup tells
MyTeamSpeak which server you are connecting to; without it a dot-less address
is resolved like any host.

`WithPacketConn(pc)` runs the session over your own `net.PacketConn`. The
client never closes it: ending a connection sets its read deadline to stop the
reader, and the next `Connect` clears it. Datagrams from any address but the
server's are dropped.

Connection auth options:

- `WithServerPassword(password)` accepts the plain-text server password, keeps only the TeamSpeak protocol hash, and sends it during `clientinit`
- `WithDefaultChannel(channel)` requests a default channel during `clientinit`
- `WithDefaultChannelPassword(password)` accepts the plain-text channel password and sends the TeamSpeak protocol hash for the configured default channel

## Client version

`clientinit` sends a recent Windows version unless `WithVersion` says
otherwise. The `versions` package has one variable for each version that is
known to work, named `<Platform>_<version>_<build>`; the first letter of a
platform that starts in lower case is capitalised, so macOS is `MacOS` and iOS
is `IOS`:

```go
import "github.com/honeybbq/teamspeak-go/versions"

c, err := client.New(id, "ts.example.com", "Bot",
	client.WithVersion(versions.Windows_3_6_2_1695203293),
)
```

A `versions.ClientVersion` is a platform, a version string and a signature, and
only the ones in the package carry a signature a server accepts. Do not modify
the variables. A server refuses a build below its configured minimum, so an old
version fails to connect on a server that has raised it. `New` returns
`ErrInvalidConfig` when a field is empty or the signature is not the base64 of
64 bytes.

## Tracing

`WithTrace` reports the milestones of a client's connection attempts and its
session, and `FileTransferOptions.Trace` those of one file transfer. Every hook
is optional.

```go
c, err := client.New(id, "ts.example.com", "Bot",
	client.WithTrace(&client.Trace{
		ResolveDone: func(i client.ResolveDoneInfo) {
			slog.Info("resolved", "target", i.Target, "took", i.Duration)
		},
		HandshakeDone: func(i client.HandshakeDoneInfo) {
			slog.Info("handshake", "took", i.Duration, "puzzle", i.PuzzleLevel, "resends", i.Resends)
		},
		SessionStart: func(i client.SessionStartInfo) {
			slog.Info("connected", "clid", i.ClientID, "nickname", i.Nickname, "took", i.Duration)
		},
		WelcomeDone: func(i client.WelcomeDoneInfo) {
			slog.Info("welcome done", "channel", i.ChannelID, "channels", i.Channels, "clients", i.Clients)
		},
		AttemptFailed: func(i client.AttemptFailedInfo) {
			slog.Warn("attempt failed", "phase", i.Phase, "target", i.Target, "err", i.Err)
		},
		SessionEnd: func(i client.SessionEndInfo) {
			slog.Info("session ended", "after", i.Duration, "cause", i.Cause)
		},
		ReconnectScheduled: func(i client.ReconnectScheduledInfo) {
			slog.Info("reconnecting", "attempt", i.Attempt, "in", i.Delay, "cause", i.Cause)
		},
		ReconnectStopped: func(i client.ReconnectStoppedInfo) {
			slog.Warn("gave up reconnecting", "attempts", i.Attempts, "cause", i.Cause)
		},
	}),
)
```

An attempt that succeeds calls `ResolveStart`, `ResolveDone`, `ConnectStart`,
`ConnectDone`, `HandshakeDone`, `SessionStart` and `WelcomeDone`, in that order.
One that does not reach `SessionStart` ends with `AttemptFailed` instead, saying
in which phase (`open`, `handshake` or `join`) it failed. Every session ends
with one `SessionEnd`, before the disconnected event; `Disconnect` also calls
`DisconnectStart` and `DisconnectDone` (which says whether the server
acknowledged the goodbye). After a drop, `ReconnectScheduled` precedes each
retry, and `ReconnectStopped` says when the loop gives up.

The rules for a hook:

- It is called synchronously, at the milestone, and its return value is
  ignored: it cannot change or stop the connection.
- It must be quick. Do slow work on your own goroutine.
- It may be called from different goroutines (yours for `Connect` and
  `Disconnect`, the receive goroutine for the handshake and a drop, the
  reconnect goroutine for a retry), so it must be safe for that. No client lock
  is held, so it can read `Status` or `ClientID`.
- It must not call `Connect` or `Disconnect`. To abandon an attempt, cancel the
  context you gave `Connect`; to leave once connected, call `Disconnect` from an
  `OnConnected` handler.
- A hook that panics is recovered and logged at Error; the connection goes on.

The client copies the `Trace` in `New`, so changing it afterwards has no effect.

A file transfer reports `DialStart`, `DialDone`, `Progress` (at most once per
64 KiB, and once more at the end with the final count) and then `Done` or
`Failed`, which says whether it failed while dialling or while transferring. The
transfer key is never in any of them. These hooks run on the goroutine that
called `UploadFileData` or `DownloadFileData`, and a panic in one is not
recovered: it reaches your code, after the connection is closed.

```go
err := teamspeak.UploadFileData(ctx, host, upload, file, teamspeak.FileTransferOptions{
	Trace: &teamspeak.FileTransferTrace{
		Progress: func(i teamspeak.FileTransferProgressInfo) { bar.Set(i.Bytes) },
		Failed:   func(i teamspeak.FileTransferFailedInfo) { slog.Warn("upload", "stage", i.Stage, "err", i.Err) },
	},
})
```
