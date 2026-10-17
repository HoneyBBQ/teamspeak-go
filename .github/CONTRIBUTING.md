# Contributing to teamspeak-go

Thanks for helping. Bug reports, fixes, protocol findings and documentation
changes are all welcome. For a larger change, such as a new package or an API
change, open an issue first so we can agree on the shape before you write it.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). To report
a security problem, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Clean-room rule

This library is a clean-room implementation, and that is the one rule a pull
request cannot bend. Do not contribute code, headers, constants tables or
decompiled output taken from TeamSpeak's proprietary SDK or applications, and do
not paste them into issues or comments either.

Protocol knowledge comes from watching traffic between a client and a server,
from public documentation, and from open implementations. Credit them where you
use them in the code; the README's acknowledgments already credit
[TS3AudioBot's TSLib](https://github.com/Splamy/TS3AudioBot). If you are not
sure whether something you know came from a clean source, leave it out and say
so in the pull request.

## Setup

You need Go 1.26 or newer and [golangci-lint](https://golangci-lint.run/). The Go versions the module supports, and how that changes over
time, are described under [Supported Go versions](../README.md#supported-go-versions);
CI tests them.

```sh
git clone https://github.com/HoneyBBQ/teamspeak-go
cd teamspeak-go
go build ./...
```

## Checks

CI runs these, so run them before you push:

```sh
golangci-lint run ./...
go test -race ./...
go run ./internal/tools/apidump -check
```

The linter configuration is in `.golangci.yml`. Every exported identifier needs a
doc comment; `doc_coverage_test.go` fails when one is missing.

### Public API report

The exported API of every package is recorded in `api/*.txt` and reviewed like
code. `apidump -check` fails with a diff when the code and the record disagree,
so an API change cannot land without showing up in the same commit. When the
change is on purpose, rewrite the record and commit it with the change:

```sh
go run ./internal/tools/apidump
```

Read the diff before you commit it. A symbol you did not mean to export shows
up there.

### Fuzz targets

The parsers that read what a server sends have fuzz targets (`FuzzParseCommand`
and `FuzzSplitRows` in `internal/wire`, `FuzzHandleRawPacket` in
`internal/transport`, and others). A plain `go test` runs their seed corpus. `go test -fuzz` takes one target and one package; to fuzz
`FuzzParseCommand` for a while:

```sh
go test -run '^$' -fuzz FuzzParseCommand -fuzztime 1m ./internal/wire
```

If you fix a crash a fuzzer found, keep the failing input under `testdata/fuzz`.

## Integration tests

The integration suite runs against a real TeamSpeak server and is behind a build
tag, so `go test ./...` does not run it. CI runs it against TeamSpeak 3 and 6.

Start a server in Docker and provision it with the fixture script, which creates
the channels the tests use, grants the permissions they exercise, relaxes
anti-flood, and writes an env file outside the repository. The file is
`ts3-fixture.env` under `$TMPDIR` (or `/tmp`), or the path in
`TS3_FIXTURE_ENV`; the script prints the path to source:

```sh
docker run -d --name ts3 -e TS3SERVER_LICENSE=accept \
  -p 9987:9987/udp -p 10011:10011 -p 30033:30033 teamspeak:latest
TS3_QUERY_HOST=127.0.0.1 ./scripts/ts3-fixture.sh
set -a; . "${TS3_FIXTURE_ENV:-${TMPDIR:-/tmp}/ts3-fixture.env}"; set +a
go test -race -p 1 -tags integration -timeout 300s ./...
```

The fixture sets `TEAMSPEAK_ADDR`, `TEAMSPEAK_DEFAULT_CHANNEL`,
`TEAMSPEAK_PASSWORD_CHANNEL` and `TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD`. Without
them the live tests skip. The TeamSpeak 6 image
(`teamspeaksystems/teamspeak6-server`) has no raw ServerQuery port; see
`.github/workflows/ci.yml` for the environment it needs, and set
`TS3_QUERY_HTTP` instead of `TS3_QUERY_HOST` when running the fixture.
TeamSpeak 3 serves SSH and WebQuery too, once the container is started with
`-e TS3SERVER_QUERY_PROTOCOLS=raw,ssh,http -e TS3SERVER_SERVERADMIN_PASSWORD=...`
and `-p 10022:10022 -p 10080:10080`: give the fixture `TS3_QUERY_HTTP`,
`TS3_QUERY_SSH_PORT`, `TS3_ADMIN_PW` and `TS3_QUERY_SSH_PASSWORD` (the password
you set) as well as `TS3_QUERY_HOST`, and the suites run over all three.

Run one server at a time. A server's flood protection bans an IP that connects
too fast, and two suites at once, or a rerun straight after a failure, can get
yours banned. If that happens, restart the container.

## Changes

- Add a test with a fix or a feature. A bug fix should have a test that fails
  without it.
- A change a user would notice gets a bullet in [CHANGELOG.md](../CHANGELOG.md)
  under `## Unreleased`; add that heading above the newest release if it is not
  there. Write it for someone upgrading: what changed and what they have to do.
  The release notes on GitHub are built from that file.
- If behaviour changes, update the README and the doc comments.
- Keep commits focused. Messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  as the history does: `feat`, `fix`, `docs`, `ci`, `test`, `refactor` or
  `chore`, with an optional scope, and a `!` after the type for a breaking
  change, for example `fix: resend every handshake step until the server replies`.
- Open the pull request against `main`. The template lists what to check.

## License

By contributing you agree that your contribution is licensed under the
[MIT License](../LICENSE).
