## What and why

<!-- What does this change, and what problem does it solve? -->

Fixes #

## Checklist

- [ ] Tests cover the change, and `go test -race ./...` passes
- [ ] `golangci-lint run ./...` is clean
- [ ] `go run ./internal/tools/apidump` was run if the public API changed, and the `api/` diff is intended
- [ ] CHANGELOG.md has a bullet under `## Unreleased` if users will notice the change
- [ ] The README, the docs and doc comments are updated if behaviour changed
- [ ] I wrote this without TeamSpeak's proprietary SDK or applications: no code, headers or decompiled output from them
