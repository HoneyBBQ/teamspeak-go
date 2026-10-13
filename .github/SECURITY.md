# Security Policy

## Supported versions

| Version         | Supported |
| --------------- | --------- |
| 1.0 betas       | Yes       |
| 0.x             | No        |

Fixes go into the newest release. While 1.0 is in beta that means the newest
beta; after 1.0.0, the newest 1.x.

## Reporting a vulnerability

Please don't open a public issue. Report it privately instead, either through
GitHub ("Report a vulnerability" on the Security tab of this repository) or by
email to [ckr@chenkr.cn](mailto:ckr@chenkr.cn).

You'll hear back within 48 hours. If the report holds up, you'll get a rough
timeline for the fix, and credit in the release notes if you want it.

## What counts

This is a client: it talks to servers you point it at, and to whatever else can
reach its socket. So the things we care most about are:

- a server, or anyone who can send it packets, crashing the process, hanging it
  or making it use unbounded memory or CPU;
- anyone but the server getting the client to accept a packet as the server's;
- passwords, password hashes, privilege keys, file transfer keys or the identity's
  private key ending up in logs, errors or formatted output.

A server you connect to can, of course, send you whatever data it likes over a
working session. That on its own is not a vulnerability.
