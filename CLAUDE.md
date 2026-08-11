# robinet

A personal tunnel built on nebula. Three roles in one binary: a **hub** on a
public address, a **tenant** daemon on an operator's machine, a **connector**
inside the network being exposed.

This file is a routing table. Read the section that matches the work, not all
of them.

| Question | Read |
|---|---|
| What is this, what are the roles, why is it built this way | [SPEC.md](SPEC.md) |
| How does somebody use it | [doc/MANUAL.md](doc/MANUAL.md), written for an agent |
| What is deployed where, what is published, how to release | [doc/DEPLOY.md](doc/DEPLOY.md), not in git |
| How to work on this project, and with its author | [doc/WORKING.md](doc/WORKING.md), not in git |
| What was decided but not built | [IDEAS.md](IDEAS.md) |
| What the package shows on install | [doc/INFO.md](doc/INFO.md) |

Before changing anything, read [doc/WORKING.md](doc/WORKING.md). It is short and
it is where the mistakes of the first session are written down.

## Layout

```
cmd/robinet/        the command line, grouped by role
internal/hub/       the public node: instances, members, routes, enrollment
internal/tenant/    the operator's daemon: authority, decisions, connections
internal/connector/ what runs inside the exposed network
internal/netstack/  gvisor: the gateway and the DNS forwarder
internal/userdev/   nebula overlay device with no tun
internal/wrak/      the authentication protocol: SSHSIG, signed requests
internal/enroll/    the enrollment wire types
internal/ca/        certificate authority and key generation
doc/                documents that ship in the package
variant/            per group build configuration, not in git
```

Nebula is an ordinary module dependency. There is no fork and no patch set.

## Known and not ours

`make race` fails on `TestSharedTokenRotation` with a data race in
`nebula/overlay/tun_disabled.go`, `Close()` against `Read()`, reached through
`hub.Delete` stopping a lighthouse. It is upstream, it predates this repository's
current state, and nothing here will fix it: patching nebula is not a thing this
project does. Confirm it is still that one and move on. Do not report it as a
finding and do not investigate it again.

Searched on 2026-08-11: no issue or pull request upstream mentions it, and
nebula's master carries the same unsynchronized `t.read = nil` as v1.11.0.
Nobody else hits it because reaching it needs `tun.disabled` and a
`Control.Stop()` on a live process, which is the hub's lighthouse lifecycle and
nothing else.
