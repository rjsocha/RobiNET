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
