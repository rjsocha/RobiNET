---
name: robinet
description: Use when this machine has to reach a network it has no route to - a Railway environment, a docker compose network, a subnet behind somebody else's NAT - or when a network here has to be made reachable by somebody else, and for anything about RobiNET instances, members, approvals, routes or the names they resolve.
version: dev
---

# RobiNET - what to do

An **instance** is one private network. Members of it reach each other and the
networks its **connectors** carry. This machine joins an instance, or creates
one and admits others to it.

This build already knows which hub to talk to, so nothing here takes a url or a
token.

**This file says what to do. `hopper manual robinet --raw` says why, and what
each thing means.** Read the manual before explaining anything, before
diagnosing anything not listed below, and before advising on a decision the
user has to make.

## Before anything else

```sh
robinet status
```

| It says | Do |
|---|---|
| `not registered with a hub` | `robinet join` - once per machine; signs with the user's ssh key and starts the daemon |
| `could not reach the daemon` | `robinet setup` |
| `speaks a different control protocol` | `robinet restart` |
| a connection is `waiting` | nothing; the owner has not decided |
| a connection is `down` | wait one refresh, 15s |

`robinet join` and `robinet setup` are the user's to run: the first signs with
their key and then asks for their password to start the daemon. Never run them
unasked.

## Reach a network somebody else exposes

```sh
robinet instance list                  # ROLE - means this machine is not in it
robinet instance attach <name>         # name or id, both resolve
robinet status                         # poll until up
robinet reach                          # what is reachable, and what to call it
robinet dns install                    # optional, resolves those names here
robinet dns alias <name> <short>       # a shorter name for one of them, local
```

Names are `<something>.<connector>.<instance>.robinet`. `reach` says which name
spaces exist and which this machine can already resolve; `dns list` says what
the resolver would be told, and changes nothing.

Do not deploy a connector for this. If one is already in that network, joining
the instance is the whole procedure.

## Expose a network from a container

```sh
robinet instance create --name <name>
robinet instance show <name>           # prints ROBINET_ENDPOINT to paste
```

Run `wyga/robinet:1` in that network with `ROBINET_ENDPOINT` set and a volume
at `/data`. Then admit it, below.

## Admit somebody

```sh
robinet member pending                 # what is asking, what it announced, what it will be called
robinet member approve <id>            # --name, --routes, --domains to change or accept less
robinet member reject <id> --reason "..."
robinet member list                    # who is inside
robinet member remove <name>           # a member that is gone; frees its name and address
robinet member ban <name>              # one to keep out; routes gone, certificate refused everywhere
```

Never approve without showing the user what the request announced. Only the
owner of an instance can approve, and nobody can be asked to approve remotely.

**A redeployed connector is a new member.** A fresh volume is a fresh key, so
it arrives as a stranger and the one it replaces still holds its name and
address. Approving is refused until the old one is removed - `member remove`,
not `ban`, which is for keeping something out.

## Local to this machine, told to nobody

```sh
robinet inbound [ping|open|none]       # what members may reach here; ping by default
robinet family  [both|ipv4|ipv6]       # which routes go on the device
robinet dns alias <name> <short>       # another name for a name space
```

None of these is sent anywhere. No owner can set them for somebody else, and
the machine that carries the consequence is the one that chooses.

## Never

- Never run `join`, `setup` or `instance create` unasked - each one takes an
  identity or address space.
- Never use ping to decide whether something is reachable: a connector answers
  for every address in the range it carries, and ICMP is not forwarded. Test
  the port.
- Never ban a member to tidy up after one that is gone. `ban` keeps it on
  purpose, so its certificate stays refused; `remove` is the one that forgets.
