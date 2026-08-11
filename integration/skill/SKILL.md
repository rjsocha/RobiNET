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

Every member is also `<member>.<kind>.<instance>.instance` - the name on its
certificate, answered by the lighthouse, which every member handshakes. The
kind is `connector`, `tenant` or `hub`. Use these to reach a member that
carries no network, or before any connector is admitted; `dns install`
configures them too.

Do not deploy a connector for this. If one is already in that network, joining
the instance is the whole procedure.

## Expose a network from a container

```sh
robinet instance create --name <name>
robinet instance show <name>           # prints ROBINET_ENDPOINT to paste
robinet instance token <name>          # new shared token; old endpoints stop enrolling
```

Run `wyga/robinet:1` in that network with `ROBINET_ENDPOINT` set and a volume
at `/data`. Then admit it, below.

Paste that endpoint whole. It is `host/instance` with a shared token and the
hub's pin after it when there are any, and the pin is the part worth keeping:
it is what stops somebody in the middle keeping a ban from reaching the
connector. Nothing in the string is decoration and none of it is optional once
it is printed.

A connector always announces one zone, and says which in its log as
`announcing ... domain=...`. `ROBINET_DOMAIN` if set, else the platform's zone
if robinet knows the platform (Railway announces `railway.internal`), else `.` -
the root, meaning its network appends nothing to a name, which is what a docker
compose network wants: `db.<connector>.<instance>.robinet` is asked over there
as `db`. Nothing has to be configured for either. `ROBINET_DNS=0` announces
none at all.

## Admit somebody

```sh
robinet member pending                 # what is asking, what it announced, what it will be called
robinet member approve <id>            # --name, --routes to change or accept less; --no-domain refuses its zone
robinet member reject <id> --reason "..."
robinet member list                    # who is inside
robinet member ban <name> --note "..."    # keep one out; routes gone, certificate refused, member stays
robinet member unban <name> --note "..."  # let it back in; nothing is reissued
robinet member remove <name>              # forget a banned one for good; burns its key and certificate
```

Never approve without showing the user what the request announced. Only the
owner of an instance can approve, and nobody can be asked to approve remotely.

A name is unique inside an instance and nowhere else, so `ban`, `unban` and
`remove` refuse a name held by two instances this machine owns rather than
guessing. `--instance <name>` settles it.

**Retiring a member is two steps, in this order.** `ban` keeps it out and keeps
it: its routes go and its certificate is refused everywhere, but it stays,
holding its name and address, and `unban` reverses it. `remove` then forgets it
and frees the name and the address, burning its key and certificate for good.

A ban is not instant everywhere. This machine takes it on its next refresh, and
a connector within five minutes, which is how often one asks. A banned
connector does not stop or exit: it logs that it was banned and keeps running,
refused by everybody until `unban`, and neither the ban nor the unban needs it
restarted. A container that looks alive after a ban is behaving correctly.

`remove` on a member that is not banned is refused, and this is not ceremony. A
certificate cannot be revoked, so an unbanned member holds a valid one for the
address the removal frees, and the next member admitted would be handed an
address something can still reach the network with.

**A redeployed connector is a new member.** A fresh volume is a fresh key, so
it arrives as a stranger and the one it replaces still holds its name and
address. Approving is refused until the old one is retired: `ban`, then
`remove`. The removal burns the old key, so that container never enrols again
without a new volume.

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
- Never reach for `remove` first. It only follows a `ban`, and the ban is what
  makes freeing the address safe.
- Never replace an instance's shared token to tidy up. `instance token` retires
  every connector endpoint handed out so far; admitted connectors keep running,
  but nobody can deploy a new one from the old string.
