# robinet - operating manual

Audience: an agent acting on a user's request. The user asks for access to a
network; this document says what to run and how to read the result.

Scope: the tenant side of one machine, and starting a connector. Running a hub
is not covered here.

## What robinet does

Gives this machine routes into a private network it has no path to - a Railway
environment, a docker compose network, a subnet behind somebody else's NAT - by
way of a connector already running inside that network.

Three facts that determine most answers:

- A **hub** introduces machines. It holds no keys and decides nothing.
- An **instance** is one network's mesh. Its **owner** holds its certificate
  authority and is the only one who can admit anybody.
- A **connector** runs inside the exposed network and carries its prefixes. A
  **tenant** consumes them. This machine is a tenant.

## Establishing state before acting

Run `robinet status` first. It answers every question about where this machine
stands.

```
hub        https://hub.example.com:8443
machine    robert@laptop (binder robert)

connections
  INSTANCE      ROLE    ADDRESS        ADDRESS6              DEVICE    STATE    ROUTES
  railway-prod  tenant  198.19.4.7/24  fd59:a:b:4::7/112     robinet0  up       fd12:a3a7:1986:1::/64
  staging       tenant  -              -                     robinet1  waiting  -
```

The `ADDRESS6` column appears only when something has one. Two more lines
appear only when this machine chose something: `routes ipv4 only, by local
choice` and `inbound open`.

| Result | Meaning | Next action |
|---|---|---|
| `this machine is not registered with a hub` | `join` has not been run | run `robinet join` as the user, with their ssh-agent; it starts the daemon too |
| `could not reach the daemon` | the daemon is not running | `robinet setup`, or `systemctl start robinet` |
| a connection is `up` | routes are installed | use the addresses directly |
| a connection is `waiting` | the owner has not decided | nothing to do; the user must ask them |
| a connection is `down` | the daemon has not brought it up yet | wait one refresh, default 15s |
| no connections | this machine belongs to nothing yet | `robinet instance list`, then `robinet instance attach <id>` |

## Task: reach a network somebody else exposes

1. `robinet instance list` - shows every instance on the hub with its owner. A
   row whose `ROLE` is `-` is one this machine does not belong to; the `OWNER`
   column says which binder to ask.
2. `robinet instance attach <instance>` - by name or by identifier, both
   resolve. Asks the owner to admit this machine; the request carries the name
   the hub vouched for, so the owner sees a person, not a key.
3. The tunnel comes up on its own once approved. Poll `robinet status` rather
   than asking the user to do anything.

Once `up`, addresses inside that network work directly: `curl http://10.128.4.12:8080/`.

Do not suggest deploying another connector for this. If a connector is already
in that network, joining the instance is the whole procedure.

4. `robinet dns install` - optional, and not automatic. Points this machine's resolver
   at the connector answering for each domain that instance carries, so names
   work rather than addresses. It elevates itself, needs systemd-resolved, and
   says so when there is none. It writes a file per device under
   /etc/systemd/network, so it survives a restart. Run it again after a
   connector is admitted, since the table will have changed.

## Task: expose a network with a connector

The connector runs inside the network being exposed and needs no capabilities
and no tun device. It is configured entirely by environment variables, which is
what makes it deployable on a platform that offers nothing else.

| Variable | Meaning |
|---|---|
| `ROBINET_ENDPOINT` | `host/instance[/token][/pin]`, or a full enrollment url |
| `ROBINET_INSTANCE` | instance id, when the endpoint is only a hub url |
| `ROBINET_TOKEN` | the instance's shared token, when the endpoint does not carry it |

Two different tokens exist and they are never interchangeable. The **registry
token** belongs to the hub and registers a machine; it is what a variant build
carries and what `robinet join` uses. The **shared token** belongs to one
instance, is generated when it is created, and is what a connector's enrollment
is signed with. A connector never sees the registry token.

`robinet instance token <name>` replaces the shared token and prints the new
endpoint. It gates enrollment and nothing else, so connectors already admitted
hold certificates and keep running, while every endpoint handed out before it
stops being able to enroll anything new.
| `ROBINET_STATE` | state directory; **must** be persistent |
| `ROBINET_NAME` | label shown to whoever approves |
| `ROBINET_ANNOUNCE_ROUTES` | prefixes to announce, comma separated |
| `ROBINET_DOMAIN` | the one zone this connector resolves. Replaces what the platform would say rather than joining it. `.` means its network appends nothing to a name |
| `ROBINET_DISABLE_AUTODISCOVER` | set to stop detecting attached networks |
| `ROBINET_MTU` | override the computed stack mtu |
| `ROBINET_DNS` | forward DNS to the container's resolver, on by default |
| `ROBINET_INSECURE` | skip hub certificate verification, on by default |

`ROBINET_ENDPOINT` takes a short form so one field carries everything:

```
192.0.2.10/76615289c33b3186              host and instance
192.0.2.10/76615289c33b3186/sekret       and the shared token
192.0.2.10/76615289c33b3186/SHA256:uT9x  and the hub's pin
192.0.2.10/76615289c33b3186/sekret/SHA256:uT9x
192.0.2.10:9443/76615289c33b3186         on a non default port
https://hub.example.com:8443/v1/enroll/76615289c33b3186
```

Port 8443 is assumed when none is given. Ask the instance's owner for this
string: `robinet status` prints it for the instances they own.

The token and the pin are both optional and neither is found by counting: a
pin says what it is, so `SHA256:` is what tells the two apart. A pin appears in
the string when the machine that printed it verifies its own hub by one, and it
is worth carrying - it is what stops somebody in the middle keeping a ban from
reaching this connector. Nothing else in an enrollment result can be forged,
but the blocklist can be withheld.

docker compose:

```yaml
services:
  robinet:
    image: wyga/robinet:1
    environment:
      ROBINET_ENDPOINT: 192.0.2.10/76615289c33b3186/sekret
    volumes:
      - robinet-state:/data
volumes:
  robinet-state:
```

The image is `wyga/robinet:1`. It carries `dig` and `curl` for looking around
from inside the exposed network, and the ca-certificates needed when the hub
has a real certificate and `ROBINET_INSECURE=0` is set.

`ROBINET_STATE` on a volume is not optional. The directory holds the
connector's keypair, which is its identity. Without it, every restart returns
as a stranger, needing approval again, and `ban` and `forget` stop meaning
anything. The connector warns at startup when the path looks temporary.

After starting it, the instance owner has to approve it. If the user owns the
instance, that is `robinet member approve <id>` on their machine.

## Task: replace a connector that was redeployed

A connector deployed again with a fresh volume is a new key, so it is a new
member asking to be let in - and the one it replaces is still in the instance
under the same name, holding an address.

1. `robinet member pending` - the new one is there, and `WILL BE CALLED` says
   the name it wants, which is the name the old one holds.
2. `robinet member ban <name> --note "redeployed"` - the old one stops being
   able to reach anybody, which is what has to be true before its address can
   go to somebody else.
3. `robinet member remove <name>` - forgets it and frees the name and the
   address. Only a banned member can be removed, and this burns the old key and
   the old certificate for good.
4. `robinet member approve <id>` - now that the name is free.
5. `robinet dns install` - the name space is the same, but the address behind
   it changed.

The two steps are not ceremony. A certificate cannot be revoked, so the old
member holds a valid one for its address until it expires, ten years out. Free
that address without burning the certificate first and the next member admitted
gets handed an address something else can still use.

## Task: admit somebody, on an instance this machine owns

`robinet status` lists what is waiting:

```
waiting for a decision
  ID        INSTANCE      KIND       NAME     ADDRESS        ROUTES        FROM
  9c1f4a20  railway-prod  connector  railway  198.19.4.3/24  10.128.0.0/9  35.x.x.x
```

| Command | Effect |
|---|---|
| `robinet member approve <id>` | signs a certificate; the applicant connects on its own |
| `robinet member approve <id> --routes 10.1.0.0/16` | accepts only part of what a connector announced |
| `robinet member reject <id> --reason "..."` | refuses; a connector that restarts asks again |
| `robinet member ban <name> --note "..."` | takes its routes away and puts its certificate on every member's blocklist, so it can no longer reach anybody; the member stays, holding its name and its address |
| `robinet member unban <name> --note "..."` | takes it off every blocklist and puts its routes back; nothing is reissued |
| | a ban reaches this machine on the next refresh and a connector within five minutes, since that is how often one asks. A banned connector says so in its log and keeps running: it is refused by everybody until it is unbanned, and it needs no restart either way |
| `robinet member remove <name>` | forgets a banned member and frees its name and address, burning its key and its certificate for good; refused for one that is not banned |
| `robinet member ban <name> --instance <instance>` | settles which one is meant; a name is unique inside an instance and nowhere else, so `ban`, `unban` and `remove` refuse a name held in two of them rather than guessing |
| `robinet member approve <id> --no-domain` | admits it and refuses the zone it announced: it carries routes and no names. There is nothing between the two, since it answers for the zone its own resolver knows or for none |
| `robinet instance delete <name> --force` | removes it from the hub and its authority from here, for good |
| `robinet instance token <name>` | replaces the shared token; running connectors are unaffected, endpoints handed out before it stop enrolling |
| `robinet inbound open` | lets members of an instance reach ports on this machine; the default is ping |
| `robinet reach` | every network this machine can get to, and the name space for each |
| `robinet dns list` | what the resolver would be told, without changing anything |
| `robinet dns alias <name> <as>` | answer for a name space under a shorter name here; local, told to nobody |
| `robinet member forget <id>` | drops the record so it stops appearing |

`KIND` is `connector` when it carries routes and `tenant` when it consumes
them. A tenant is granted no routes to carry, whatever it asked for.

## Deciding for this machine, and telling nobody

Two things are local: no owner sets them, the hub is never told, and they
change no certificate.

| Command | What it decides |
|---|---|
| `robinet inbound [ping\|open\|none]` | what other members may reach here. `ping` unless told otherwise: joining an instance to reach a network is not an offer to be reached back |
| `robinet family [both\|ipv4\|ipv6]` | which families of route go on this machine's device. `both` unless told otherwise |

## Failures and what they mean

| Message | Cause | Action |
|---|---|---|
| `registration rejected: either the token is wrong or none of these keys is known to the hub` | deliberately ambiguous; the hub never says which | have the hub operator confirm the user's public key is in its configuration |
| `the hub's public key does not match the pin this binary carries` | the hub is not the one this was built for, or its key changed | ask its operator for the current pin; do not work around it with `--insecure` |
| `no ssh-agent: SSH_AUTH_SOCK is not set` | `join` needs the agent | start one and `ssh-add`, or pass `--ssh-key <file>` |
| `the agent does not hold SHA256:...` | wrong `--ssh-fingerprint` | drop the flag to try every key the agent has |
| `<prefix> is already carried by the connection to <other>` | two instances claim the same range | `robinet instance detach` one, or run them in separate network namespaces |
| `only the owner of that instance may do that` | this machine is a member, not the owner | the owner has to act |
| `this machine does not belong to that instance` | not admitted yet | `robinet instance attach <id>` and wait |
| `up needs CAP_NET_ADMIN` | started without the capability | `robinet setup` installs a unit that grants exactly that |
| `a connector is already called <name>` | the one it replaces is still a member, usually after a redeploy with a fresh volume | `robinet member ban <name>` and `robinet member remove <name>`, then approve; or approve with `--name` if both are meant to stay |
| `<name> is not banned: ban it first` | `remove` frees an address the member still holds a valid certificate for | `robinet member ban <name> --note "..."`, then remove |
| `<name> is a member of <a> and <b>: say which with --instance` | a name is unique inside an instance and nowhere else | add `--instance <name>`, or use the fingerprint instead |
| `this key was removed from <instance> and will not be admitted again` | a removed connector is enrolling with the key that was burned when it was removed | give it a new keypair, which for a container means a fresh state volume |
| `enrollment refused, waiting before letting this process exit` | the hub turned the request away, and it will turn the next one away the same way | read the error beside it; the connector waits 30s before exiting so a supervisor restarting it does not bury the reason |
| `this connector has been banned` | somebody ran `robinet member ban` on it; every member of that instance now refuses it | nothing on the connector. It keeps running and keeps asking, and `robinet member unban` brings it back without a restart |
| `ROBINET_DOMAIN: domain ... is not a letter, digit or hyphen` | the variable holds something that is not one zone | one zone, or `.` for a network that appends nothing; refused before anything reaches the hub |
| `the daemon is running <x> and this command is <y>` | the binary was upgraded, the service still runs the old one | `robinet restart` |
| `robinet is not configured: ROBINET_ENDPOINT is still CHANGEME` | a template was deployed without being edited | set it to what `robinet instance show` printed |
| `cannot carry <prefix>: this instance has no address of that family` | the hub has no IPv6 pool, so no certificate can hold an IPv6 route | set `overlays6` on the hub and create a new instance |
| `this daemon is too old to restart itself` | it predates the restart endpoint | `sudo systemctl restart robinet`, once |

## Facts that are easy to get wrong

**Ping is not a reachability test.** The connector's stack answers echo requests
for every address in the range it carries, including addresses where nothing
exists. Always test the actual port.

**Certificates are signed once.** They say who a member is, not what it can
reach. Routes come from the hub and change on their own, so a newly admitted
connector becomes reachable without anything being reissued or restarted,
usually within one refresh.

**A connector whose network moved is silently useless.** Its certificate carries
the prefixes it had when it was approved. It logs a warning at startup when what
it detects no longer matches. The fix is to purge its state directory and enroll
again, which needs approval again.

**A connector that asked to be called something impossible is not turned
away.** A name has to work as a domain name; one that cannot is dropped and
kept as a hint, so the owner sees what was meant and can approve it under a
name of their own with `member approve --name`.

**A connector that asked for nothing is named from what it said about itself**,
in this order: the platform's environment and project, as `<environment>.<project>`;
then its service, project or hostname, whichever first reads as a label; and
failing all of that, its kind and the first eight characters of its key. In a
container the hostname is the short container id, so a compose connector with
no `ROBINET_NAME` becomes something like `7a2f93195965`. `member pending` shows
the result as `WILL BE CALLED` before any decision, and it is worth overriding:
`docker compose down` and up again is a new container with a new id, while the
member keeps the name it was admitted under.

**Every member is also `<member>.<kind>.<instance>.instance`.** That is the name
its certificate was issued to, and the lighthouse answers for it: every member
handshakes the lighthouse, so it holds the one complete list of who is where.
The kind is `connector`, `tenant` or `hub` - the lighthouse itself is
`hub.<instance>.instance`. This works for members that carry nothing at all,
which the name spaces below do not cover, and it needs no connector to be
admitted first.

`robinet dns install` configures this alongside the rest; it is answered by the
daemon's own resolver, which forwards it to the lighthouse. The hub decides
whether to answer at all, with `dns` in its configuration.

**A connector always announces a name space**, and four things decide which,
in this order:

1. `ROBINET_DNS=0` announces none at all, since nothing here would answer them.
2. `ROBINET_DOMAIN` is taken as given, and replaces anything detected rather
   than joining it. One zone: a connector answers under one name space, so a
   second could only be recorded and never asked. A value that is not a domain
   is refused by the connector at startup, before anything reaches the hub.
3. Otherwise the platform is asked. Railway states this deployment's own name
   in `RAILWAY_PRIVATE_DOMAIN`, and the zone is read off the end of it, so
   `nginx.railway.internal` announces `railway.internal`.
4. Failing all of that, `.` - the root, which is the network saying it appends
   nothing to a name. `db.<connector>.<instance>.robinet` is then asked over
   there as `db`, which is exactly what a docker compose network answers, so
   two compose projects that both call a service `db` stay apart the same way
   two Railway projects do, with nothing configured.

**Every name is `<something>.<connector>.<instance>.robinet`.** A connector
announces one zone - `railway.internal`, or `.` where names carry no suffix -
and the daemon answers under a name space of its own instead, built from the
connector's name and the instance's. So two Railway projects,
which both call their network `railway.internal`, are two different name spaces
here and both are reachable. `robinet dns install` writes that, and it is not
automatic: it changes how names resolve on this machine. Run it again after
admitting a connector.

**The daemon answers DNS itself**, on each connection's overlay address, port
5354, over UDP and TCP. It rewrites the name, asks the connector, rewrites the answer back, and
drops records of a family that connector does not carry. Nothing else may reach
it: the inbound firewall answers ping and nothing more unless this machine says
otherwise.

**The first packet to a member can be lost.** Reaching one that has not been
spoken to recently starts a handshake, and whatever asked for it waits: a `dig`
with a short timeout fails and the next one answers. It is not a fault, and
retrying is the whole fix.

**ICMP is not forwarded.** TCP and UDP are.

**A hub is verified by a pin, not by an authority.** Its certificate is usually
self signed. `robinet join --pin SHA256:...` checks the hub's public key
against that value and nothing else, which is a narrower statement than any
certificate authority makes. A build handed out to a group carries the pin
already, and a connector's endpoint carries it as its last part. `--insecure`
accepts anything and is the weaker answer.

Pins were once written `sha256/` with standard base64. That form is still read
everywhere one is accepted, so nothing has to be reissued, but it contains a
`/` and cannot travel in an endpoint. What `robinet hub test` prints is the
current form.

**Both families, always signed.** Every member gets an IPv4 and an IPv6 address
from its instance, and its certificate carries both, because nebula refuses an
unsafe network unless the certificate holds an address of that family. A
machine may install only one of them - `robinet family ipv4|ipv6|both` - which
is local, told to nobody and changes no certificate.

**On Railway, announce IPv6.** Every project on the platform is handed the same
`10.128.0.0/9`, so it identifies nothing and collides with every other
connector; the IPv6 prefix is unique per environment. A connector that detects
Railway announces only its `/64`. `ROBINET_KEEP_PLATFORM_IPV4=1` puts the IPv4
range back.

**IPv6 needs 1280, and below it fails silently.** A connector's user space
stack refuses to send any IPv6 packet on a link narrower than that, which is
what RFC 8200 requires of every link. IPv4 keeps working, so the symptom is
"IPv6 does not work here" with nothing in any log: packets arrive, are
delivered, a flow is created, and no answer ever leaves. The connector now
floors its stack at 1280 and warns when the path is genuinely narrower.

**The path that matters is the tunnel's, not the carried network's.** A
connector computes its MTU from the interface with the default route, because
that is where packets to the other members go. The link to the network being
carried constrains a different connection - the one this connector opens to a
service there, made by the host with the host's own MTU.

**MTU matters.** The connector takes the lower of its own link and the hub's,
minus nebula's overhead. Railway hands out 1316, which is below the usual
assumption; getting this wrong shows up as large transfers hanging rather than
as an error.

**DNS is answered by the connector**, on its own overlay address, using the
resolver inside the exposed network. Query it directly to check:
`dig @198.19.4.3 some-service.railway.internal`.
