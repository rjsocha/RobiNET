# The whole thing on one machine

A hub, a tenant that owns an instance on it, and a connector carrying a compose
network that publishes nothing. Linux only, and deliberately so: it depends on
docker bridges behaving the way they do on Linux.

```
./demo.sh
```

That is the whole demo. It takes about a minute, ends by printing what to try,
and `./teardown.sh` removes everything including the keys.

## What it does, in order

**1. Generates the tenant's ssh key.** Into `tenant/secret/`, which is ignored.
It is the only generated thing here, and it is generated on the side that owns
it: the private half never leaves that directory, and the hub is given the
public half as `hub/secret/binder/demo.yaml`. That file is what a binder is - a
name and the keys that speak for it, the same keys you would put in
`authorized_keys`.

**2. Starts the hub.** After the binder file exists, because a hub with nobody
allowed to create an instance refuses to start.

**3. Registers the tenant and creates an instance.** Registering signs a
bootstrap message with the ssh key; the hub records the machine identity that
comes out of it and every later request is signed with that. Then the daemon
creates `example`, which is where its certificate authority is generated - on
this machine, and never anywhere else.

**4. Starts the connector.** It enrolls and waits. Nothing has been granted
yet.

**5. Approves it.** The tenant signs a certificate for the connector, naming
the network it may carry. The route table on the hub changes, every member
reads it, and the tunnel comes up on its own.

## Then

```
cd tenant && docker compose exec tenant sh
```

From inside, the compose network is reachable although nothing published a
port:

```
dig @198.19.0.254 mysql.robinet-demo-net +short   # the connector answers for its network
nc -z <that address> 3306                         # mysql, through the tunnel
```

The connector's address on the instance is what `demo.sh` prints and what
`robinet member list` shows. Connectors are allocated from the top of the
instance prefix and everyone else from the bottom, so an address says which
kind of member holds it. The answer is mysql's address on the compose network, which nothing
outside that network has a route to.

On a machine with `systemd-resolved`, `robinet dns install` installs that resolver for
the domains each connector announced, and the name then resolves without naming
a server. The tenant container here has no resolved, so it says so and changes
nothing - which is the intended behaviour rather than a gap in the demo.

## The addresses, and why they are fixed

| What | Where |
|---|---|
| hub | `250.250.250.250`, on the `robinet-demo` bridge |
| tenant | `250.250.250.251`, same bridge |
| connector | `250.250.250.252`, same bridge, plus one on `172.31.250.0/24` |
| mysql | on `172.31.250.0/24`, its own network only, as `mysql.robinet-demo-net` |
| the instance | `198.19.0.0/24` and `fd42:6f62:696e::/112` |

Fixed because they end up in a certificate, in a connector's environment and in
this document. A demo whose addresses moved between runs would be a demo that
could not be written down.

The hub publishes no ports and sits on a named bridge instead. Publishing would
break it: a lighthouse learns where a member is from the source address of its
packets, and docker's userland proxy replaces that with its own, so every
member would look like it came from one place and none could be told apart.

The connector is on the hub's bridge as well as its own, because docker
isolates bridge networks from each other and it has to reach the hub. That is
an artefact of running everything on one machine - on a real platform the hub
is somewhere on the internet. It is also why the connector announces its routes
explicitly here: detection would otherwise offer to carry the hub's own
network.

## What is worth noticing

**The hub holds no key and makes no decision.** It allocates addresses and
ports, carries enrollment requests and keeps the route table. Delete
`hub/hub.yaml` and there is nothing secret left in it: the registry token
proves knowledge and grants nothing, because an ssh signature still decides who
you are.

**The authority never moves.** It is generated when the instance is created and
stays in the tenant's state volume. Losing that volume loses the instance for
good - nobody else has a copy.

**The shared token never travels.** `ROBINET_ENDPOINT` carries it as
`host/instance/token`, and the connector uses it to authenticate its enrollment
rather than to send it: the request goes to `POST /v1/enroll/example` with a
code computed from the token. Watching the wire does not reveal it.

**The instance is named, not identified.** `250.250.250.250/example/demo` works
because only one instance here is called `example`. Names are not unique on a
hub, so a shared one is refused rather than guessed at, and the identifier is
always accepted.

**Nothing granted the connector anything.** It asked. The owner decided, on
their own machine, with a key the hub has never seen.

## Running the pieces separately

Each directory is a compose project of its own, and the order above is the
order they need. `hub/hub.yaml` is fixed and committed, which is what makes the
join line and the connector's endpoint constants rather than something to copy
between runs.

`hub/secret/` and `tenant/secret/` are ignored. Running `demo.sh` again leaves
an existing key alone: regenerating one would orphan every machine already
registered under it.
