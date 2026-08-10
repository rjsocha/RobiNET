# Quick reference

**Where to get help**:
[the project's issues](https://github.com/rjsocha/robinet/issues)

**Supported architectures**:
`linux/amd64`

# Supported tags and respective `Dockerfile` links

- [`wyga/robinet:1` (Dockerfile)](https://github.com/rjsocha/robinet/blob/master/Dockerfile)

# What this is

Reach a private network you have no route to - a Railway environment, a docker
compose network, a subnet behind somebody else's NAT - without a public address
on either side and without a hosted third party in the middle.

This image is the **connector**: the part that runs inside the network being
exposed. It dials out, joins an encrypted mesh, and forwards TCP, UDP and DNS
from that mesh into the network it sits on. It opens no port and needs no
public URL.

**This is not plug and play.** It requires a RobiNET hub of your own, on a
public address, and an instance on it that you own. There is nothing to sign up
for: the hub is the same program run with different arguments. See
[the project](https://github.com/rjsocha/robinet).

# Running it

```
docker run -d \
  -v robinet:/data \
  -e ROBINET_ENDPOINT=hub.example.com/my-instance/shared-token \
  -e ROBINET_NAME=compose \
  wyga/robinet:1
```

`ROBINET_ENDPOINT` is the line `robinet instance show` prints for your
instance. The volume holds the keypair that is this connector's identity:
without it, every restart arrives as a stranger and has to be approved again.

The connector then enrols and waits. Nothing is granted until the owner of the
instance approves it, on their own machine:

```
robinet member pending
robinet member approve <id>
```

# Compose

```yaml
services:
  app:
    image: your/app          # publishes nothing

  vpn:
    image: wyga/robinet:1
    restart: unless-stopped
    environment:
      ROBINET_ENDPOINT: hub.example.com/my-instance/shared-token
      ROBINET_NAME: compose
    volumes:
      - vpn:/data

volumes:
  vpn:
```

Once approved, `app` is reachable from any machine in that instance, at its
address on the compose network, although nothing published a port.

# Configuration

| Variable | What it does |
|---|---|
| `ROBINET_ENDPOINT` | `<hub>/<instance>[/<token>]`, or a full enrolment url. Required |
| `ROBINET_INSTANCE` | the instance, when the endpoint is a bare host or a full url |
| `ROBINET_TOKEN` | the instance's shared token, when the endpoint does not carry it |
| `ROBINET_NAME` | what the owner sees when deciding whether to admit this connector |
| `ROBINET_ANNOUNCE_ROUTES` | prefixes to carry, on top of what is detected |
| `ROBINET_DOMAINS` | domains it can resolve, on top of the search list it detects |
| `ROBINET_DISABLE_AUTODISCOVER` | detect neither, and carry only what was given |
| `ROBINET_KEEP_PLATFORM_IPV4` | announce a platform's IPv4 range too. On Railway that range is the same for every project, so it is dropped by default |
| `ROBINET_DNS` | answer DNS on the overlay address, using the resolver it sees. On by default |
| `ROBINET_STATE` | where the identity is kept. `/data`, and it must survive restarts |
| `ROBINET_MTU` | override the computed stack mtu |
| `ROBINET_INSECURE` | accept the hub's self signed certificate. On by default |
| `ROBINET_LOG` | `debug`, `info`, `warn`, `error` |

# What is worth knowing

**It needs no privileges.** No `NET_ADMIN`, no `/dev/net/tun`, no
`--privileged`. The network stack runs in user space, which is what lets this
work on a platform that hands out a container and nothing else.

**Nothing here grants anything.** The connector asks. The owner of the instance
decides, with a signing key the hub has never seen, and can withdraw it: a ban
takes the connector's routes out of the table for everybody at once.

**On the wire this is plain Nebula.** [Nebula](https://github.com/slackhq/nebula)
is imported as a Go library and compiled into this image - no fork, no patches,
no vendored copy, and no `replace` in `go.mod`. The handshake, the certificate
format and the lighthouse protocol are upstream's, unchanged.

What RobiNET adds is the control plane around it: enrolling a machine that has
never been seen before, admitting it by a signature from an ssh key, and a
route table that lives on the hub so admitting a connector changes what
everybody sees. A stock `nebula` binary can join the same mesh, given a
certificate from that instance and the lighthouse in its `static_host_map` -
it just has to be handed its routes by hand, and they will not follow changes.

There is no second service to run.

**Ping is not a reachability test.** The connector answers echo requests for
every address in the range it carries, including addresses where nothing
exists. Test the actual port.

# Source and licence

[github.com/rjsocha/robinet](https://github.com/rjsocha/robinet). The code
written for RobiNET is in the public domain; Nebula is MIT and remains so.
