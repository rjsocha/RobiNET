# robinet

Reach a private network you have no route to - a Railway environment, a docker
compose network, a subnet behind someone else's NAT - without a public address
on either side and without a hosted third party in the middle.

Linux only. Early, and honest about it: the enrollment path is covered by tests
end to end, the tunnel has been brought up by hand, the connector has not been
run in anger yet.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/robinet-connector)

That deploys a connector into a Railway environment. It needs a hub of your
own: there is nothing to sign up for, and the button is one end of a mesh
rather than a product.

## This is nebula, plus some code around it

**The tunnel is [nebula](https://github.com/slackhq/nebula).** All of it: the
noise handshake, the certificate format, the lighthouse, hole punching, relays,
the firewall, the tun device. robinet imports nebula as an ordinary Go module
dependency. There is no fork, no patch set and no vendored copy - the version
in `go.mod` is upstream, and updating it is `go get`.

**On the wire this is plain nebula**, and that follows from the above rather
than being a separate promise. A stock `nebula` binary joins the same mesh,
given a certificate from that instance and the lighthouse in its
`static_host_map`; it just has to be handed its routes by hand, and they will
not follow changes.

What robinet adds is the part nebula deliberately leaves to you:

- **an enrollment path**, so a machine that has never been seen before can ask
  to join and be admitted by a person, instead of somebody copying certificates
  around by hand
- **ssh keys as the root of trust**: your agent signs a bootstrap message in
  OpenSSH's SSHSIG format, the same thing `ssh-keygen -Y sign` produces, so the
  hub's configuration lists the same keys you would put in `authorized_keys`
- **a hub** that carries those requests, hands out address space and ports, and
  runs a lighthouse per instance - while holding no signing key, so it can never
  produce an identity
- **a user space stack** built on nebula's overlay device and gvisor, so a
  connector runs in a container with no `NET_ADMIN` and no `/dev/net/tun`, and
  still forwards TCP, UDP and DNS into the network it lives in

Everything else - the hard part, the cryptography and the transport - is
nebula's, and this project would not exist without it.

## Vocabulary

**hub** - the node on a public address. A lighthouse per instance, the
enrollment mailbox, the address pools. Holds no authority key.

**instance** - one mesh: its own authority, its own overlay prefix, its own
lighthouse on its own UDP port.

**tenant** - the daemon on your machine. Holds the authority, decides who joins,
runs nebula with a real tun so this host can reach what a connector offers.

**connector** - what runs inside the network being exposed. No tun device, no
capabilities.

## How it fits together

```
connector                     hub                        tenant
(no capabilities)      (public address)            (your machine)

  enroll  ------------->  stores the request
                          allocates an address
                                                <---  polls for pending
                                                      you approve locally
                                                      signs a certificate
                          holds the certificate  <---  posts it back
  collects  <-----------
  starts nebula
        \                lighthouse introduces        /
         \____________  them, then they talk _______ /
                        directly if they can
```

The authority key is generated on your machine and never leaves it. The hub
carries public keys, announced routes, hints and signed certificates - all of
which are public by nature. A compromised hub can deny service. It cannot mint
an identity, and it cannot decide who joins.

## Try it

```
# on a machine with a public address
robinet hub init --endpoint 203.0.113.10        # writes /etc/site/robinet/hub.yaml
sudoedit /etc/site/robinet/binder/me.yaml         # who may create instances, by ssh key
robinet hub test                                # what that resolves to
robinet hub install                             # a systemd unit, no capabilities at all

# on your machine, as yourself, with your ssh key in the agent
robinet join --hub https://203.0.113.10:8443 --token <the hub token> --insecure
robinet setup                                     # elevates itself; runs as you with CAP_NET_ADMIN
robinet instance create --name railway-prod --shared-token shared

# inside the network you want to reach
robinet connect --endpoint https://203.0.113.10:8443/v1/enroll/<id> \
  --token shared --state /data

# back on your machine
robinet status                # the request is waiting
robinet member approve <id>
```

Somebody else who needs the same network registers their own machine and asks
to be let in, rather than deploying a second connector:

```
robinet join --hub https://203.0.113.10:8443 --token <the hub token> --insecure
robinet instance attach <instance id>     # appears in the owner's status, by name
```

For a group, a preconfigured binary saves the first step's arguments:

```
make variants                    # from variant/<name>/config.json
robinet.variant.<name> join      # the hub and the token are already in it
```

It presets nothing that matters: the ssh key still decides who you are, and the
owner still decides what you may reach.

Every connector flag can be given as an environment variable instead
(`ROBINET_ENDPOINT`, `ROBINET_TOKEN`, `ROBINET_STATE`), which is
how it is configured on a platform that offers nothing else.

## What it does not do

- It does not forward ICMP. Ping is not a reachability test either: promiscuous
  mode makes the connector's stack answer echo requests for every address in the
  range it carries, whether or not anything is there.
- It does not renew certificates. They are signed once, long lived, and a
  connector whose network changed enrolls again.
- It does not carry two routes to the same prefix. One route table cannot hold
  both, so a colliding prefix blocks approval until the holder is banned.
- It has no remote panel. Decisions are made on the machine that holds the
  authority, over a unix socket.

## Building

```
make local     # host only
make build     # linux/amd64 and linux/arm64 into dist/
make test
make race
```

## License

**Public domain.** The code written here reserves no rights: copy it, change
it, sell it, no attribution asked for.

nebula is a separate matter. It is MIT, Copyright (c) 2018-2019 Slack
Technologies, Inc., it is used here unmodified, and its notice travels with any
binary built from this repository because that binary contains its code. Both
texts are in [LICENSE](LICENSE).
