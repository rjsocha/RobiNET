# robinet

A personal tunnel that gives a workstation reachable access into a private
network it has no route to - a Railway environment, a docker compose network, a
VM subnet - without either side having a public address and without a hosted
third party in the middle.

Status: the three roles are implemented and the enrollment path is covered end
to end by tests. SSH based authentication is next, see section 5.

## 1. Problem

A workload runs on a provider that hands it a private network and no inbound
connectivity. Railway is the case that drove this: every environment sits on
`10.128.0.0/9`, service names resolve only from inside, and there is no way to
reach a database or a metrics endpoint from a laptop.

The obvious answer, a hosted mesh VPN, has costs that do not fit:

- it reserves an entire address range on the client machine, colliding with
  ranges already in use across the fleet
- it pins a magic DNS address that collides with other local tooling
- it inserts another cloud provider between the user and the workload, priced
  per seat
- every environment uses the same `10.128.0.0/9`, so a host route table can
  hold exactly one of them at a time

robinet is the smallest thing that solves this with self-hosted parts.

## 2. Vocabulary

Four words, used consistently in the code, the command line, the logs and here.

**hub** - the node on a public address. Runs a lighthouse per instance, hands
out address space and ports, and carries enrollment requests.

**instance** - one mesh: its own authority, its own overlay prefix, its own
lighthouse on its own UDP port. A hub carries several; they never mix.

**tenant** - the daemon on your machine. Holds the authority, decides who
joins, runs nebula with a real tun so this host can reach what a connector
offers. One instance, one tenant, one person.

**connector** - what runs inside the network being exposed. No tun device, no
capabilities, user space stack.

**binder** - a person the hub knows, named in its configuration by their ssh
keys. A binder may register machines and create instances.

Nothing is called a client, a user or a node.

## 3. Roles

Three roles, one binary, mode selected by flags.

**hub** - a daemon on a machine with a stable public address. Runs one nebula
lighthouse per instance, each on its own UDP port. Serves the enrollment
mailbox. Owns address allocation. Holds no certificate authority key and no
tenant secret.

**tenant** - a daemon on your own machine or VM. Holds the authority. Signs
connector certificates. Runs nebula with a real tun device and installs routes.
Talks to the hub over its own identity. Exposes a unix socket for the local
command line.

**connector** - a container running inside the private network being exposed.
No tun device, no capabilities, user space network stack. Announces the routes
it can reach, forwards TCP and UDP into that network, and forwards DNS to the
resolver it sees.

## 4. Trust model

The tenant CA private key never leaves the tenant machine. The hub carries only
material that is public by nature: connector public keys, announced routes,
environment hints, and signed certificates.

The hub cannot mint a certificate. A compromised hub can deny service, and can
see enrollment metadata, but cannot produce a valid identity.

Approval happens on the tenant machine. The hub records requests, never
decisions. This is deliberate: a hub that could record decisions would become an
authorization authority, and an attacker holding it could have a rogue connector
approved, claim a prefix, and receive the tenant's traffic for it.

The one pre-authentication surface in the system is the enrollment endpoint on
the hub. Everything else requires a signed identity or a local socket.

## 5. Identity and authentication

The WRAK protocol, implemented here. robinet and DLG share the wire format the
way two SSH clients share SSHSIG: the specification is common, the code is not.

**Bootstrap, once, unprivileged.** The tenant machine signs a canonical
bootstrap message with a key from the ssh-agent, in OpenSSH SSHSIG format. The
hub replays the message from its own configuration and checks the signature
against every key it knows; the binder follows from which key matched, so
nobody has to say who they are. The token appears in the signed message but
never on the wire, and a wrong token is answered exactly like an unknown key,
so the reply says nothing about which keys the hub holds.

The agent is tried key by key, since which of them a hub knows is the hub's
business. `--ssh-fingerprint` picks one, and `--ssh-key` signs with a file for
a machine that has no agent.

**Per request, afterwards.** Every later call carries an ed25519 machine
identity, a timestamp, a nonce and a signature over a canonical string covering
method, path, sorted query and body hash. The hub keeps an in-memory nonce set,
enforces a five minute window, and rate limits failures per source address.

Consequence: the ssh-agent is needed exactly once, in a process that is not
root. The tenant daemon runs as root and never touches it.

**Transport.** The hub's API certificate is self-signed and pinned by SPKI on
the client side, so the hub needs no publicly trusted certificate.

**Local.** The tenant CLI talks to the daemon over a unix socket. Authorization
is `SO_PEERCRED`: the kernel reports the caller's uid and gid, so there is no
token to steal and nothing to bind to a network address.

## 6. Registering, owning and joining

A machine registers with a hub once: it mints an identity of its own and signs
a bootstrap message with a key from its ssh-agent. The hub checks the signature
against every key it knows and learns which binder the machine belongs to from
whichever key matched, so nobody has to state who they are. Registering grants
nothing; it only makes the machine known.

A registered machine may then create an instance, which makes it that
instance's owner and the holder of its authority, or ask the owner of an
existing instance to let it in.

**Sharing.** A colleague who needs the same network does not deploy a second
connector into it. They register their own machine with their own ssh key, ask
to join, and appear in the owner's list under the name the hub vouched for. The
owner approves with the same command used for a connector, and their authority
signs a certificate with an address and no unsafe networks: a tenant consumes
routes, it never carries them.

Only the owner can admit anybody, and that is not a rule being enforced but a
consequence of where the authority key lives.

Transferring ownership, and several owners of one instance, are out of scope
here. Both are the same mechanism - an additional authority generated by the
new owner - and neither is needed yet.

## 7. Enrollment

Store and forward. The hub is a courier.

1. The connector generates a keypair on first start and persists it. The public
   key fingerprint is its identity for the lifetime of that volume.
2. The connector posts an enrollment request to `https://hub/enroll/<instance>`:
   public key, announced routes, environment hints, and, when a shared token is
   configured, an HMAC of the request under that token.
3. The hub verifies the shared token if one is configured, rate limits, and
   stores the request as pending. It allocates an overlay address from the
   instance's prefix and records it with the request.
4. The connector polls for its result. Until there is one it receives a backoff
   interval chosen by the hub.
5. The tenant daemon polls for pending requests, authenticated by its identity.
6. The decision is made locally, over the unix socket. The tenant signs a
   certificate carrying the allocated address and the approved routes, and posts
   it back to the hub.
7. The connector picks the certificate up, together with the CA certificate, the
   lighthouse overlay address, the lighthouse public endpoint, the hub's link
   MTU and whether the lighthouse relays. It then starts nebula and connects.

The shared token doubles as an integrity key. Without it the hub could swap the
public key in a pending request and have the tenant sign a certificate for an
attacker. With it, the tenant verifies the HMAC locally and the hub is reduced
to a courier. Without a token, the connector prints its own key fingerprint at
startup so it can be compared by hand.

Certificates travel through the hub in the clear. Tampering is pointless: the
hub cannot forge a signature, so the worst it can do is withhold.

Collecting the result of an enrollment is not authenticated either, so anyone
holding both identifiers can read the bundle. Everything in it is public by
nature - a certificate, the authority certificate, a lighthouse address - and
useless without the connector's private key. What leaks is metadata: that
somebody joined, which address they were given and which routes they carry.
This is accepted knowingly rather than overlooked; requiring the shared token
here would close it, at the cost of a token being mandatory to poll.

## 8. Decisions on a request

**approve** - sign and return a certificate.

**reject** - refuse. Not final. A connector that restarts submits again, which is
deliberate: a connector pointed at the wrong instance should be visible, not
silently gone.

**forget** - drop the record and stop showing this key. The connector may keep
trying; it stops appearing.

**ban** - add the certificate fingerprint to the nebula blocklist and reload.
Nebula implements this natively (`cert.CAPool.BlocklistFingerprint`,
`pki.blocklist`); robinet only writes the list. The member stays, holding its
name and its address, and **unban** takes the fingerprint off again. Each
decision is appended to the member's own list with the note explaining it, and
the current state is the last one: there is no separate flag to reconcile.

**remove** - forget the member entirely, and only after a ban. Its key and its
certificate are burned: the certificate stays on the blocklist with no record
left to carry it, and an enrollment from that key is refused by the hub. This is
what frees the name and the address, and nothing takes either credential off the
burned list.

Removal has to follow a ban because a certificate cannot be revoked. A member
that is not banned holds a valid one for its address, so freeing that address
would hand the next applicant something already in use.

Reject, forget and ban are keyed on the applicant's public key. They hold only
as long as the connector keeps its key, so a connector without a persistent
volume returns as a new identity. The connector warns loudly at startup when its
state directory is not persistent. Removal is the exception: the burned key is
remembered by the instance, so returning under it is refused rather than shown
to the owner again.

## 9. Routes

The connector detects its own on-link prefixes and announces them.
`--announce-routes` adds explicit prefixes and `--disable-autodiscover` turns
detection off, so exactly what is announced can be chosen.

**A prefix may be held by one connector per instance.** A second connector
announcing a prefix that is already assigned cannot be approved. This is not an
error to work around, it is the shape of the problem: two Railway environments
both announce `10.128.0.0/9`, and one route table cannot hold both. Replacing a
connector is ban then remove on the old one, then approve the new one. The panel
shows whether the holder's tunnel is currently alive, since the tenant daemon
runs the lighthouse and has the hostmap.

**Sign once.** Routes are fixed in the certificate at approval and never
refreshed. When a provider changes its addressing, the operator purges the
connector's volume and enrolls again. An automatic refresh path would let a
stolen identity announce arbitrary routes without anyone looking.

At startup the connector compares detected routes against its certificate and
logs a loud warning on mismatch, then runs with what the certificate says.

**Multiple connectors per instance** are allowed when their prefixes are
disjoint. There is no support for two paths to the same prefix.

## 10. The route table

The table lives on the hub, because the hub is the only party that sees every
connector. A member reads it with its own identity and installs what it says.

This is what keeps certificates static. A certificate says who you are, once,
for years. What you can reach changes whenever a connector is admitted or
banned, and that change reaches every member at their next read, without
anybody reissuing anything and without a restart.

A member does not install a route pointing at itself: a connector reaches its
own network directly.

## 11. Addressing

The hub owns addressing. Its pool is written as a superprefix plus the size
handed to each instance, so `198.19.0.0/16/24` is a /16 carved into /24s. An
instance gets one of those slices and a UDP port; inside the slice the first
address is the lighthouse, the second the tenant, and connectors follow.

Allocation is sticky per fingerprint, so a connector that enrolls again keeps
its address. The hub allocates at enrollment time and carries the address in the
record; the tenant bakes it into the certificate. The hub therefore stays
authoritative over its own space without ever signing anything.

A tenant does not choose its own prefix. Two of them would eventually choose the
same one, and only the hub can see both.

## 12. Certificates

Lifetime is configurable on the tenant, ten years by default. The tenant CA is
generated with a longer lifetime, because nebula rejects every certificate under
an expired CA regardless of the certificate's own validity
(`cert/ca_pool.go`, `ErrRootExpired`).

The connector generates its own keypair and sends only the public key. Signing
uses majak's `internal/nebca`, which takes a client supplied public key PEM and
has no dependency on any server state.

The tenant signs three things: its own node certificate, the lighthouse
certificate it uploads to the hub, and each approved connector.

## 13. Connector runtime

Built on nebula's user space device with a gvisor network stack.

- **Gateway.** TCP and UDP arriving from the mesh for an address other than the
  connector's own overlay address are terminated in the stack and redialed on
  the host network. ICMP is not forwarded. Ping is not a reachability test:
  promiscuous mode makes the stack answer echo requests for every address in the
  forwarded range.
- **DNS.** Queries to port 53 on the connector's overlay address are forwarded,
  over UDP and TCP, to the resolver the container itself uses. On Railway this
  is an IPv6 resolver and it works, because the upstream is dialed on the host
  stack rather than through the overlay.
- **MTU.** Configurable, and it matters: Railway's `railnet0` has an MTU of 1316
  and nebula adds about sixty bytes, so the default of 1280 fragments.
- **State.** Identity and certificate live on a persistent volume.
- **Inputs.** Hub URL, optional shared token, optional announced routes,
  optional autodiscovery switch, MTU.

Source addresses are rewritten: connections are terminated in the stack and
redialed, so the destination sees the connector's address, not the client's
overlay address.

## 14. Tenant runtime

`sudo robinet setup` installs the service, creates the socket as `root:<group>`
with mode 0660 and adds the invoking user to that group. Afterwards the user
runs `robinet ...` without sudo and reaches the daemon over the socket.

`SUDO_UID` is not used to locate anything. It is zero when root invokes sudo,
absent under systemd, and is an ordinary environment variable. Ownership is
recorded in configuration at setup time.

The daemon holds the CA, the tenant node certificate and key, the client
registry and the blocklist, runs nebula with a real tun, installs unsafe routes
for approved connectors and reloads on change.

The panel is local: CLI over the socket, optionally a page bound to loopback.
There is no remote UI, no HTTP auth and no exposed bind address.

## 15. Hub runtime

Configuration declares binders and their authorized SSH keys, the per tenant
address pools, the UDP port range (for example 20000 to 24999), the API address
and the nebula bind address.

For each tenant the hub runs a nebula lighthouse process on its own port, using
a certificate signed by that tenant. The supervisor pattern is DLG's link: one
process per instance directory, restarted with capped backoff, logs prefixed per
instance.

Demultiplexing is by port. The nebula header carries no identifier that a
middlebox could use - version, type, subtype, reserved, remote index and counter
- and a process presents one certificate, so one process cannot serve several
certificate authorities.

State is SQLite: tenants, ports, pools, allocations, enrollment records, issued
fingerprints.

## 16. Out of scope for the first version

- `--install-dns`, which would write a `systemd-networkd` split DNS file
  pointing a domain at a connector's overlay address. It belongs to instance
  lifecycle management and lands later.
- DNS suffix rewriting, which would let compose networks, where no search domain
  exists, be addressed as `app.something.lan`.
- Hints from external sources such as whois or geo databases. Local hints only:
  environment variables, hostname, source address, instance URL.
- A remote panel.
- High availability, meaning several paths to the same prefix.
- Certificate renewal. Certificates are long lived and reissued by re-enrolling.

## 17. Open questions

- Whether the tenant is also offered as a container with `NET_ADMIN` and its own
  tun. That is what makes two instances carrying the same prefix usable on one
  machine, since separate network namespaces mean separate route tables.
- Transferring ownership of an instance, and several owners of one. Both are
  the same mechanism, an additional authority generated by the new owner.
- Whether a joined tenant may be granted the right to admit others. Today it
  cannot, because only the authority holder can sign, and that is a property
  worth keeping unless something forces the issue.

## 18. What this is built on

Nebula, as a library dependency: `nebula.Main` with an injected device factory,
`cert.TBSCertificate.Sign`, `cert.CAPool` with the blocklist, and `config.C`.
No fork, no patches, no vendored copy.

The lighthouses run inside the hub process with the tun disabled, so there is no
external nebula binary to supervise and no capability to grant.

WRAK, as a protocol. DLG implements the same one; robinet does not borrow its
code.
