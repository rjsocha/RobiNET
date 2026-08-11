# Ideas

Decided, described, not built. Roughly in the order they would be worth doing.
Sections marked **open** are the exception: they describe a problem whose answer
has not been settled.

## Two connectors carrying the same prefix - open

Nothing refuses it. The collision check compares one instance against another
(`internal/tenant/tenant.go`, when a connection starts) and never looks inside
a single instance, so two connectors admitted to the same instance both end up
in the route table with the same prefix and different `via`.

Nebula inserts routes into a prefix tree, so the second insert of a prefix
replaces the first: one carrier wins. Which one is not stable - `routesOf`
sorts by prefix and takes the rest of its order from iterating a map, so the
winner can change from one refresh to the next, silently. A second Railway
project reaches this immediately, since every one of them announces
`10.128.0.0/9`.

The shape of the answer is agreed. The request lands in `pending` like any
other, because a hub that auto-rejected would be a hub making decisions.
Approval is what refuses, naming the connector that already carries the prefix,
and the way out is `member approve --routes` with a set that does not collide:
the owner may want the second connector for something narrower, or with no
routes at all. The check has to run on what will actually be signed, after
`--routes` narrows it and after the unsignable families are dropped. A ban
takes the first connector's routes out of the table, so the second becomes
approvable with no extra mechanism.

What is open is whether refusing is right at all. Nebula's `via` takes several
gateways with weights, so two connectors carrying the same prefix could be an
answer rather than a mistake - the same network reachable through two
independent paths. That is a different feature with a different failure mode:
here the two prefixes are the same range in two unrelated projects, and sending
traffic to either one is wrong rather than redundant. Nothing distinguishes the
two cases today, and inventing a distinction before anybody needs the second one
would be guessing.

On Railway it no longer arises: a connector there announces its IPv6 prefix,
which is unique per environment, and drops the IPv4 range every project shares.
What is left is two connectors that genuinely claim the same network, which is
rarer and less accidental than the case this was written for.

## Running a connector on Railway - open

The connector needs its state directory to survive a restart: it holds the
keypair that is its identity, and without it every restart arrives as a new
applicant needing approval again. On Railway that means a volume, and how a
service is given one - whether the volume is a project level object attached to
a service, or something declared on the service itself - has not been checked.

Beyond that: whether a template can carry the whole thing, so adding robinet to
a project is one action rather than a service, a volume, a mount path and four
environment variables typed by hand. Railway has templates; what they can
declare, and whether one can be published privately, is unknown here.

## Names, what is left

A name is unique on a hub, resolves wherever an identifier does, and completes
in a shell. What is left is that uniqueness is first come first served: the
second person to want `railway` is refused and told who holds it, with nothing
to do about it but pick another word.

A `binder/name` form would let two people each have their own, with the short
form working while only one exists. Worth doing when a hub has enough people on
it for the refusal to be a nuisance, and not before: the qualified form is more
to type and more to explain.

## DNS, what is left

Announced, carried, rewritten and routed. What is not there:

**A domain of the instance's own.** `instance create --domain corp.internal`
instead of `<connector>.<instance>.robinet`, for somebody who owns a domain and
would rather use it. The name stays the identifier and the domain becomes a
property of the instance. Two instances claiming one domain collide the way two
connectors claiming a prefix do, and an owner choosing a domain that exists
publicly takes it over on every member's machine - which is legitimate to want
and terrible to discover, so it belongs in what `instance attach` prints.

**Records other than addresses.** A, AAAA and CNAME are rewritten and passed
on; everything else is dropped, so a query for a record that exists comes back
as NOERROR with nothing in it - which says "no such record" and is not true.
SRV is the first real gap: database clients and service discovery use it.

The authority and additional sections go the same way, so a negative answer
carries no SOA and nothing tells a resolver how long to remember it.

Doing this honestly means either understanding every type that is passed on, or
passing through untouched the ones with no names inside them - which requires
knowing which those are.

**The name spaces, kept rather than rebuilt.** `routerTableFor` runs in four
places - `Refresh`, `DNSPlan`, `Reach` and `SetAlias` - each on a route table
just fetched from the hub, and each throws its result away. What survives is
only what the router holds, which is that table with `withAliases` already
folded in. The set of name spaces a connector actually announced exists nowhere
in memory, so every question about it becomes a request to the hub, including
adding an alias, which asks only to check that the name it stands for exists.

The router should keep both: `base`, which is what the hub said, and the merged
table it answers from. `Refresh` replaces `base` and the merge follows, so a
connector admitted a minute ago still appears the way it does today. Setting an
alias becomes a merge over what is already held, which is also what makes it
take effect at once rather than at the next refresh. Applying aliases happens
in one place instead of at each call site.

Completing what an alias stands for falls out of that. `dns alias` takes a name
space nobody can be expected to type from memory - it is built from the
connector's name and the instance's, and the only way to see it is to run `dns
list` first - and with `base` held, a read only endpoint over the socket answers
from memory with no hub request behind a tab press. The alias itself under
`--remove` comes from the state file the same way. Both are the shape every
other completion here already has.

## A local panel

Approving from a terminal is fine for one person. `robinet status` plus
`member approve` is the whole flow, and it was deliberately kept to that.

A page bound to loopback would help when several requests arrive at once, and
would show what the fingerprints and hints actually say without a table wider
than a terminal. It stays local: the decision must not move to the hub, because
a hub that could record decisions becomes an authority that can be taken.

## Telling somebody their IPv6 is switched off

A machine with `net.ipv6.conf.all.disable_ipv6=1`, or a kernel booted with
`ipv6.disable=1`, cannot hold the IPv6 address its certificate carries. Nothing
can be done about that from here and nothing should be: it is the operator's
machine.

What can be done is saying so. `/proc/net/if_inet6` missing means the kernel
has no IPv6 at all, the `disable_ipv6` sysctls say the rest, and checking when
a connection comes up turns an obscure failure to configure a device into one
line naming the sysctl. `robinet family ipv4` is then the answer, and it should
be the line that says it.

## Seeing the configuration nebula was given

`renderConfig` hands its bytes straight to `config.C.LoadString` and nothing
keeps them. So when nebula fails on something it was told, the only way to know
what it was told is to reason about the renderer, which is how an afternoon
goes on a failure that reproduces once in two starts.

`robinet debug config <instance>` prints it. Whole, including `pki.key`: that
is the caller's own key, in the caller's own state file, over a socket that
belongs to them, and cutting it out would protect nobody.

The instance is an argument rather than an option, in both roles. A tenant runs
one nebula, one tun and one configuration per instance, and a hub runs one
lighthouse per instance, so neither has a single answer to give. The hub's
equivalent belongs next to its other subcommands.

It should serve what is running, not a fresh render. The runner already holds
the `*config.C` nebula loaded, and a re-render answers a different question:
what would be sent if the connection started now. When those two disagree, the
disagreement is the bug being looked for.

## Relay, tested

The hub runs its lighthouses with `am_relay` on, and nothing has ever exercised
it: every test so far punched through. A member behind symmetric NAT has no
other way in, so this is the difference between working and not working for
somebody, and nobody has checked it.

## Ownership

An instance is owned by an identity, which is one machine's key. A binder is
the person: they register every machine they use, and each registration gets an
identity of its own. So the same person arriving from a second machine is a
stranger to their own instance, has to ask to be let in, and is admitted by
themselves from the first one.

That is backwards. Ownership belongs to the binder; an identity is one place
they happen to be sitting. Left as it is for now, deliberately, because the
correction is not only a comparison in `ownerOnly`: admitting anybody is a
signature, and the authority for an instance exists on exactly one machine.

What it should become: a binder may hold more than one identity for the same
instance, each with an authority of its own, trusted alongside the first.
Nebula takes several certificate authorities in one pool, so the pieces exist.
That single change gives three things at once.

- **Several machines, one person.** A second machine of the same binder admits
  itself, because it holds an authority the instance already trusts.
- **A recovery path.** A binder who lost a machine, or wants to retire one,
  adds a fresh identity from somewhere else and then retires the old authority.
  Today a lost machine means a lost instance.
- **Transfer.** Handing an instance to somebody else is the same mechanism with
  a different binder: they generate an authority, it is trusted, the first is
  retired.

It reaches connectors too: a connector is admitted by a signature from one
authority, and a route table that survives the loss of that authority means
either re-signing what exists or trusting more than one from the start.

A smaller step that needs none of that: export the instance's certificate
authority - its certificate and its key. Only the CA travels. A member
certificate does not: it carries an address the hub handed to one key, and a
machine signing with the CA signs its own once the hub has given it one.

Where that CA key then goes is not this program's business. Once signing can go
through ssh-agent (below), a person who wants to admit members from a second
machine loads **the CA key** into their agent and does it, or forwards the
agent they already have. It is a key somebody owns, handled the way they handle
every other key they own - and building transport for it here would be
inventing a worse version of something they have.

It does not teach the hub that two machines are one person: the listing still
reads "yours, but its authority is on rjs". It ends the case where a machine is
shut out of its own instance with nothing to do about it but delete it.

Related: whether an admitted tenant can be granted the right to admit others.
Today it cannot, because only the authority holder can sign. That property is
worth keeping unless something forces the issue.

## The CA key, encrypted

An instance's signing key sits in this machine's state file in the clear. The
file is the user's and 0600, which is the same protection an ssh key gets by
default and no more: a backup, a stolen disk or anything running as that user
walks away with the power to admit members to every instance it owns.

Nebula's own cert package already does this - `EncryptAndMarshalSigningPrivateKey`
and `DecryptAndUnmarshalSigningPrivateKey`, Argon2 and AES-256-GCM - so the
format would be upstream's, readable by `nebula-cert`, and nothing has to be
invented.

What it costs is where the passphrase goes. Signing happens in the daemon, so
admitting a member stops being one command and becomes a prompt: either passed
in for each approval, or held in the daemon's memory after being unlocked once
and lost on restart. That is the design question, not the crypto. It should be
an option and not the only way: a machine that admits connectors unattended has
a reason to keep the key usable.

There is a better answer than a passphrase, and it fits what is already here.
`nebula-tool` signs a nebula certificate **through ssh-agent**: the CA key is
exported once as an OpenSSH key, loaded into the agent, and the signature is
asked for rather than computed, so the key is never read from disk again. The
daemon would hold the CA certificate and nothing else.

Two different keys end up in the same agent, and they must not be confused.
The **binder** is the person's own ssh key: it registers a machine with a hub
and proves who is speaking to it. The **CA key** is the instance's, generated
by this program when the instance was created, and it signs the certificates
that admit members. The agent is only a place to keep a key; what each key
authorises is unrelated, and neither can stand in for the other.

That said, the shape is the same as registration - a key held by the agent,
never read by this program - which makes it one habit instead of two. It also
composes with the encryption above rather than replacing it: encrypted at rest
protects the copy on disk before it is loaded, and the agent keeps it out of
the daemon afterwards. What it costs is that admitting anybody then needs an
agent holding the CA key, which is the point.

## Certificate renewal

Certificates are signed once, for ten years, and there is no renewal path. A
tenant whose certificate expires has to enroll again, and its authority expires
before that. Long enough not to matter yet, wrong enough to write down.

## The tenant as a container

The one thing that makes two instances carrying the same prefix usable on one
machine: a container per instance, with `NET_ADMIN` and its own tun, so each
gets its own route table. The connector already runs this way. The tenant does
not, and the collision is refused instead.

## A skill for the package

The manual is written for an agent. A hopper skill would put it where an agent
looks by default, the way `dlg` ships one. Same content, different envelope.

## Smaller things

- **Authenticating the enrollment poll.** Anyone holding both identifiers can
  read a bundle. Everything in it is public and useless without the connector's
  private key, so this was accepted knowingly. Requiring the shared token here
  would close it, at the cost of making a token mandatory.
- **Multi platform image.** `wyga/robinet:1` is amd64 only. The hopper package
  too.
- **Hints from outside.** whois, geo, BGP lookups on a connector's source
  address would help recognize a request. It sends a client's address to a third
  party, so it stays off unless asked for explicitly.
- **`robinet hub --setup` style symmetry.** The hub has `--init`, `--install`,
  `--test` and `--cleanup`. The tenant has `setup` and `setup --cleanup`. The
  two grew separately and read differently.
