# robinet

Reach a private network you have no route to - a Railway environment, a docker
compose network, a subnet behind somebody else's NAT.

This build already knows which hub to talk to. Two commands:

```
robinet join      # once: your ssh key registers this machine, and starts
                  # the daemon, which is what asks for your password
robinet status    # where you stand
```

Then ask whoever runs the network you need for its name:

```
robinet instance attach <name>
```

Their screen shows your name, because the hub vouched for the ssh key you
signed with. Once they approve, the tunnel comes up on its own and the
addresses inside that network work directly.

To expose a network of your own:

```
robinet instance create --name <something>
```

It prints how to run a connector inside the network you want to reach.

After an upgrade, restart the daemon: it keeps running the binary it started
with, so a new one changes nothing until then. Every command refuses to talk to
a daemon from a different build, and says this.

```
robinet restart
```

Every command explains itself: `robinet <command> --help`.
