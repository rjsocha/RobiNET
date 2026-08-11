package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/rjsocha/robinet/internal/variant"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// statePath resolves the state file, defaulting to the owner's own directory.
// The daemon belongs to one person, so its secrets live with that person
// rather than in a machine wide directory.
func statePath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return tenant.DefaultStatePath()
}

func socketPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return tenant.DefaultSocketPath()
}

func newJoinCmd() *cobra.Command {
	var (
		hubURL    string
		token     string
		name      string
		sshKey    string
		sshFinger string
		state     string
		insecure  bool
		hubPin    string
		logLevel  string
		noSetup   bool
		socket    string
	)

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Register this machine with a hub",
		Long: `join introduces this machine to a hub, once.

Your ssh-agent signs a bootstrap message carrying a token both sides already
know, so the token never travels and the hub learns which of its binders you
are from the key that signed. Afterwards this machine has an identity of its
own and signs every call with it, so the agent is never needed again.

It then starts the daemon, since everything else needs one and there is nothing
else to do first. That part asks for a password. --no-setup leaves it, and
robinet setup does it later.

Registering grants nothing by itself. Which instance you may enter is decided
by whoever owns it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// A variant build already knows its hub, so the flags only have to
			// be given when there is nothing baked in or it is being overridden.
			if preset, ok := variant.Load(); ok {
				if hubURL == "" {
					hubURL = preset.Hub
				}
				if token == "" {
					token = preset.Token
				}
				if !cmd.Flags().Changed("insecure") && preset.Insecure {
					insecure = true
				}
				if hubPin == "" {
					hubPin = preset.Pin
				}
			}

			if hubURL == "" || token == "" {
				return fmt.Errorf("--hub and --token are required (this build has no hub baked in)")
			}

			path, err := statePath(state)
			if err != nil {
				return err
			}

			st, err := tenant.OpenState(path)
			if err != nil {
				return err
			}

			if name == "" {
				name = tenant.DefaultNameMarker
				if !st.Registered() {
					name = defaultMachineName()
				}
			}

			joined, err := tenant.Join(cmd.Context(), st, tenant.JoinOptions{
				HubURL:         hubURL,
				Token:          token,
				Name:           name,
				SSHKeyPath:     sshKey,
				SSHFingerprint: sshFinger,
				Insecure:       insecure,
				Pin:            hubPin,
			}, newLogger(logLevel))
			if err != nil {
				return err
			}

			what := "registered with"
			if joined.Refreshed {
				what = "registration refreshed with"
			}
			fmt.Printf("%s %s, as %s\n", what, hubHost(joined.Hub), joined.Name)

			// Only now: a note printed next to a failure reads as if the
			// failure did not happen.
			if preset, ok := variant.Load(); ok && preset.Note != "" {
				fmt.Printf("\n%s\n", preset.Note)
			}

			// There is exactly one thing to do next and everything else needs
			// it, so it is done rather than described. Skipped when the daemon
			// is already there, which is what registering again looks like.
			if noSetup || daemonReachable(cmd, socket) {
				printAfterJoin()
				return nil
			}

			fmt.Printf("\nstarting the daemon, which runs as a service: this is what asks for your password\n")

			if err := runSetup(cmd.Context()); err != nil {
				return err
			}

			printAfterJoin()

			return nil
		},
	}

	f := cmd.Flags()
	addSocketFlag(cmd, &socket)
	f.BoolVar(&noSetup, "no-setup", false, "register only, and leave the daemon for robinet setup")
	f.StringVar(&hubURL, "hub", "", "hub base url, for example https://hub.example:8443")
	f.StringVar(&token, "token", "", "the hub's registry token, for registering this machine")
	f.StringVar(&name, "name", "", "what to call this machine (default: user@host, or the name already registered)")
	f.StringVar(&sshKey, "ssh-key", "", "sign with this private key file instead of the agent")
	f.StringVar(&sshFinger, "ssh-fingerprint", "", "pick one key out of the agent, as SHA256:...")
	f.StringVar(&state, "state", "", "state file (default is under your home)")
	f.BoolVar(&insecure, "insecure", false, "skip verification of the hub's TLS certificate")
	f.StringVar(&hubPin, "pin", "", "verify the hub against this public key hash instead, as sha256/BASE64")
	f.StringVar(&logLevel, "log", "info", "log level")

	return cmd
}

func newCreateCmd() *cobra.Command {
	var (
		name   string
		shared string
		socket string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an instance owned by this machine",
		Long: `create asks the hub for an instance, generates its certificate authority
here, and signs the hub's lighthouse with it.

The authority key never leaves this machine, which is what makes you the only
one who can admit anybody to it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var out map[string]any
			err = newControl(path).do(cmd.Context(), "POST", "/create",
				map[string]string{"name": name, "shared_token": shared}, &out)
			if err != nil {
				return err
			}

			fmt.Printf("instance %s created\n", name)
			if id, ok := out["id"].(string); ok {
				fmt.Printf("  id       %s\n", id)
			}
			if overlay, ok := out["overlay"].(string); ok {
				fmt.Printf("  overlay  %s\n", overlay)
			}
			if overlay6, ok := out["overlay6"].(string); ok {
				fmt.Printf("           %s\n", overlay6)
			} else {
				// Worth saying: without one, nothing admitted to this instance
				// can ever carry an IPv6 route, and that cannot be changed
				// afterwards.
				fmt.Printf("           ipv4 only, because the hub has no ipv6 pool\n")
			}

			endpoint, _ := out["endpoint"].(string)
			if endpoint == "" {
				return nil
			}

			printConnectorHint(endpoint)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", "instance name")
	f.StringVar(&shared, "shared-token", "", "token connectors sign their enrollment with (generated when empty)")
	addSocketFlag(cmd, &socket)
	cmd.MarkFlagRequired("name")

	return cmd
}

// runSetup starts the daemon, elevating the way setup does when run on its
// own. A child rather than an exec, so what join has already said stays on the
// screen and its own exit status is the one that counts.
func runSetup(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	name, args := exe, []string{"setup"}
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("registered, but starting the daemon needs root and sudo is not installed: run robinet setup as root")
		}
		name, args = sudo, append([]string{"--", exe}, args...)
	}

	run := exec.CommandContext(ctx, name, args...)
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr

	return run.Run()
}

// printAfterJoin is the first thing somebody sees after registering, and being
// registered decides nothing: a machine on its own reaches nothing at all.
//
// Both ways on are worth saying, because which one applies is not something
// this program can know. Somebody handed a hub by a colleague is looking for a
// network that already exists; somebody who set the hub up is looking to make
// one.
func printAfterJoin() {
	fmt.Print(`
this machine belongs to no network yet. two ways on:

  robinet instance create --name <name>   start a network. connectors and other
                                          machines join it only if you approve

  robinet instance list                   networks that already exist here, then
                                          robinet instance attach <name> and its
                                          owner decides whether to let you in

  robinet status                          where this machine stands, at any time
`)
}

// hubHost is the hub as somebody would say it out loud, without the scheme
// they never typed in the first place.
func hubHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// daemonReachable says whether there is something to talk to, without
// bothering the caller about why not.
func daemonReachable(cmd *cobra.Command, socket string) bool {
	path, err := socketPath(socket)
	if err != nil {
		return false
	}

	c := newControl(path)
	c.anyVersion = true

	var status tenant.Status
	return c.do(cmd.Context(), http.MethodGet, "/status", nil, &status) == nil
}

// printConnectorHint says how to point a connector at an instance. One
// variable, because this is usually typed into a platform's environment by
// hand and three fields are three chances to get it wrong.
func printConnectorHint(endpoint string) {
	fmt.Printf("\nrun a connector inside the network you want to reach:\n\n")
	fmt.Printf("  docker run -d --name robinet -v robinet:/data \\\n")
	fmt.Printf("    -e ROBINET_ENDPOINT=%s \\\n", endpoint)
	fmt.Printf("    %s\n", connectorImage)
	fmt.Printf("\nor on a platform that only takes environment variables:\n\n")
	fmt.Printf("  image             %s\n", connectorImage)
	fmt.Printf("  ROBINET_ENDPOINT  %s\n", endpoint)
	fmt.Printf("  volume            /data   (its identity: without it every restart is a stranger)\n")
	fmt.Printf("\nthen approve it: robinet member pending\n")
}

// connectorImage is where the connector is published.
const connectorImage = "wyga/robinet:1"

func newUpCmd() *cobra.Command {
	var (
		state    string
		socket   string
		interval time.Duration
		logLevel string
	)

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Run the tenant daemon",
		Long: `up brings up every connection this machine has and serves the control
socket.

It needs CAP_NET_ADMIN for the tun devices and the routes, and nothing else.
Run it under sudo, or let robinet setup install a unit that grants just that
capability, in which case the daemon runs as you and never as root.

Routes come from the hub, so a connector admitted a minute ago becomes
reachable here without anybody reissuing a certificate.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := tenant.CheckNetAdmin(); err != nil {
				return err
			}

			statePath, err := statePath(state)
			if err != nil {
				return err
			}
			sockPath, err := socketPath(socket)
			if err != nil {
				return err
			}

			log := newLogger(logLevel)

			st, err := tenant.OpenState(statePath)
			if err != nil {
				return err
			}

			d, err := tenant.NewDaemon(st, log)
			if err != nil {
				return err
			}
			defer d.Stop()

			log.Info("tenant daemon ready", "socket", sockPath, "state", statePath)

			eg, ctx := errgroup.WithContext(ctx)
			eg.Go(func() error { return d.Serve(ctx, sockPath) })
			eg.Go(func() error {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()

				for {
					d.Refresh(ctx)

					select {
					case <-ctx.Done():
						return nil
					case <-ticker.C:
					}
				}
			})

			// A requested restart is a clean exit and says so. The unit is
			// Restart=always, and systemd tells a process that ended by
			// itself from one it was told to stop, so nothing has to be
			// dressed up as a failure to come back.
			return eg.Wait()
		},
	}

	f := cmd.Flags()
	f.StringVar(&state, "state", "", "state file (default is under the invoking user's home)")
	f.StringVar(&socket, "socket", "", "control socket")
	f.DurationVar(&interval, "refresh", 15*time.Second, "how often to read the route table from the hub")
	f.StringVar(&logLevel, "log", "info", "log level")

	return cmd
}
