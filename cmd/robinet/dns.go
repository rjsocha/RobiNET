package main

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/spf13/cobra"
)

// newDNSCmd groups what can be done to this machine's resolver. It does
// nothing by itself: reading is one thing and changing how every name here
// resolves is another, and they should not be the same word.
func newDNSCmd() *cobra.Command {
	var (
		socket string
		mode   string
	)

	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Resolve the names each connector answers for",
		Long: `dns tells this machine's resolver which connector to ask about which
names.

A connector announces the domains it can resolve, the owner of the instance
approves them, and the hub carries them beside the routes. The daemon answers
under a name space of its own built from the connector's name and the
instance's, so two networks calling themselves the same thing stay apart.

install writes one file per device under /etc/systemd/network and applies it
now, so it survives a restart. It elevates itself: changing a resolver needs
root, and the daemon holds one capability and nothing else.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		newDNSListCmd(&socket, &mode),
		newDNSInstallCmd(&socket, &mode, false),
		newDNSInstallCmd(&socket, &mode, true),
		newDNSAliasCmd(&socket),
	)

	addSocketFlag(cmd, &socket)

	return cmd
}

// newDNSListCmd shows what would be installed, and needs nothing: reading is
// not root's business.
func newDNSListCmd(socket, mode *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show what this machine's resolver would be told",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := dnsPlan(cmd, *socket, *mode, false)
			if err != nil {
				return err
			}

			if err := printDNSPlan(entries); err != nil {
				return err
			}

			// Said here rather than refused here: listing is reading, and a
			// machine without systemd-resolved can still want to know what it
			// would be missing.
			if err := tenant.CheckResolver(cmd.Context()); err != nil {
				fmt.Printf("\n  warning: %v\n", err)
				fmt.Printf("  robinet dns install would fail on this machine\n")
			}

			return nil
		},
	}

	return cmd
}

// addModeFlag belongs to install and to nothing else. Listing shows what is
// carried, which is the same however a resolver is told; removing takes away
// whatever was written, without being told what wrote it; and an alias is kept
// here and told to nobody at all.
func addModeFlag(cmd *cobra.Command, mode *string) {
	cmd.Flags().StringVar(mode, "mode", tenant.ModeSystemd,
		"how to tell this machine's resolver: "+strings.Join(tenant.ModeNames(), ", "))
}

func newDNSInstallCmd(socket, mode *string, remove bool) *cobra.Command {
	use, short := "install", "Point this machine's resolver at those names"
	if remove {
		use, short = "remove", "Take the resolver configuration off again"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Changing a resolver is root's: systemd-resolved asks polkit
			// rather than looking at capabilities, and a machine without
			// polkit refuses everybody but root.
			if os.Geteuid() != 0 {
				return elevate()
			}

			entries, err := dnsPlan(cmd, *socket, *mode, remove)
			if err != nil {
				return err
			}

			if err := tenant.Apply(cmd.Context(), *mode, entries); err != nil {
				return err
			}

			if remove {
				fmt.Println("resolver configuration removed")
				return nil
			}

			return printDNSPlan(entries)
		},
	}

	if !remove {
		addModeFlag(cmd, mode)
	}

	return cmd
}

// dnsPlan asks the daemon what should be configured. It decides; applying it
// is the caller's, because it needs root and the daemon does not have it.
func dnsPlan(cmd *cobra.Command, socket, mode string, remove bool) ([]tenant.DNSEntry, error) {
	path, err := socketPath(socket)
	if err != nil {
		return nil, err
	}

	var entries []tenant.DNSEntry
	req := tenant.DNSRequest{Mode: mode, Remove: remove}
	if err := newControl(path).do(cmd.Context(), http.MethodPost, "/dns", req, &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

func printDNSPlan(entries []tenant.DNSEntry) error {
	var carrying []tenant.DNSEntry
	for _, e := range entries {
		if len(e.Domains) > 0 {
			carrying = append(carrying, e)
		}
	}

	if len(carrying) == 0 {
		fmt.Println("nothing to resolve: no connector this machine can see announces a domain")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "INSTANCE\tDEVICE\tDOMAINS\tASKING")
	for _, e := range carrying {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.Instance, e.Device, strings.Join(e.Domains, ","), strings.Join(e.Servers, ","))
	}

	return w.Flush()
}

// newDNSAliasCmd gives a name space a shorter name on this machine.
//
// Local and told to nobody: the canonical name keeps working, the hub is not
// asked, and nothing about who carries what changes. It exists because the
// name a connector ends up with describes where it runs rather than what it is
// to you.
func newDNSAliasCmd(socket *string) *cobra.Command {
	var remove bool

	cmd := &cobra.Command{
		Use:   "alias [<name> <as>]",
		Short: "Answer for a name space under another name here",
		Long: `alias gives a name space a second name on this machine.

  robinet dns alias production.acme.dom.robinet acme.vpn   add one
  robinet dns alias --remove acme.vpn                      take it away
  robinet dns alias                                        list them

--remove takes the alias rather than the name it stood for.

Run robinet dns install after either: the resolver has to be told about the
names as well.`,
		Args: cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(*socket)
			if err != nil {
				return err
			}

			req := tenant.AliasRequest{}
			switch {
			case remove:
				if len(args) != 1 {
					return fmt.Errorf("--remove takes the alias, and nothing else")
				}
				req.Alias = args[0]
			case len(args) == 0:
				// Nothing to say means nothing is changed, and what comes
				// back is the listing.
			case len(args) != 2:
				return fmt.Errorf("alias takes the name and what to call it here")
			default:
				req.Canonical, req.Alias = args[0], args[1]
			}

			var aliases map[string]string
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/alias", req, &aliases); err != nil {
				return err
			}

			if len(aliases) == 0 {
				fmt.Println("no aliases")
				return nil
			}

			names := make([]string, 0, len(aliases))
			for alias := range aliases {
				names = append(names, alias)
			}
			sort.Strings(names)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ALIAS\tSTANDS FOR")
			for _, alias := range names {
				fmt.Fprintf(w, "%s\t%s\n", alias, aliases[alias])
			}
			w.Flush()

			if len(args) == 0 && !remove {
				fmt.Println("\n  robinet dns alias --remove <alias>   to take one away")
				return nil
			}

			fmt.Println("\n  robinet dns install   to resolve it here")
			return nil
		},
	}

	cmd.Flags().BoolVar(&remove, "remove", false, "take an alias away")

	return cmd
}
