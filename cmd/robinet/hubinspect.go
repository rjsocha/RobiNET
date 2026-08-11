package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"github.com/spf13/cobra"
)

// The hub knows things nobody else can see: which instances exist, what
// address space each one took, who was admitted and who is still asking.
// Everything here reads its state file and changes nothing - decisions belong
// to the owner of an instance, on their own machine, and a hub that could make
// them would be a hub worth taking.
func newHubListCmd(configPath *string, configDirs *[]string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the instances on this hub",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openHubState(*configPath, *configDirs)
			if err != nil {
				return err
			}

			instances := store.List()
			if len(instances) == 0 {
				fmt.Println("no instances")
				return nil
			}

			sort.Slice(instances, func(i, j int) bool { return instances[i].Name < instances[j].Name })

			// The second column only when something has one: a hub with no
			// IPv6 pool would otherwise print a column of dashes, and one
			// with a pool would leave somebody wondering whether an instance
			// got an address or the listing just does not say.
			dual := false
			for _, inst := range instances {
				dual = dual || inst.Overlay6.IsValid()
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if dual {
				fmt.Fprintln(w, "NAME\tID\tBINDER\tOVERLAY\tOVERLAY6\tPORT\tMEMBERS\tPENDING\tCREATED")
			} else {
				fmt.Fprintln(w, "NAME\tID\tBINDER\tOVERLAY\tPORT\tMEMBERS\tPENDING\tCREATED")
			}

			for _, inst := range instances {
				if dual {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
						inst.Name, inst.ID, inst.Binder, inst.Overlay, prefixOrDash(inst.Overlay6),
						inst.Port, inst.MemberCount(), pendingOrDash(pendingIn(inst)),
						inst.CreatedAt.Local().Format("2006-01-02"))
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
					inst.Name, inst.ID, inst.Binder, inst.Overlay,
					inst.Port, inst.MemberCount(), pendingOrDash(pendingIn(inst)),
					inst.CreatedAt.Local().Format("2006-01-02"))
			}
			w.Flush()

			return nil
		},
	}
}

func newHubShowCmd(configPath *string, configDirs *[]string) *cobra.Command {
	return &cobra.Command{
		Use:   "show <instance>",
		Short: "Show one instance: its addressing, its members and what is waiting",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openHubState(*configPath, *configDirs)
			if err != nil {
				return err
			}

			inst, err := store.Resolve(args[0])
			if err != nil {
				return fmt.Errorf("no instance %s", args[0])
			}

			fmt.Printf("name        %s\n", inst.Name)
			fmt.Printf("id          %s\n", inst.ID)
			fmt.Printf("binder      %s\n", inst.Binder)
			fmt.Printf("overlay     %s\n", inst.Overlay)
			if inst.Overlay6.IsValid() {
				fmt.Printf("            %s\n", inst.Overlay6)
			} else {
				fmt.Printf("            ipv4 only, and no certificate under it can ever carry an ipv6 route\n")
			}
			fmt.Printf("port        %d\n", inst.Port)
			fmt.Printf("lighthouse  %s\n", addrOrDash(netip.PrefixFrom(inst.LighthouseAddress, inst.Overlay.Bits())))
			fmt.Printf("relay       %v\n", inst.Relay)
			fmt.Printf("created     %s\n", inst.CreatedAt.Local().Format(time.RFC3339))

			if len(inst.Members) > 0 {
				fmt.Println("\nmembers")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  KIND\tNAME\tADDRESS\tADDRESS6\tROUTES\tDOMAIN\tSTATE\tJOINED")
				for _, m := range sortedMembers(inst) {
					state := "ok"
					if m.Banned() {
						state = "banned"
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						m.Kind, dashIfEmpty(m.Name), addrOrDash(m.Address), prefixOrDash(m.Address6),
						prefixes(m.Routes), dashIfEmpty(m.Domain),
						state, m.JoinedAt.Local().Format("2006-01-02 15:04"))
				}
				w.Flush()
			}

			waiting := pendingIn(inst)
			if waiting > 0 {
				fmt.Println("\nwaiting for a decision")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  ID\tKIND\tNAME\tADDRESS\tROUTES\tFROM\tASKED")
				for _, r := range inst.Requests {
					if r.Status != enroll.StatusPending {
						continue
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						short(r.ID, 8), r.Kind, applicantName(r.Request), r.OverlayAddress,
						prefixes(r.Request.Routes), r.SourceAddr,
						r.ReceivedAt.Local().Format("2006-01-02 15:04"))
				}
				w.Flush()

				// Said plainly, because somebody reading this on the hub is
				// the person most likely to want to act on it and least able
				// to: the authority is not here.
				fmt.Printf("\n  only %s can admit these, on the machine holding the authority\n", inst.Binder)
			}

			return nil
		},
	}
}

func newHubMachinesCmd(configPath *string, configDirs *[]string) *cobra.Command {
	return &cobra.Command{
		Use:   "machines",
		Short: "List the machines registered with this hub",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openHubState(*configPath, *configDirs)
			if err != nil {
				return err
			}

			machines := store.Registrations()
			if len(machines) == 0 {
				fmt.Println("no machines registered")
				return nil
			}

			sort.Slice(machines, func(i, j int) bool {
				if machines[i].Binder != machines[j].Binder {
					return machines[i].Binder < machines[j].Binder
				}
				return machines[i].Name < machines[j].Name
			})

			// Where each one ended up, because a registration on its own says
			// only that somebody vouched for a machine - not what it can
			// reach, which is the next thing anybody wants to know.
			membership := map[string][]string{}
			for _, inst := range store.List() {
				for _, m := range inst.Members {
					if m.Identity == "" {
						continue
					}
					where := fmt.Sprintf("%s %s", inst.Name, m.Address.Addr())
					if m.Address6.IsValid() {
						where += " " + m.Address6.Addr().String()
					}
					membership[m.Identity] = append(membership[m.Identity], where)
				}
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "BINDER\tMACHINE\tIDENTITY\tLAST SEEN\tMEMBER OF")
			for _, m := range machines {
				seen := "-"
				if !m.LastSeenAt.IsZero() {
					seen = m.LastSeenAt.Local().Format("2006-01-02 15:04")
				}

				in := membership[m.Identity]
				sort.Strings(in)

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					m.Binder, dashIfEmpty(m.Name), short(m.Identity, 16),
					seen, dashIfEmpty(strings.Join(in, ", ")))
			}
			w.Flush()

			// Said once, because it is the question this listing raises: a
			// connector has no identity here. It is admitted by its key alone
			// and belongs to one instance, so it appears in hub members.
			fmt.Println("\n  connectors are not registered machines and are not listed here: robinet hub members")

			return nil
		},
	}
}

// newHubMembersCmd is every member of every instance, which is the only view
// that shows connectors: they have no identity of their own and are admitted
// by their key alone.
func newHubMembersCmd(configPath *string, configDirs *[]string) *cobra.Command {
	var kind string

	cmd := &cobra.Command{
		Use:   "members",
		Short: "List every member of every instance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openHubState(*configPath, *configDirs)
			if err != nil {
				return err
			}

			instances := store.List()
			sort.Slice(instances, func(i, j int) bool { return instances[i].Name < instances[j].Name })

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "INSTANCE\tKIND\tNAME\tADDRESS\tADDRESS6\tROUTES\tDOMAIN\tSTATE")

			rows := 0
			for _, inst := range instances {
				for _, m := range sortedMembers(inst) {
					if kind != "" && m.Kind != kind {
						continue
					}

					state := "ok"
					if m.Banned() {
						state = "banned"
					}

					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						inst.Name, m.Kind, dashIfEmpty(m.Name),
						addrOrDash(m.Address), prefixOrDash(m.Address6),
						prefixes(m.Routes), dashIfEmpty(m.Domain), state)
					rows++
				}
			}

			if rows == 0 {
				fmt.Println("no members")
				return nil
			}

			w.Flush()
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "only connector, tenant or owner")

	return cmd
}

// openHubState reads the state file the configuration points at.
func openHubState(configPath string, configDirs []string) (*hub.Store, error) {
	file, err := hub.LoadFile(configPath, configDirs...)
	if err != nil && !errors.Is(err, hub.ErrNoBinders) {
		return nil, err
	}

	// Reading the state does not need a binder to be configured: who may
	// create an instance is a different question from what exists.
	return hub.OpenStore(file.State.Path)
}

func pendingIn(inst *hub.Instance) int {
	n := 0
	for _, r := range inst.Requests {
		if r.Status == enroll.StatusPending {
			n++
		}
	}
	return n
}

func sortedMembers(inst *hub.Instance) []*hub.Member {
	out := make([]*hub.Member, 0, len(inst.Members))
	for _, m := range inst.Members {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Addr().Less(out[j].Address.Addr()) })
	return out
}

// prefixOrDash is addrOrDash for a prefix that may not be there at all.
func prefixOrDash(p netip.Prefix) string {
	if !p.IsValid() {
		return "-"
	}
	return p.String()
}
