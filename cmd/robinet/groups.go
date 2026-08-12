package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/spf13/cobra"
)

// The command surface follows the roles, which are the one thing about this
// tool that does not change:
//
//	hub, connect        other roles entirely
//	join, setup, status this machine
//	instance ...        this machine's relationship to a network
//	member ...          decisions about other machines in networks this one owns
func newInstanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "instance",
		Short: "Instances on this machine's hub",
		Long: `An instance is one network's mesh: its own authority, its own address space
and its own lighthouse. Create one to expose a network of your own, or attach
to one somebody else owns to reach theirs.`,
	}

	cmd.AddCommand(
		newListCmd(),
		newShowCmd(),
		newCreateCmd(),
		newAttachCmd(),
		newDeleteCmd(),
		newDetachCmd(),
		newInstanceTokenCmd(),
		newInstanceConfigCmd(),
	)

	return cmd
}

func newShowCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:               "show <id or name>",
		Short:             "Show an instance, and how to point a connector at it",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, true),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var info map[string]any
			err = newControl(path).do(cmd.Context(), http.MethodPost, "/show",
				tenant.ConnectRequest{Instance: args[0]}, &info)
			if err != nil {
				return err
			}

			fmt.Printf("instance %v\n", info["name"])
			fmt.Printf("  id       %v\n", info["id"])
			fmt.Printf("  overlay  %v\n", info["overlay"])
			fmt.Printf("  owner    %v\n", info["owner"])
			fmt.Printf("  role     %v\n", dashIfEmpty(fmt.Sprint(info["role"])))
			fmt.Printf("  up       %v\n", info["running"])

			endpoint, _ := info["endpoint"].(string)
			if endpoint == "" {
				fmt.Printf("\nask %v for the endpoint to give a connector\n", info["owner"])
				return nil
			}

			printConnectorHint(endpoint)
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

// newInstanceConfigCmd prints the nebula configuration one connection runs on,
// the same question `robinet hub config` answers on the other side.
func newInstanceConfigCmd() *cobra.Command {
	var (
		socket   string
		showKeys bool
	)

	cmd := &cobra.Command{
		Use:   "config <instance>",
		Short: "Print the nebula configuration a connection runs on",
		Long: `config prints what nebula was handed for one instance this machine is in: the
certificate it presents, the lighthouse it talks to, the routes on its device,
the blocklist it enforces.

What the running nebula was loaded from, not a fresh guess at it. When nothing
is running for that instance - it is still waiting to be approved, or its start
was refused - what would be handed over is rendered instead, and the first line
says so.

This machine's signing key is left out unless --show-keys asks. Everything else
is public by nature or already known to every member of that instance.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, true),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var out tenant.ConfigResult
			err = newControl(path).do(cmd.Context(), http.MethodPost, "/config",
				tenant.ConfigRequest{Instance: args[0], ShowKeys: showKeys}, &out)
			if err != nil {
				return err
			}

			fmt.Print(out.Config)
			return nil
		},
	}

	cmd.Flags().BoolVar(&showKeys, "show-keys", false, "print this machine's signing key too")
	addSocketFlag(cmd, &socket)

	return cmd
}

func newMemberCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "member",
		Short: "Who is in the instances this machine owns",
		Long: `Members are the connectors and people admitted to an instance.

Only the owner of an instance can admit anybody, because only the owner holds
its certificate authority. That is not a rule being enforced; it is where the
signing key lives.`,
	}

	cmd.AddCommand(
		newPendingCmd(),
		newApproveCmd(),
		newDecisionCmd("reject", "Refuse a pending applicant"),
		newDecisionCmd("forget", "Stop showing a request"),
		newBanCmd(),
		newUnbanCmd(),
		newRemoveMemberCmd(),
		newMemberListCmd(),
	)

	return cmd
}

func newPendingCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List what is waiting for a decision",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var pending []tenant.PendingEntry
			if err := newControl(path).do(cmd.Context(), http.MethodGet, "/pending", nil, &pending); err != nil {
				return err
			}

			if len(pending) == 0 {
				fmt.Println("nothing waiting")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tINSTANCE\tKIND\tWILL BE CALLED\tADDRESS")
			for _, p := range pending {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					short(p.Record.ID, 8), p.Instance, p.Record.Kind, willBeCalled(p), p.Address)
			}
			w.Flush()

			for _, p := range pending {
				describe(p)
			}

			fmt.Println("\n  robinet member approve <id>")
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

func newMemberListCmd() *cobra.Command {
	var (
		socket   string
		instance string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List who is already inside",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var members []tenant.MemberEntry
			if err := newControl(path).do(cmd.Context(), http.MethodGet, "/members", nil, &members); err != nil {
				return err
			}

			if instance != "" {
				var kept []tenant.MemberEntry
				for _, m := range members {
					if strings.EqualFold(m.Instance, instance) {
						kept = append(kept, m)
					}
				}
				if len(kept) == 0 && len(members) > 0 {
					return fmt.Errorf("no instance called %s here: robinet instance list", instance)
				}
				members = kept
			}

			if len(members) == 0 {
				fmt.Println("no members yet")
				return nil
			}

			// The second address column only when something has one, the same
			// as everywhere else it appears.
			dual := false
			for _, m := range members {
				dual = dual || m.Member.Address6.IsValid()
			}

			// The instance column says nothing once it holds one value, which
			// is exactly what --instance makes it hold.
			where := func(m tenant.MemberEntry) string { return m.Instance + "\t" }
			header := "INSTANCE\t"
			if instance != "" {
				where = func(tenant.MemberEntry) string { return "" }
				header = ""
				fmt.Printf("members of %s\n\n", members[0].Instance)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if dual {
				fmt.Fprintln(w, header+"KIND\tNAME\tBINDER\tADDRESS\tADDRESS6\tROUTES\tDOMAIN\tSTATE")
			} else {
				fmt.Fprintln(w, header+"KIND\tNAME\tBINDER\tADDRESS\tROUTES\tDOMAIN\tSTATE")
			}

			for _, m := range members {
				state := "ok"
				if m.Member.Banned() {
					state = "banned"
				}

				if dual {
					fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						where(m), m.Member.Kind, dashIfEmpty(m.Member.Name), dashIfEmpty(m.Member.Binder),
						addrOrDash(m.Member.Address), addrOrDash(m.Member.Address6),
						prefixes(m.Member.Routes),
						dashIfEmpty(m.Member.Domain), state)
					continue
				}

				fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					where(m), m.Member.Kind, dashIfEmpty(m.Member.Name), dashIfEmpty(m.Member.Binder),
					addrOrDash(m.Member.Address), prefixes(m.Member.Routes),
					dashIfEmpty(m.Member.Domain), state)
			}
			w.Flush()

			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().StringVar(&instance, "instance", "", "only the members of this instance")
	_ = cmd.RegisterFlagCompletionFunc("instance", completeInstances(socket, true))

	return cmd
}

// newInstanceTokenCmd replaces the secret a connector's enrollment is
// authenticated with.
func newInstanceTokenCmd() *cobra.Command {
	var socket, token string

	cmd := &cobra.Command{
		Use:   "token <id or name>",
		Short: "Replace the shared token new connectors enroll with",
		Long: `token gives an instance a new shared token and prints the connector
endpoint carrying it. One is generated unless --token says otherwise.

Only enrollment is authenticated with it. A connector already admitted holds a
certificate and never presents the token again, so nothing running is
interrupted; what stops working is every connector configuration handed out
before this, which is the point.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, true),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var result tenant.TokenResult
			req := tenant.TokenRequest{Instance: args[0], Token: token}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/instance/token", req, &result); err != nil {
				return err
			}

			fmt.Printf("%s has a new shared token, and the endpoints handed out before it no longer enroll\n",
				result.Instance)
			printConnectorHint(result.Endpoint)
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().StringVar(&token, "token", "", "use this token instead of a generated one")
	return cmd
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// newDeleteCmd removes an instance, which only its owner can do and nobody can
// undo.
func newDeleteCmd() *cobra.Command {
	var (
		socket string
		force  bool
	)

	cmd := &cobra.Command{
		Use:   "delete <instance>",
		Short: "Delete an instance this machine owns",
		Long: `delete removes an instance from the hub and the authority for it from
here.

Nothing is revoked, because nothing can be: the certificates were signed by an
authority the hub never had, and this deletes that authority. What ends is the
lighthouse and the route table, so members can no longer find each other or
know where to send anything. Connectors pointed at it will keep asking.

There is no way back. A new instance of the same name is a different instance,
with a different authority, and everyone has to be admitted again.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, true),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var result tenant.DeleteResult
			req := tenant.DeleteRequest{Instance: args[0], Force: force}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/delete", req, &result); err != nil {
				return err
			}

			fmt.Printf("deleted %s\n", result.Instance)
			if result.Members > 1 {
				fmt.Printf("%d members lost it, and their certificates are now useless\n", result.Members-1)
			}
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().BoolVar(&force, "force", false, "delete it although other machines are members")

	return cmd
}
